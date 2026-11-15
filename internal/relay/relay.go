// Package relay 实现端到端加密中继（M3 打洞失败的兜底路径）。
//
// 协议：连接后首行 "RELAY <token>"，相同 token 的两条连接被配对并互为
// 管道。token = PAKE 派生的信道凭据（无口令不可计算），中继只见密文；
// 传输层首帧即 AEAD 认证（wire），令牌被窃也只构成拒绝服务。
//
// 治理：等待配对连接数上限、等待超时、单信道限速（默认开）。默认整机关闭
// （relay.enabled=false）。
package relay

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/oekit/concurrency/async"
	"github.com/oekit/concurrency/loop"
	"golang.org/x/time/rate"
)

const (
	maxWaiting     = 1024
	waitingTimeout = 60 * time.Second
	maxTokenLen    = 128
	maxLineLen     = maxTokenLen + 16
	pipeBufSize    = 32 << 10
	minBytesPerSec = 32 * 1024 // 限速下限,防误配成近似断流
	// maxConnsPerIP 单 IP 并发连接上限(2026-10-05 审计 P2:此前随机 token
	// 可占满全局 1024 等待槽令所有用户不可用;读写阶段一并计入)
	maxConnsPerIP = 16
	// p2p#49:配对后管道治理——空闲超时与信令 idle_timeout 口径对齐(2min),
	// 生命周期上限与活动信道全局上限对齐 maxWaiting 的容量设计。
	idleTimeout       = 2 * time.Minute
	maxLifetime       = 30 * time.Minute
	maxActiveChannels = 1024
)

// Params 中继服务参数(0 值/nil 用内置默认,见常量)。
type Params struct {
	// BytesPerSec 单信道带宽上限(字节/秒,0=不限,下限 minBytesPerSec)。
	BytesPerSec int64
	// MaxWaiting 等待配对连接数上限(0=默认)。
	MaxWaiting int
	// MaxConnsPerIP 单 IP 并发连接上限(0=默认)。
	MaxConnsPerIP int
	// WaitingTimeout 等待配对超时(0=默认)。
	WaitingTimeout time.Duration
	// IdleTimeout 配对后管道空闲上限(0=默认 2min:无字节即关,p2p#49)。
	IdleTimeout time.Duration
	// MaxChannelLifetime 配对后管道最长生命周期(0=默认 30min,p2p#49)。
	MaxChannelLifetime time.Duration
	// MaxActiveChannels 全局活动信道上限(0=默认 1024;超限拒绝新配对,p2p#49)。
	MaxActiveChannels int
	Log               *slog.Logger
}

// Serve 阻塞服务中继，直到 ctx 结束或 listener 关闭。
func Serve(ctx context.Context, ln net.Listener, p Params) error {
	if p.BytesPerSec > 0 && p.BytesPerSec < minBytesPerSec {
		p.BytesPerSec = minBytesPerSec
	}
	if p.MaxWaiting <= 0 {
		p.MaxWaiting = maxWaiting
	}
	if p.MaxConnsPerIP <= 0 {
		p.MaxConnsPerIP = maxConnsPerIP
	}
	if p.WaitingTimeout <= 0 {
		p.WaitingTimeout = waitingTimeout
	}
	if p.IdleTimeout <= 0 {
		p.IdleTimeout = idleTimeout
	}
	if p.MaxChannelLifetime <= 0 {
		p.MaxChannelLifetime = maxLifetime
	}
	if p.MaxActiveChannels <= 0 {
		p.MaxActiveChannels = maxActiveChannels
	}
	s := &server{
		waiting:        make(map[string]net.Conn),
		since:          make(map[string]time.Time),
		perIP:          make(map[string]int),
		waitingIP:      make(map[string]string),
		bytesPerSec:    p.BytesPerSec,
		maxWaiting:     p.MaxWaiting,
		maxConnsPerIP:  p.MaxConnsPerIP,
		waitingTimeout: p.WaitingTimeout,
		idleTimeout:    p.IdleTimeout,
		maxLifetime:    p.MaxChannelLifetime,
		maxActive:      p.MaxActiveChannels,
		log:            p.Log,
	}
	// 等待超时清扫（收编 oekit/concurrency/loop.Run 2026-11-03：周期任务+
	// ctx 停机+逐轮 panic 收编恰是 loop 的形状，ticker/select 手搓壳退役；
	// loop 内部每轮 async.RunSafeLabeled，与原 GoSafeLabeled 同级防护）
	loop.Run(ctx, loop.Config{Interval: 10 * time.Second, Name: "relay-housekeeping"}, func(context.Context) {
		s.mu.Lock()
		for tok, c := range s.waiting {
			if time.Since(s.since[tok]) > s.waitingTimeout {
				_ = c.Close()
				delete(s.waiting, tok)
				delete(s.since, tok)
				// 超时清扫 = 连接真正消失 ⇒ 此时才归还 per-IP 槽位
				s.releaseIPLocked(s.waitingIP[tok])
				delete(s.waitingIP, tok)
			}
		}
		s.mu.Unlock()
	})
	async.GoSafeLabeled("relay-listener-close", func() {
		<-ctx.Done()
		_ = ln.Close()
	})
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("relay accept: %w", err)
		}
		// GoSafeLabeled:单连接 panic 不打死中继进程，只断该连接（每连接处理互相隔离）
		async.GoSafeLabeled("relay-conn", func() { s.handle(ctx, conn) })
	}
}

type server struct {
	mu      sync.Mutex
	waiting map[string]net.Conn
	since   map[string]time.Time
	perIP   map[string]int
	// waitingIP token → 该等待连接占着的 per-IP 槽位属主。
	// 槽位不能随 handle 返回而释放（见 handle 内的 release 注释），
	// 必须留到连接被配对/超时清扫/关闭时才归还。
	waitingIP      map[string]string
	bytesPerSec    int64
	maxWaiting     int
	maxConnsPerIP  int
	waitingTimeout time.Duration
	// p2p#49:配对后管道治理
	idleTimeout time.Duration
	maxLifetime time.Duration
	maxActive   int
	active      int
	log         *slog.Logger
}

// releaseIPLocked 归还一个 per-IP 槽位（调用方必须已持 s.mu）。
func (s *server) releaseIPLocked(ip string) {
	if ip == "" {
		return
	}
	s.perIP[ip]--
	if s.perIP[ip] <= 0 {
		delete(s.perIP, ip)
	}
}

// releaseIP 归还一个 per-IP 槽位（自带加锁）。
func (s *server) releaseIP(ip string) {
	s.mu.Lock()
	s.releaseIPLocked(ip)
	s.mu.Unlock()
}

func (s *server) handle(ctx context.Context, conn net.Conn) {
	ip := remoteIP(conn)
	s.mu.Lock()
	if s.perIP[ip] >= s.maxConnsPerIP {
		s.mu.Unlock()
		_ = conn.Close()
		return
	}
	s.perIP[ip]++
	s.mu.Unlock()
	// ⚠️ 槽位的**归属**在这条连接的生命期内两次易手（2026-11-06 P1）：
	//
	//	handle 存活期          → 由这里持有（release=true）
	//	挂进 waiting 之后      → 交给 waiting 条目持有（release=false）
	//
	// 修复前是「无条件 defer 归还」⇒ 连接一挂进 waiting，handle 立刻返回、
	// 槽位当场释放，可连接**还躺在 waiting 里占着全局名额**（最长
	// waitingTimeout=60s）⇒ 攻击者用随机 token 每次开 16 条（上限）、拿到槽位
	// 立刻被释放 ⇒ 可以无限次灌 waiting，把全局 maxWaiting=1024 占满
	// ⇒ per-IP 配额在 waiting 阶段**完全失效**（正是当初引入它的那个 DoS 面）。
	release := true
	defer func() {
		if release {
			s.releaseIP(ip)
		}
	}()

	_ = conn.SetDeadline(time.Now().Add(s.waitingTimeout))
	// 逐字节读首行:bufio 会预读多字节,把客户端紧随其后的首帧吞进缓冲
	token, ok := readLine(conn, maxTokenLen)
	if !ok {
		_ = conn.Close()
		return
	}
	_ = conn.SetDeadline(time.Time{}) // 清除等待期 deadline,管道按限速自由流动

	s.mu.Lock()
	if len(s.waiting) >= s.maxWaiting {
		s.mu.Unlock()
		_ = conn.Close()
		return
	}
	if peer, ok := s.waiting[token]; ok {
		// p2p#49:活动信道全局上限——只约束等待表会让配对完成后的信道
		// 无限增长(单 IP 16 条空转即可长期占用中继带宽)。超限拒绝**新到的
		// 配对连接**,先到的等待方留在 waiting 由超时清扫/下一端配对回收。
		if s.active >= s.maxActive {
			s.mu.Unlock()
			_ = conn.Close()
			return
		}
		s.active++
		peerIP := s.waitingIP[token]
		delete(s.waiting, token)
		delete(s.since, token)
		delete(s.waitingIP, token)
		s.releaseIPLocked(peerIP) // 对端已出队配对 ⇒ 归还它占的槽位
		s.mu.Unlock()
		// 配对成功:互为管道(单信道限速),任一端断开即双向关闭
		// (数据面面向不可信对端,panic 只许死信道不许带崩进程——GoSafe 收编;
		//  wg.Done 留在闭包内,panic 展开时仍先于 recover 执行,配对汇合语义不变)
		s.pair(ctx, conn, peer)
		return
	}
	s.waiting[token] = conn
	s.since[token] = time.Now()
	s.waitingIP[token] = ip
	s.mu.Unlock()
	// 槽位随 waiting 条目走：由配对分支或超时清扫归还（见上方 release 注释）。
	release = false
}

// pair 配对成功后的管道阶段(p2p#49)。活动信道名额由调用方在持锁时
// 占用,这里 defer 归还——无论管道正常收工还是中途 panic,计数都不泄漏。
// 空闲/生命周期双超时经 pipeCtl 落在连接 deadline 上:任一方向有字节
// 即续空闲期,生命周期上限不因流量顺延,到期由 Read/Write 超时掐断。
func (s *server) pair(ctx context.Context, conn, peer net.Conn) {
	defer func() {
		s.mu.Lock()
		s.active--
		s.mu.Unlock()
	}()
	ctl := &pipeCtl{idle: s.idleTimeout, expireAt: time.Now().Add(s.maxLifetime)}
	ctl.refresh(conn, peer) // 初始 deadline:配对后首字节前也受空闲约束
	var wg sync.WaitGroup
	lim := newBucket(s.bytesPerSec)
	wg.Add(2)
	async.GoSafeLabeled("relay-pipe", func() { defer wg.Done(); pipe(ctx, conn, peer, lim, ctl) })
	async.GoSafeLabeled("relay-pipe", func() { defer wg.Done(); pipe(ctx, peer, conn, lim, ctl) })
	wg.Wait()
	_ = conn.Close()
	_ = peer.Close()
}

// pipeCtl 配对后管道的超时治理(p2p#49):空闲超时 + 最长生命周期。
type pipeCtl struct {
	idle     time.Duration
	expireAt time.Time // 出生 + MaxChannelLifetime
}

// refresh 把两端连接的 deadline 推到 min(now+idle, expireAt)。任一方向
// 有字节即视为信道活跃(两端一起续),生命周期上限不顺延。
// SetDeadline 是连接级且并发安全的:两个 pipe goroutine 同时刷新无害。
func (c *pipeCtl) refresh(conns ...net.Conn) {
	d := time.Now().Add(c.idle)
	if c.expireAt.Before(d) {
		d = c.expireAt
	}
	for _, cn := range conns {
		_ = cn.SetDeadline(d)
	}
}

// pipe 单向搬运;限速桶按方向共享(双向合计不超过单信道额度)。
func pipe(ctx context.Context, dst, src net.Conn, lim *rate.Limiter, ctl *pipeCtl) {
	buf := make([]byte, pipeBufSize)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			ctl.refresh(src, dst) // 有字节=信道活跃,续空闲期
			if lim != nil {
				if werr := lim.WaitN(ctx, n); werr != nil {
					return
				}
			}
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// readLine 逐字节读一行（不超读）,返回去掉前缀后的 token。
func readLine(conn net.Conn, maxLen int) (string, bool) {
	var sb strings.Builder
	buf := make([]byte, 1)
	for {
		n, err := conn.Read(buf)
		if err != nil || n == 0 {
			return "", false
		}
		if buf[0] == '\n' {
			line := sb.String()
			token, ok := strings.CutPrefix(strings.TrimSpace(line), "RELAY ")
			if !ok || len(token) != 64 || !isHex(token) {
				return "", false
			}
			return token, true
		}
		sb.WriteByte(buf[0])
		if sb.Len() > maxLen {
			return "", false
		}
	}
}

func newBucket(bytesPerSec int64) *rate.Limiter {
	if bytesPerSec <= 0 {
		return nil
	}
	return rate.NewLimiter(rate.Limit(bytesPerSec), int(bytesPerSec)) // 1s 突发
}

// remoteIP 取对端 IP（去端口；解析失败回退整串）。
func remoteIP(conn net.Conn) string {
	addr := conn.RemoteAddr().String()
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}

func isHex(s string) bool {
	for _, c := range s {
		isDigit := c >= '0' && c <= '9'
		isLowerHex := c >= 'a' && c <= 'f'
		if !isDigit && !isLowerHex {
			return false
		}
	}
	return true
}
