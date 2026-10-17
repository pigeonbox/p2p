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
	Log            *slog.Logger
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
	s := &server{
		waiting:        make(map[string]net.Conn),
		since:          make(map[string]time.Time),
		perIP:          make(map[string]int),
		bytesPerSec:    p.BytesPerSec,
		maxWaiting:     p.MaxWaiting,
		maxConnsPerIP:  p.MaxConnsPerIP,
		waitingTimeout: p.WaitingTimeout,
		log:            p.Log,
	}
	// 等待超时清扫
	go func() {
		t := time.NewTicker(10 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.mu.Lock()
				for tok, c := range s.waiting {
					if time.Since(s.since[tok]) > s.waitingTimeout {
						_ = c.Close()
						delete(s.waiting, tok)
						delete(s.since, tok)
					}
				}
				s.mu.Unlock()
			}
		}
	}()
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
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
	mu             sync.Mutex
	waiting        map[string]net.Conn
	since          map[string]time.Time
	perIP          map[string]int
	bytesPerSec    int64
	maxWaiting     int
	maxConnsPerIP  int
	waitingTimeout time.Duration
	log            *slog.Logger
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
	defer func() {
		s.mu.Lock()
		s.perIP[ip]--
		if s.perIP[ip] <= 0 {
			delete(s.perIP, ip)
		}
		s.mu.Unlock()
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
		delete(s.waiting, token)
		delete(s.since, token)
		s.mu.Unlock()
		// 配对成功:互为管道(单信道限速),任一端断开即双向关闭
		// (数据面面向不可信对端,panic 只许死信道不许带崩进程——GoSafe 收编;
		//  wg.Done 留在闭包内,panic 展开时仍先于 recover 执行,配对汇合语义不变)
		var wg sync.WaitGroup
		lim := newBucket(s.bytesPerSec)
		wg.Add(2)
		async.GoSafeLabeled("relay-pipe", func() { defer wg.Done(); pipe(ctx, conn, peer, lim) })
		async.GoSafeLabeled("relay-pipe", func() { defer wg.Done(); pipe(ctx, peer, conn, lim) })
		wg.Wait()
		_ = conn.Close()
		_ = peer.Close()
		return
	}
	s.waiting[token] = conn
	s.since[token] = time.Now()
	s.mu.Unlock()
}

// pipe 单向搬运;限速桶按方向共享(双向合计不超过单信道额度)。
func pipe(ctx context.Context, dst, src net.Conn, lim *rate.Limiter) {
	buf := make([]byte, pipeBufSize)
	for {
		n, err := src.Read(buf)
		if n > 0 {
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
