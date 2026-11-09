package client

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/oekit/concurrency/async"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/pigeonbox/p2p/internal/reflect"
)

// ---- 候选交换与 UDP 同时开洞 ----

// candInfo 打洞候选与传输凭据（经 PAKE 派生密钥加密后过信令信道）。
// v4/v6 各自独立候选族(显式分栈——双栈通配会让 QUIC 地址族混用静默丢包,
// 见 Send/Receive 的历史教训);JSON 字段向后兼容,旧对端忽略未知字段。
type candInfo struct {
	UDPPublic  string   `json:"udp_public"`  // 反射器观察到的 IPv4 映射地址
	UDPLAN     []string `json:"udp_lan"`     // 本机各网卡 IPv4:port
	UDPPublic6 string   `json:"udp_public6"` // 反射器观察到的 IPv6 映射地址(v4 可空)
	UDPLAN6    []string `json:"udp_lan6"`    // 本机全局 IPv6:port
	UDPMapped  string   `json:"udp_mapped"`  // PCP/NAT-PMP/UPnP 端口映射外部地址
	CertFP     string   `json:"cert_fp"`     // 临时证书指纹 hex(sha256(DER))
	RelayToken string   `json:"relay_token"`
}

// sealOpen k_cand 加解密助手（nonce 前缀格式,与 wire 一致的思路）。
func seal(key [32]byte, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, chacha20poly1305.NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, plaintext, nil), nil
}

func open(key [32]byte, data []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, err
	}
	if len(data) < chacha20poly1305.NonceSize+aead.Overhead() {
		return nil, errors.New("密文过短")
	}
	nonce, ct := data[:chacha20poly1305.NonceSize], data[chacha20poly1305.NonceSize:]
	return aead.Open(nil, nonce, ct, nil)
}

// 反射查询的重试参数。
//
// 预算刻意压得比「一次 1s」短：反射是**本机到 registry 的 UDP 往返**，正常
// 是亚毫秒级；拉长单次预算只会让失败时的等待更长。
const (
	reflectAttempts = 3
	// reflectQueryBudget 1.5s（p2p#23 第二层）：600ms 对公网反射器的 RTT+处理
	// 抖动偏紧（跨洲单跳即 300ms+），且测试环境反射器与查询方同进程、负载
	// 挤压下调度延迟即超。1.5s×3 次最坏 4.95s，仍属准备阶段一次性开销。
	reflectQueryBudget = 1500 * time.Millisecond
	reflectRetryDelay  = 150 * time.Millisecond
)

// reflectOwn 向 registry 同端口的 UDP 反射器查询本套接字的公网映射地址。
//
// ⚠️ 必须**重试**（p2p#20，2026-11-03 实测）：反射器按源 IP 限流
// （令牌桶 10/s、突发 20）且**超限静默丢包**——不回任何响应 ⇒ 同一出口 IP 的
// 多个客户端（家庭/公司 NAT、并行测试）并发查询时，突发额度用尽后的查询
// 必然收不到回应 ⇒ 反射失败 ⇒ UDPPublic 为空 ⇒ 打洞**没有可达目标**
// （LAN 候选按设计不含 loopback）⇒ 直连必然失败，表现为
// 「打洞失败(v4/v6 均未通,对端不可直连)」。
//
// 实测：同 IP 连打 30 次反射查询 ⇒ 前 20 次全过、**第 21 次起开始失败**
// —— 正好是令牌桶的 burst ⇒ 与限流丢包完全吻合。
//
// ⇒ 失败要重试（桶按 10/s 回落，短退避即可命中）；且失败**必须留日志**
// （原实现完全静默降级 ⇒ 「直连不可用」变成查不到原因的黑洞）。
func reflectOwn(sock *net.UDPConn, registryBase string) (*net.UDPAddr, error) {
	addr := hostOf(registryBase)
	var lastErr error
	for attempt := 1; attempt <= reflectAttempts; attempt++ {
		pub, err := reflect.Query(sock, addr, reflectQueryBudget)
		if err == nil {
			return pub, nil
		}
		lastErr = err
		if attempt < reflectAttempts {
			time.Sleep(reflectRetryDelay)
		}
	}
	return nil, lastErr
}

// localPortOf 取套接字本地端口；套接字为空或类型不符时返回 0。
//
// ⚠️ 不能写 sock.LocalAddr().(*net.UDPAddr).Port：
// 无 IPv6 环境时 punchSockets 会把 sock6 置 nil（ListenUDP("udp6") 失败，
// 纯 v4 走通），而 LocalAddr() 在 nil 接收者上返回 nil ⇒ 裸类型断言 panic
// ⇒ **没有 IPv6 的机器（NAS/容器常见）上一建会话就崩**。
// 同理 v4 监听失败时 sock4 也是 nil。
func localPortOf(sock *net.UDPConn) int {
	if sock == nil {
		return 0
	}
	if a, ok := sock.LocalAddr().(*net.UDPAddr); ok && a != nil {
		return a.Port
	}
	return 0
}

// lanCandidates6 枚举本机全局 IPv6 地址与套接字端口组合。
func lanCandidates6(sock *net.UDPConn) []string {
	port := localPortOf(sock)
	if port == 0 {
		return nil // 无 v6 环境 ⇒ 无候选（不是 panic）
	}
	// loopback 候选（同 lanCandidates 的 v4 注释，p2p#23）：同机直传 + 测试环境
	// 不再依赖同进程 reflect。
	out := []string{net.JoinHostPort("::1", strconv.Itoa(port))}
	ifaces, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip6 := ipnet.IP.To16()
			// 只要全局单播(2000::/3):链路本地/ULA 对直传无意义
			if ip6 == nil || ip6.To4() != nil || ip6.IsLoopback() || ip6.IsLinkLocalUnicast() {
				continue
			}
			out = append(out, net.JoinHostPort(ip6.String(), fmt.Sprint(port)))
		}
	}
	return out
}

// lanCandidates 枚举本机 IPv4 地址与套接字端口的组合。
func lanCandidates(sock *net.UDPConn) []string {
	port := localPortOf(sock)
	if port == 0 {
		return nil
	}
	// loopback 候选（p2p#23 第三层根因修复）：同机直传是真实部署场景（fnos 预接线
	// Beam→Box、NAS 本机桌面端），此前排除 loopback ⇒ 同机对端在 LAN/公网候选
	// 全缺席时只能靠 reflect——而回环测试环境里 reflect 服务端与打洞方同进程,
	// 负载挤压下 600ms 预算超时 ⇒ 零候选 ⇒ 打洞必败（CI flake 的结构性来源）。
	// 对远端对端多发一个探针目标无害（探针是加密探针,不可达即无响应）。
	out := []string{net.JoinHostPort("127.0.0.1", strconv.Itoa(port))}
	ifaces, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipnet.IP.To4()
			if ip4 == nil || ip4.IsLoopback() || ip4.IsLinkLocalUnicast() {
				continue
			}
			out = append(out, net.JoinHostPort(ip4.String(), fmt.Sprint(port)))
		}
	}
	return out
}

// punchTarget 打洞结果:套接字(承载后续 QUIC)+验证过的对端地址。
type punchTarget struct {
	sock *net.UDPConn
	addr *net.UDPAddr
}

// punchDual v4/v6 双栈同时打洞:两族各自同时开洞,任一路径先验证成功即胜出
// (族间独立套接字——显式单栈是 QUIC 地址族一致性的前提)。maps 为端口映射
// 候选(外部地址,从同族套接字发探针)。
//
// 打洞耗时是 QUIC 窗口差值 Δ 的主要来源（p2p#20/#23）：log 打点给出
// 「打了多久、哪个族胜出/为何失败」，CI flake 复现时可直接从日志读出
// 两侧各自的打洞时间线。
func punchDual(sock4, sock6 *net.UDPConn, peer *candInfo, k [32]byte, budget time.Duration, mapped4 string, log *slog.Logger) (*punchTarget, error) {
	punchStart := time.Now()
	type res struct {
		v6   bool
		addr *net.UDPAddr
	}
	resCh := make(chan res, 2)
	var wg sync.WaitGroup
	run := func(v6 bool, sock *net.UDPConn, targets func(*candInfo) []string) {
		if sock == nil {
			return
		}
		wg.Add(1)
		async.GoSafeLabeled("punch-candidate", func() {
			defer wg.Done()
			p := *peer
			p.UDPPublic = ""
			p.UDPLAN = nil
			if v6 {
				p.UDPPublic = peer.UDPPublic6
				p.UDPLAN = peer.UDPLAN6
			} else {
				p.UDPPublic = peer.UDPPublic
				p.UDPLAN = peer.UDPLAN
				if mapped4 != "" {
					p.UDPLAN = append(append([]string{}, p.UDPLAN...), mapped4)
				}
			}
			addr, err := punch(sock, &p, k, budget)
			if err == nil {
				resCh <- res{v6: v6, addr: addr}
			}
		})
	}
	run(false, sock4, nil)
	run(true, sock6, nil)
	done := make(chan struct{})
	async.GoSafeLabeled("punch-wait-close", func() { wg.Wait(); close(done) })
	select {
	case r := <-resCh:
		// 胜出即刻返回;另一族由调用方关闭套接字终止
		fam := "v4"
		if r.v6 {
			fam = "v6"
		}
		log.Info("打洞成功", "fam", fam, "elapsed", time.Since(punchStart).String(), "budget", budget.String())
		return &punchTarget{sock: func() *net.UDPConn {
			if r.v6 {
				return sock6
			}
			return sock4
		}(), addr: r.addr}, nil
	case <-done:
		log.Warn("打洞失败(双族均未通)", "elapsed", time.Since(punchStart).String(), "budget", budget.String())
		return nil, errors.New("打洞失败(v4/v6 均未通,对端不可直连)")
	case <-time.After(budget + 2*time.Second):
		log.Warn("打洞超时", "elapsed", time.Since(punchStart).String(), "budget", budget.String())
		return nil, errors.New("打洞超时")
	}
}

// punch UDP 同时开洞：双方互发加密探针，任一候选路径收到可解密包即成功。
// 返回验证过的对端地址（从本套接字视角）。budget 内未成即失败（走中继）。
func punch(sock *net.UDPConn, peer *candInfo, k [32]byte, budget time.Duration) (*net.UDPAddr, error) {
	aead, err := chacha20poly1305.New(k[:])
	if err != nil {
		return nil, err
	}
	probe := func() ([]byte, error) {
		nonce := make([]byte, chacha20poly1305.NonceSize)
		if _, err := rand.Read(nonce); err != nil {
			return nil, err
		}
		return aead.Seal(nonce, nonce, []byte("fcb-punch-v1"), nil), nil
	}

	var targets []*net.UDPAddr
	add := func(s string) {
		if s == "" {
			return
		}
		if a, err := net.ResolveUDPAddr("udp", s); err == nil {
			targets = append(targets, a)
		}
	}
	add(peer.UDPPublic)
	for _, l := range peer.UDPLAN {
		add(l)
	}
	if len(targets) == 0 {
		return nil, errors.New("对端无可用候选")
	}

	stop := make(chan struct{})
	var sendWG sync.WaitGroup
	sendWG.Add(1)
	async.GoSafeLabeled("punch-probe-loop", func() { // 探针发送循环(对每个候选,周期性同时开洞)
		defer sendWG.Done()
		t := time.NewTicker(80 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				pkt, err := probe()
				if err != nil {
					return
				}
				for _, tgt := range targets {
					_, _ = sock.WriteToUDP(pkt, tgt)
				}
			}
		}
	})
	defer func() { close(stop); sendWG.Wait() }()

	_ = sock.SetReadDeadline(time.Now().Add(budget))
	buf := make([]byte, 128)
	for {
		n, raddr, err := sock.ReadFromUDP(buf)
		if err != nil {
			return nil, errors.New("打洞失败(对端不可直连)")
		}
		// 长度判据必须先于切片（2026-11-06 P0）：AEAD 探针报文最短 =
		// NonceSize(12) + Overhead(16)。此前直接 buf[NonceSize:n]，
		// n < 12 时 **start > end ⇒ slice bounds out of range ⇒ panic**，
		// 且这条读循环跑在 establish → Send/Receive 主链上、没有 GoSafe 兜底
		// ⇒ 任一第三方/损坏 UDP 包即可打死整个传输进程（远端可无条件触发）。
		// 同包 open() 早就有同样的长度判据（见 punch.go 顶部），此处补齐。
		// 只认可解密的探针=对端身份确认(防第三方注入)
		if probeMatches(aead, buf, n) {
			return raddr, nil
		}
	}
}

// probeMatches 判读一个打洞探针：长度够（Nonce+Tag）且能用会话密钥解开。
//
// ⚠️ 长度判据必须**先于**切片（2026-11-06 P0）：此前调用点直接
// buf[NonceSize:n]，n < 12 时 start > end ⇒ slice bounds out of range ⇒ panic；
// 该读循环跑在 establish → Send/Receive 主链上、无 GoSafe 兜底 ⇒ 任一第三方
// 或损坏的 UDP 包即可打死传输进程。独立成函数是为了能被单测直接锁住。
func probeMatches(aead cipher.AEAD, buf []byte, n int) bool {
	if n < aead.NonceSize()+aead.Overhead() {
		return false
	}
	_, err := aead.Open(nil, buf[:aead.NonceSize()], buf[aead.NonceSize():n], nil)
	return err == nil
}

// hostOf 基址取 host[:port]。
func hostOf(base string) string {
	b := trimRight(base)
	b = strings.TrimPrefix(b, "https://")
	b = strings.TrimPrefix(b, "http://")
	if i := strings.Index(b, "/"); i >= 0 {
		b = b[:i]
	}
	return b
}

// exchangeCandidates 双方互换候选（PAKE 派生密钥加密——明文候选可被注入劫持）。
func exchangeCandidates(ch *channel, k [32]byte, own *candInfo) (*candInfo, error) {
	plain, err := json.Marshal(own)
	if err != nil {
		return nil, err
	}
	boxed, err := seal(k, plain)
	if err != nil {
		return nil, err
	}
	if err := ch.send(boxed); err != nil {
		return nil, fmt.Errorf("候选发送: %w", err)
	}
	boxedPeer, err := ch.recv()
	if err != nil {
		return nil, fmt.Errorf("候选接收: %w", err)
	}
	plainPeer, err := open(k, boxedPeer)
	if err != nil {
		return nil, fmt.Errorf("候选解密失败(对端口令不一致?): %w", err)
	}
	var peer candInfo
	if err := json.Unmarshal(plainPeer, &peer); err != nil {
		return nil, fmt.Errorf("候选解析: %w", err)
	}
	return &peer, nil
}

// seal 用候选密钥封装(candInfo → 信令 data 帧负载)。
func (ci *candInfo) seal(k [32]byte) ([]byte, error) {
	plain, err := json.Marshal(ci)
	if err != nil {
		return nil, err
	}
	return seal(k, plain)
}

// pickUDP 按地址族取对端 UDP 候选(公网/映射优先,LAN 次之)。
func (ci *candInfo) pickUDP(family string) *net.UDPAddr {
	var cands []string
	if family == "v6" {
		cands = append([]string{ci.UDPPublic6}, ci.UDPLAN6...)
	} else {
		cands = append([]string{ci.UDPPublic, ci.UDPMapped}, ci.UDPLAN...)
	}
	for _, c := range cands {
		if c == "" {
			continue
		}
		if a, err := net.ResolveUDPAddr("udp", c); err == nil && usableExt(a) {
			return a
		}
	}
	return nil
}
