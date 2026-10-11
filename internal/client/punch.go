package client

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net"
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

// reflectOwn 向 registry 同端口的 UDP 反射器查询本套接字的公网映射地址。
func reflectOwn(sock *net.UDPConn, registryBase string) *net.UDPAddr {
	addr, err := reflect.Query(sock, hostOf(registryBase), time.Second)
	if err != nil {
		return nil // 反射失败不致命:退化为仅 LAN 候选+中继
	}
	return addr
}

// lanCandidates6 枚举本机全局 IPv6 地址与套接字端口组合。
func lanCandidates6(sock *net.UDPConn) []string {
	port := sock.LocalAddr().(*net.UDPAddr).Port
	var out []string
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
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
	port := sock.LocalAddr().(*net.UDPAddr).Port
	var out []string
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
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
func punchDual(sock4, sock6 *net.UDPConn, peer *candInfo, k [32]byte, budget time.Duration, mapped4 string) (*punchTarget, error) {
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
		go func() {
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
		}()
	}
	run(false, sock4, nil)
	run(true, sock6, nil)
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case r := <-resCh:
		// 胜出即刻返回;另一族由调用方关闭套接字终止
		return &punchTarget{sock: func() *net.UDPConn {
			if r.v6 {
				return sock6
			}
			return sock4
		}(), addr: r.addr}, nil
	case <-done:
		return nil, errors.New("打洞失败(v4/v6 均未通,对端不可直连)")
	case <-time.After(budget + 2*time.Second):
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
	go func() { // 探针发送循环(对每个候选,周期性同时开洞)
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
	}()
	defer func() { close(stop); sendWG.Wait() }()

	_ = sock.SetReadDeadline(time.Now().Add(budget))
	buf := make([]byte, 128)
	for {
		n, raddr, err := sock.ReadFromUDP(buf)
		if err != nil {
			return nil, errors.New("打洞失败(对端不可直连)")
		}
		// 只认可解密的探针=对端身份确认(防第三方注入)
		if _, err := aead.Open(nil, buf[:chacha20poly1305.NonceSize], buf[chacha20poly1305.NonceSize:n], nil); err == nil {
			return raddr, nil
		}
	}
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
