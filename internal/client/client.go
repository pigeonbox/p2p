package client

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/pigeonbox/p2p/internal/wire"
)

// Options 客户端参数。
type Options struct {
	Registry string // p2pd 基址,如 http://127.0.0.1:12346;裸域名触发 DNS 发现
	// Registries 额外注册中心(多源 failover;PB_P2P_REGISTRIES 亦并入)。
	// 按 rendezvous hashing 对每个口令确定性排序,两端同表自然汇聚同一节点。
	Registries []string
	// RegistriesJoined CLI 旗标形态(逗号分隔),New 时拆入 Registries。
	RegistriesJoined string
	// NodeKeyPath 节点身份密钥（缺省 ~/.fcb-p2p/node.key）
	NodeKeyPath string
	// RelayAddr 中继地址（缺省 registry host + :12347）
	RelayAddr string
	// DisablePunch 跳过打洞直接走中继（测试与强制兜底用）
	DisablePunch bool
	// PunchBudget 打洞预算（默认 4s）
	PunchBudget time.Duration
	// Quiet 关闭过程日志
	Quiet bool
	// ChooseFiles 接收侧逐文件授权回调(nil=全部接受)。CLI 交互提示/
	// --yes 由上层实现后注入;网页/子进程模式传 nil。
	ChooseFiles func(mf manifestMsg) []manifestEntry
}

// DefaultNodeKeyPath 默认密钥位置（用户缓存目录）。
func DefaultNodeKeyPath() string {
	if base, err := os.UserCacheDir(); err == nil {
		dir := filepath.Join(base, "fcb-p2p")
		// 预建目录:NAS/容器场景 HOME 常指向不存在或不可写的路径
		// (/home/zhangyi 不存在),此处探明可写性,失败回退临时目录。
		if err := os.MkdirAll(dir, 0o700); err == nil {
			return filepath.Join(dir, "node.key")
		}
	}
	// 无 HOME/HOME 不可写:回退系统临时目录(密钥随容器生命周期,可接受)
	return filepath.Join(os.TempDir(), "fcb-p2p-node.key")
}

// Client 直传客户端。
type Client struct {
	opt Options
	id  *nodeIdentity
	log *slog.Logger
	reg *registryAPI
}

// New 构造客户端（加载/生成节点身份密钥）。
func New(opt Options) (*Client, error) {
	if opt.Registry == "" {
		return nil, fmt.Errorf("registry 地址必填")
	}
	if opt.NodeKeyPath == "" {
		opt.NodeKeyPath = DefaultNodeKeyPath()
	}
	if opt.PunchBudget <= 0 {
		opt.PunchBudget = 4 * time.Second
	}
	for _, r := range strings.Split(opt.RegistriesJoined, ",") {
		if r = strings.TrimSpace(r); r != "" {
			opt.Registries = append(opt.Registries, r)
		}
	}
	id, err := newNodeIdentity(opt.NodeKeyPath)
	if err != nil {
		return nil, err
	}
	log := slog.Default()
	if opt.Quiet {
		log = slog.New(discardHandler{})
	}
	return &Client{opt: opt, id: id, log: log, reg: newRegistryAPI(opt.Registry)}, nil
}

// codeAlphabet Crockford base32（去 I/L/O/U 歧义）。
const codeAlphabet = "0123456789ABCDEFGHJKMNPQRSTWXYZ"

// GenerateCode 生成 12 位强口令（3×4 分组,≈60bit 熵——远超联邦公告门槛）。
func GenerateCode() (string, error) {
	raw := make([]byte, 12)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	var sb strings.Builder
	for i, b := range raw {
		if i > 0 && i%4 == 0 {
			sb.WriteByte('-')
		}
		sb.WriteByte(codeAlphabet[int(b)%len(codeAlphabet)])
	}
	return sb.String(), nil
}

func (c *Client) relayAddr() string {
	if c.opt.RelayAddr != "" {
		return c.opt.RelayAddr
	}
	// registry 常带端口(http://host:22346),默认中继=同主机换 12347 端口
	// ——直接拼接会得到 host:22346:12347(215 部署实测踩坑)。
	host := hostOf(c.opt.Registry)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return host + ":12347"
}

// setupNode 注册节点租约；返回 best-effort 注销函数。
func (c *Client) setupNode(reg *registryAPI) func() {
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "device"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := reg.register(ctx, c.id, hostname, time.Hour); err != nil {
		c.log.Warn("节点注册失败(继续尝试)", "err", err)
	}
	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		reg.deregister(ctx, c.id)
	}
}

// resolveRetry 解析带重试:500ms 基准间隔(±20% 抖动,多接收方并发等公告
// 时不至于齐步冲击注册中心),超过 wait 后以最后一次错误返回。
func (c *Client) resolveRetry(reg *registryAPI, code string, wait time.Duration) (string, error) {
	deadline := time.Now().Add(wait)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		id, err := reg.resolve(ctx, code)
		cancel()
		if err == nil {
			return id, nil
		}
		if !time.Now().After(deadline) {
			time.Sleep(jitterDur(500*time.Millisecond, 0.2))
			continue
		}
		return "", fmt.Errorf("解析: %w", err)
	}
}

// jitterDur d±d*jitter 的随机时长(抖动防雷群)。
func jitterDur(d time.Duration, jitter float64) time.Duration {
	if jitter <= 0 {
		return d
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return d
	}
	frac := 1 - jitter + 2*jitter*(float64(binary.BigEndian.Uint64(b[:]))/float64(1<<64-1))
	return time.Duration(float64(d) * frac)
}

// progress 每 1MB 打一条进度日志。
func (c *Client) progress() func(got, total int64) {
	var last int64
	return func(got, total int64) {
		if got-last >= 1<<20 || got == total {
			last = got
			c.log.Info("传输进度", "got", got, "total", total)
		}
	}
}

// ---- v4 会话编排:双栈候选+端口映射+先通后优 ----

// xswap 传输源原子槽:先通后优的文件边界换源点。
type xswap struct {
	mu      sync.Mutex
	cur     *xport
	all     []*xport // 建立过的全部承载,收尾统一 finish
	armed   bool     // 发送侧:直连就绪,下一边界换源
	swapped bool
}

// arm 标记直连就绪(发送侧;由升级协程调用)。
func (x *xswap) arm() {
	x.mu.Lock()
	x.armed = true
	x.mu.Unlock()
}

// boundary 发送侧文件边界:已 arm 且未换过 → 写 MsgSwap 并换源,返回 true。
func (x *xswap) boundary() (swap bool) {
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.armed && !x.swapped {
		x.swapped = true
		return true
	}
	return false
}

func (x *xswap) store(v *xport) {
	x.mu.Lock()
	x.cur = v
	x.all = append(x.all, v)
	x.mu.Unlock()
}

func (x *xswap) get() *xport {
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.cur
}

func (x *xswap) finish(isSender bool) {
	x.mu.Lock()
	all := x.all
	x.mu.Unlock()
	for _, v := range all {
		v.finish(isSender)
	}
}

// punchSockets 建 v4/v6 各一套接字(显式分族——双栈通配下 QUIC 地址族混用
// 会静默丢包),并对 v4 申请端口映射(家用路由场景把对称 NAT 变直连)。
func (c *Client) punchSockets() (sock4, sock6 *net.UDPConn, mapped string, release func()) {
	release = func() {}
	sock4, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		return nil, nil, "", release
	}
	if sock6, err = net.ListenUDP("udp6", &net.UDPAddr{}); err != nil {
		sock6 = nil // 无 v6 环境:纯 v4
	}
	if ext, rel, ok := mapUDPPort(sock4); ok {
		if usableExt(ext) {
			mapped = ext.String()
			c.log.Info("端口映射成功", "external", mapped)
			release = rel
		} else {
			rel() // 空映射(如 0.0.0.0:0)归还租约,按无映射走打洞/中继
			c.log.Info("端口映射外部地址不可用,忽略", "external", ext.String())
		}
	}
	return sock4, sock6, mapped, release
}

// buildCandidates 双栈候选:反射公网映射+LAN 候选(v4/v6 各自)+端口映射地址。
func (c *Client) buildCandidates(sock4, sock6 *net.UDPConn, mapped string) *candInfo {
	ci := &candInfo{UDPLAN: lanCandidates(sock4), UDPLAN6: lanCandidates6(sock6), UDPMapped: mapped}
	if pub := reflectOwn(sock4, c.opt.Registry); pub != nil {
		ci.UDPPublic = pub.String()
	}
	if sock6 != nil {
		if pub6 := reflectOwn(sock6, c.opt.Registry); pub6 != nil {
			ci.UDPPublic6 = pub6.String()
		}
	}
	return ci
}

// establish 传输承载建立(双角色状态机):
//
//	快打洞(1.5s)双侧独立进行:
//	  双侧成功 → 发送方监听/接收方拨号,直连(常态);
//	  仅发送方成功 → 监听等 8s,超时落中继,后台升级(监听窗口 25s+offer)
//	                等接收方补拨——非对称打洞不再整场失败(真机 215 实测抓出);
//	  仅接收方成功 → 接收方先拨(8s),失败落中继,后台等 offer 补拨;
//	  双侧失败   → 中继先行,后台各打 30s 长洞 → offer/补拨 升级。
//	升级全程不影响已在进行的传输(文件边界 MsgSwap 换源)。
func (c *Client) establish(sw *xswap, sock4, sock6 *net.UDPConn, mapped string, session []byte, cert tls.Certificate, peer *candInfo, isSender bool, ch *channel) (*xport, string, error) {
	k := wire.DeriveKey(session, "cand")
	fast := c.opt.PunchBudget
	if fast > 1500*time.Millisecond {
		fast = 1500 * time.Millisecond
	}
	tgt, punchErr := punchDual(sock4, sock6, peer, k, fast, mapped)

	if punchErr == nil {
		remote := peer.pickUDP(famOf(tgt.sock))
		var x *xport
		var derr error
		if isSender {
			x, derr = establishQUIC(tgt.sock, session, cert, peer.CertFP, nil, true)
		} else {
			x, derr = establishQUIC(tgt.sock, session, cert, peer.CertFP, remote, false)
		}
		if derr == nil {
			return x, "quic-direct(" + famOf(tgt.sock) + ")", nil
		}
		c.log.Warn("快打洞成功但直连建立失败,落中继+后台升级", "err", derr)
	}

	// 中继可达性探测(2s):不可用则长打洞兜底(旧行为)
	relayOK := false
	if conn, derr := net.DialTimeout("tcp", c.relayAddr(), 2*time.Second); derr == nil {
		_ = conn.Close()
		relayOK = true
	}
	if !relayOK {
		c.log.Info("中继不可用,长打洞兜底", "budget", c.opt.PunchBudget.String())
		tgt2, err2 := punchDual(sock4, sock6, peer, k, c.opt.PunchBudget, mapped)
		if err2 != nil {
			return nil, "", fmt.Errorf("打洞失败且中继不可用: %w", err2)
		}
		var x *xport
		var derr error
		if isSender {
			x, derr = establishQUICBudget(tgt2.sock, session, cert, peer.CertFP, nil, true, c.opt.PunchBudget+5*time.Second)
		} else {
			x, derr = establishQUIC(tgt2.sock, session, cert, peer.CertFP, peer.pickUDP(famOf(tgt2.sock)), false)
		}
		if derr != nil {
			_ = tgt2.sock.Close()
			return nil, "", fmt.Errorf("quic 建立: %w", derr)
		}
		return x, "quic-direct(" + famOf(tgt2.sock) + ")", nil
	}

	// 中继先行
	x, rerr := establishRelay(session, c.relayAddr(), relayToken(session), isSender)
	if rerr != nil {
		return nil, "", fmt.Errorf("中继接入失败: %w", rerr)
	}
	if c.opt.DisablePunch || ch == nil {
		return x, "relay", nil
	}
	if isSender {
		c.startUpgradeSender(sw, x, sock4, sock6, mapped, session, cert, peer, ch, k, tgt)
	} else {
		c.startUpgradeReceiver(sw, x, sock4, sock6, session, cert, ch, k)
	}
	return x, "relay(后台升级中)", nil
}

func famOf(sock *net.UDPConn) string {
	if ip, err := net.ResolveUDPAddr("udp", sock.LocalAddr().String()); err == nil && ip.IP.To4() == nil {
		return "v6"
	}
	return "v4"
}

// sockOf 按地址族取本端套接字。
func sockOf(sock4, sock6 *net.UDPConn, family string) *net.UDPConn {
	if family == "v6" {
		return sock6
	}
	return sock4
}

// startUpgradeSender 升级编排(发送侧):监听窗口 25s + offer(带新候选);
// answer 到达即 arm,发送主流程在下一文件边界写 MsgSwap 换源。
// fastTgt 非空(快打洞成功但接收方未至)时直接复用,否则补打 30s 长洞。
func (c *Client) startUpgradeSender(sw *xswap, relayX *xport, sock4, sock6 *net.UDPConn, mapped string, session []byte, cert tls.Certificate, peer *candInfo, ch *channel, k [32]byte, fastTgt *punchTarget) {
	go func() {
		tgt := fastTgt
		if tgt == nil {
			t, err := punchDual(sock4, sock6, peer, k, 30*time.Second, mapped)
			if err != nil {
				c.log.Info("后台打洞未通(全程中继)", "reason", err.Error())
				return
			}
			tgt = t
		}
		fam := famOf(tgt.sock)
		ownNew := c.buildCandidates(sock4, sock6, mapped)
		ownNew.CertFP = peer.CertFP // 复用会话证书(指纹不变)
		boxed, serr := ownNew.seal(k)
		if serr != nil {
			return
		}
		// 先监听(接收方拨入),offer 随后——顺序不能反(真机踩坑:先 offer
		// 后监听会让接收方拨号扑空,双侧互相等待超时)
		dxCh := make(chan *xport, 1)
		go func() {
			dx, err := establishQUICBudget(tgt.sock, session, cert, ownNew.CertFP, nil, true, 25*time.Second)
			if err == nil {
				dxCh <- dx
			}
		}()
		offer, _ := json.Marshal(map[string]any{"u": "offer", "fam": fam, "cand": boxed})
		if err := ch.send(offer); err != nil {
			return
		}
		select {
		case dx := <-dxCh:
			sw.store(dx)
			sw.arm()
			c.log.Info("直连升级就绪(文件边界换源)", "family", fam)
		case <-time.After(30 * time.Second):
			c.log.Info("升级应答超时(全程中继)", "family", fam)
		}
	}()
}

// startUpgradeReceiver 升级编排(接收侧):等 offer(同时自身快/长打洞在
// establish 已处理),按 offer 族拨发送方新候选,成功回 ready。
func (c *Client) startUpgradeReceiver(sw *xswap, relayX *xport, sock4, sock6 *net.UDPConn, session []byte, cert tls.Certificate, ch *channel, k [32]byte) {
	go func() {
		raw, err := ch.recv()
		if err != nil {
			return
		}
		var offer struct {
			U    string          `json:"u"`
			Fam  string          `json:"fam"`
			Cand json.RawMessage `json:"cand"`
		}
		if err := json.Unmarshal(raw, &offer); err != nil || offer.U != "offer" {
			return
		}
		sock := sockOf(sock4, sock6, offer.Fam)
		plain, oerr := open(k, offer.Cand)
		if sock == nil || oerr != nil {
			return
		}
		var peerNew candInfo
		if err := json.Unmarshal(plain, &peerNew); err != nil {
			return
		}
		remote := peerNew.pickUDP(offer.Fam)
		if remote == nil {
			return
		}
		dx, derr := establishQUIC(sock, session, cert, peerNew.CertFP, remote, false)
		if derr != nil {
			c.log.Info("升级拨号失败(留中继)", "err", derr)
			return
		}
		sw.store(dx)
		ready, _ := json.Marshal(map[string]any{"u": "ready"})
		_ = ch.send(ready)
		c.log.Info("直连升级拨号完成(等待发送方边界换源)", "family", offer.Fam)
	}()
}

// Send 多文件发送(文件/目录混填)。code 为空则自动生成;返回实际使用的口令。
func (c *Client) Send(paths []string, code string) (string, error) {
	if code == "" {
		var err error
		if code, err = GenerateCode(); err != nil {
			return "", err
		}
	}
	dereg, err := c.setupNodeAnnounce(code)
	if err != nil {
		return "", err
	}
	defer dereg()

	ch, err := joinChannel(c.opt.Registry, code, c.id, 10*time.Minute)
	if err != nil {
		return "", err
	}
	defer ch.close() // 注:候选交换后信道归升级协程独占,此处关闭即其生命周期

	if err := negotiateVersion(ch); err != nil {
		return code, err
	}
	c.log.Info("对端已接入,开始 PAKE")

	session, err := runPake([]byte(code), true, ch.exchange())
	if err != nil {
		return code, err
	}
	// 首个 AEAD 使用即口令正确性判定(错口令=密钥不一致=解密失败)

	cert, ownFP, err := sessionCert()
	if err != nil {
		return code, fmt.Errorf("会话证书: %w", err)
	}
	sock4, sock6, mapped, releaseSockets := c.punchSockets()
	defer releaseSockets()
	own := c.buildCandidates(sock4, sock6, mapped)
	own.CertFP = ownFP
	peer, err := exchangeCandidates(ch, wire.DeriveKey(session, "cand"), own)
	if err != nil {
		_ = sock4.Close()
		_ = sock6.Close()
		return code, err
	}

	sw := &xswap{}
	x, via, err := c.establish(sw, sock4, sock6, mapped, session, cert, peer, true, ch)
	if err != nil {
		_ = sock4.Close()
		_ = sock6.Close()
		return code, err
	}
	sw.store(x)
	defer func() { sw.finish(true) }()
	c.log.Info("传输通道建立", "via", via)

	n, err := sendAll(sw.get, paths, c.progress(), sw.boundary)
	if err != nil {
		return code, err
	}
	c.log.Info("发送完成", "code", code, "files", n)
	return code, nil
}

// Receive 多文件接收,返回落盘路径清单。
func (c *Client) Receive(code, dir string) ([]string, error) {
	// resolve 先行:钉定发送方身份(防信道被第三方抢入)。HRW 链逐节点解析,
	// miss/不可达顺延下一节点;命中节点的租约注册与信道同源。
	var winner *registryAPI
	var senderID string
	for _, base := range c.registryChain(code) {
		reg := newRegistryAPI(base)
		id, err := c.resolveRetry(reg, code, 4*time.Second)
		if err == nil {
			winner, senderID = reg, id
			break
		}
		c.log.Warn("注册中心解析未命中,顺延下一节点", "base", base, "err", err)
	}
	if winner == nil {
		return nil, fmt.Errorf("解析: 全部注册中心均无该口令")
	}
	dereg := c.setupNode(winner)
	defer dereg()

	ch, err := joinChannel(winner.base, code, c.id, 10*time.Minute)
	if err != nil {
		return nil, err
	}
	defer ch.close()
	if ch.peerID != senderID {
		return nil, fmt.Errorf("身份核对失败: 信道对端 %s ≠ 公告节点 %s", ch.peerID, senderID)
	}

	if err := negotiateVersion(ch); err != nil {
		return nil, err
	}
	c.log.Info("已配对且身份核对通过,开始 PAKE")

	session, err := runPake([]byte(code), false, ch.exchange())
	if err != nil {
		return nil, err
	}

	cert, ownFP, err := sessionCert()
	if err != nil {
		return nil, fmt.Errorf("会话证书: %w", err)
	}
	sock4, sock6, mapped, releaseSockets := c.punchSockets()
	defer releaseSockets()
	own := c.buildCandidates(sock4, sock6, mapped)
	own.CertFP = ownFP
	peer, err := exchangeCandidates(ch, wire.DeriveKey(session, "cand"), own)
	if err != nil {
		_ = sock4.Close()
		_ = sock6.Close()
		return nil, err
	}

	sw := &xswap{}
	x, via, err := c.establish(sw, sock4, sock6, mapped, session, cert, peer, false, ch)
	if err != nil {
		_ = sock4.Close()
		_ = sock6.Close()
		return nil, err
	}
	sw.store(x)
	defer func() { sw.finish(false) }()
	c.log.Info("传输通道建立", "via", via)

	out, err := recvAll(sw.get, dir, c.opt.ChooseFiles, c.progress())
	if err != nil {
		return out, err
	}
	c.log.Info("接收完成", "files", len(out))
	return out, nil
}

// setupNodeAnnounce 发送侧合并流程:HRW 链逐节点 注册+公告,成功即选定信道
// 节点;全败返回报错注销函数。
func (c *Client) setupNodeAnnounce(code string) (func(), error) {
	chain := c.registryChain(code)
	for _, base := range chain {
		reg := newRegistryAPI(base)
		d := c.setupNode(reg)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		expires := time.Now().Add(15 * time.Minute)
		err := reg.announce(ctx, c.id, code, expires)
		cancel()
		if err == nil {
			c.log.Info("公告就绪", "base", base)
			return d, nil
		}
		d()
		c.log.Warn("注册中心公告失败,顺延下一节点", "base", base, "err", err)
	}
	return func() {}, fmt.Errorf("公告: 全部注册中心不可用(%d 个)", len(chain))
}

// discardHandler Quiet 模式的空日志处理器。// discardHandler Quiet 模式的空日志处理器。// discardHandler Quiet 模式的空日志处理器。// discardHandler Quiet 模式的空日志处理器。
type discardHandler struct{}

func (discardHandler) Enabled(_ context.Context, _ slog.Level) bool  { return false }
func (discardHandler) Handle(_ context.Context, _ slog.Record) error { return nil }
func (h discardHandler) WithAttrs([]slog.Attr) slog.Handler          { return h }
func (h discardHandler) WithGroup(string) slog.Handler               { return h }
