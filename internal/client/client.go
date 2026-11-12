package client

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/oekit/concurrency/async"
	"github.com/oekit/concurrency/retry"
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
	// NoRelay 仅直连:跳过中继兜底,打洞失败即报错(强制直连/诊断用)
	NoRelay bool
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

	relayMu    sync.Mutex
	relayCache string // 中继地址发现结果(一次发现,整场复用)
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
	c.relayMu.Lock()
	defer c.relayMu.Unlock()
	if c.relayCache != "" {
		return c.relayCache
	}
	// registry 常带端口(http://host:22346),取主机后换中继端口
	// ——直接拼接会得到 host:22346:12347(215 部署实测踩坑)。
	host := hostOf(c.opt.Registry)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	// 中继端口经注册中心 /health 的 relay_port 自发现(服务器自报,端口拓扑任意);
	// 老服务器无该字段 → 回退历史默认 12347。
	port := 12347
	if p := c.discoverRelayPort(); p > 0 {
		port = p
	}
	c.relayCache = net.JoinHostPort(host, strconv.Itoa(port))
	return c.relayCache
}

// discoverRelayPort GET {registry}/health 读 relay_port;失败返回 0(调用方回退默认)。
func (c *Client) discoverRelayPort() int {
	u := strings.TrimRight(c.opt.Registry, "/") + "/health"
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return 0
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0
	}
	defer func() { _ = resp.Body.Close() }()
	var out struct {
		RelayPort int `json:"relay_port"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return 0
	}
	return out.RelayPort
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
//
// 收编 oekit/concurrency/retry.DoValue(2026-11-02):
//   - 「±20% 抖动」原是 jitterDur(500ms,0.2) 的居中均匀分布 [400ms,600ms);
//     retry 的 JitterRatio 是单边向上 [d,d*(1+ratio)) ⇒ 取 Delay=400ms+JitterRatio=0.5
//     恰好同为 [400ms,600ms) 均匀分布,防雷群语义逐位等价;
//   - 「超过 wait 以最后一次错误返回」的墙钟 deadline 用 Retryable 门控表达:
//     过期即不可重试 ⇒ DoValue 立即返回最后一次错误,再包 "解析: %w"(与原
//     实现逐字一致;原实现的 deadline 检查同样在 attempt 之后,连 per-attempt
//     5s 超时溢出 deadline 的边界行为也一致);
//   - Attempts 是安全兜底(理论上界 wait/最小退避+2),实际总是 deadline 门控先截停。
//   - 行为差异:无。jitterDur 随之删除。
func (c *Client) resolveRetry(reg *registryAPI, code string, wait time.Duration) (string, error) {
	deadline := time.Now().Add(wait)
	id, err := retry.DoValue(context.Background(), retry.Config{
		Attempts:    int(wait/(400*time.Millisecond)) + 2,
		Delay:       400 * time.Millisecond,
		JitterRatio: 0.5, // =500ms±20% 均匀抖动(防雷群)
		Retryable:   func(error) bool { return !time.Now().After(deadline) },
	}, func(int) (string, error) {
		actx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return reg.resolve(actx, code)
	})
	if err != nil {
		return "", fmt.Errorf("解析: %w", err)
	}
	return id, nil
}

// progress 每 1MB 打一条进度日志。
//
// ⚠️ 回调会被**多条流的 goroutine 并发调用**（transfer.go 每个 stream 各一条），
// 此前 last 是裸 int64 闭包变量 ⇒ data race（-race 可复现；读数撕裂会让日志
// 抖成「每 100KB 一条」或长时间不打印）。改为原子量：仅用于限频，无需严格序。
func (c *Client) progress() func(got, total int64) {
	var last atomic.Int64
	return func(got, total int64) {
		if got-last.Load() >= 1<<20 || got == total {
			last.Store(got)
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
	// closed/role:收尾后到达的 upgrade 通道必须**就地回收**
	// （2026-11-06）。finish 取 all 快照后就放手了，而升级协程可能在此之后
	// 才 store 成功（监听窗口 25s > 传输耗时）⇒ 该 xport 永远不在任何人的
	// 收尾清单里 ⇒ QUIC 连接 + 套接字泄漏（每次传输一条）。role 记住收尾角色，
	// 让后到的通道按同一侧语义 finish。
	closed bool
	role   bool
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
	if x.closed {
		role := x.role
		x.mu.Unlock()
		// 收尾已发生 ⇒ 没人会再来回收它，就地 finish（否则泄漏，见 closed 注释）。
		v.finish(role)
		return
	}
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
	x.all = nil // 已回收，防重复 finish
	x.closed = true
	x.role = isSender
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
	ci := &candInfo{UDPLAN: lanCandidates(sock4), UDPLAN6: lanCandidates(sock6), UDPMapped: mapped}
	if pub, err := reflectOwn(sock4, c.opt.Registry); err == nil {
		ci.UDPPublic = pub.String()
	} else {
		c.log.Warn("公网映射地址反射失败,直连候选可能缺失(退化为仅 LAN 候选+中继)", "err", err)
	}
	if sock6 != nil {
		if pub6, err6 := reflectOwn(sock6, c.opt.Registry); err6 == nil {
			ci.UDPPublic6 = pub6.String()
		} else {
			c.log.Warn("IPv6 公网映射地址反射失败(退化为仅 LAN 候选+中继)", "err", err6)
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
//
// quicOpBudget 直连通道(快打洞/长打洞)的 QUIC **接受/拨号**预算。
//
// ⚠️ 发送侧与拨号侧必须**同值**(p2p#20,2026-11-03 实测):
// QUIC 窗口各自从**自己**打洞结束那刻起算 ⇒ 两侧打洞结束时刻相差 Δ 时,
// 拨号方必须活过 Δ 才能等到对侧开始监听。
// 此前拨号侧固定 8s、发送侧 PunchBudget+5s ⇒ 不对称 ⇒ 直连在打洞耗时接近预算时
// 必败("quic 拨号: context deadline exceeded")。实测健康路径的对侧就绪差值
// Δ 已达 6~8s(贴着 8s 边缘)⇒ 负载一抖就红。
//
// ⇒ 统一取「打洞预算 + 握手余量」:任一侧最晚在 PunchBudget 后就绪,
// 对侧窗口覆盖它 ⇒ 必成。生产默认 PunchBudget=4s ⇒ 9s(与原 8s 同量级,
// 「快速失败落中继」的设计意图保留);测试预算三轮放宽后 PunchBudget=45s ⇒ 50s
// （放宽史 3s→6s→20s→45s,见 #23）。
func (c *Client) quicOpBudget() time.Duration {
	return c.opt.PunchBudget + 5*time.Second
}

// upgradeOpBudget 升级通道(后台 offer/补拨)的 QUIC 预算。
//
// 升级是**后台**动作(全程中继兜底)⇒ 窗口可以放宽;
// 但**两侧必须同值**:监听侧等补拨、拨号侧等监听,不同步 ⇒
// 拨号侧会在监听就绪前超时(p2p#20 同款根因)。
const upgradeOpBudget = 25 * time.Second

// listenFirst 发送侧 QUIC 监听:单族直接听;双栈两族**竞速**。
//
// 根因(p2p#33 根因①,2026-11-12):双栈快打洞两侧独立竞速、胜出族无协商,
// 发送侧胜 v4、接收侧胜 v6 时拨号族≠监听族 ⇒ 单族监听下另一族的拨入无人
// 应答,QUIC 必等满 quicOpBudget(测试 50s/生产 9s)超时。两族各起一个监听
// 后,对端拨到哪族哪边先握手成功;先成者胜,败者随 ctx 取消即刻收摊
// (不关套接字——留给回退/升级/收尾)。套接字由 punchDual quiesce 保证
// 打洞循环已停(transport.go:135 交接前提)。
//
// 预算必须与拨号侧同源(p2p#20)⇒ 实参显式写 c.quicOpBudget()
// (quic_budget_guard_test 逐调用点锁形态)。
func (c *Client) listenFirst(socks []*net.UDPConn, session []byte, cert tls.Certificate, peerFP string) (*xport, string, error) {
	live := make([]*net.UDPConn, 0, 2)
	seen := make(map[*net.UDPConn]bool, 2)
	for _, s := range socks {
		if s != nil && !seen[s] {
			seen[s] = true
			live = append(live, s)
		}
	}
	if len(live) == 0 {
		return nil, "", fmt.Errorf("quic 建立: 无可用 UDP 套接字")
	}
	if len(live) == 1 {
		x, err := establishQUICBudget(context.Background(), live[0], session, cert, peerFP, nil, true, c.quicOpBudget(), c.log)
		return x, famOf(live[0]), err
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type res struct {
		x   *xport
		fam string
		err error
	}
	ch := make(chan res, len(live))
	for _, s := range live {
		sock := s
		async.GoSafeLabeled("quic-listen-race", func() {
			x, err := establishQUICBudget(ctx, sock, session, cert, peerFP, nil, true, c.quicOpBudget(), c.log)
			ch <- res{x: x, fam: famOf(sock), err: err}
		})
	}
	// 先回先出:接收侧只拨一次(单族 punch 验证地址),至多一个监听收得到拨入
	// ——任一监听出结果即定胜负。成功=直连成;失败=快路径已无对端可等,立即
	// 回退,不等另一族空转到预算(那正是 50s 空转的另一半)。
	r := <-ch
	// 先显式取消、再把兄弟监听的结果**收干**才返回:保证本函数返回时没有任何
	// 在途 Transport(tr.Close 已同步复位 conn),调用方可立即把套接字交回
	// 回退长打洞/升级通道(p2p#33 交接卫生)。
	cancel()
	for i := 1; i < len(live); i++ {
		<-ch
	}
	if r.err != nil {
		return nil, "", r.err
	}
	return r.x, r.fam, nil
}

func (c *Client) establish(sw *xswap, sock4, sock6 *net.UDPConn, mapped string, session []byte, cert tls.Certificate, peer *candInfo, isSender bool, ch *channel) (*xport, string, error) {
	k := wire.DeriveKey(session, "cand")
	fast := c.opt.PunchBudget
	if fast > 1500*time.Millisecond {
		fast = 1500 * time.Millisecond
	}
	tgt, punchErr := punchDual(sock4, sock6, peer, k, fast, mapped, c.log)

	if punchErr == nil {
		// 交接前提(2026-10-15 定长墙根因 + p2p#33):punchDual 返回前已统一
		// quiesce——打洞循环必停、读截止归零,无需再手清;败族套接字**不再关闭**
		// (双族都要留给发送侧双族监听竞速/回退长打洞/升级通道)。
		var x *xport
		var derr error
		var via string
		if isSender {
			// 发送侧双族监听竞速:接收侧可能在另一族胜出(双栈错位,p2p#33 根因①),
			// 单族监听下拨号族≠监听族 ⇒ QUIC 必等满预算超时。
			var fam string
			x, fam, derr = c.listenFirst([]*net.UDPConn{sock4, sock6}, session, cert, peer.CertFP)
			via = "quic-direct(" + fam + ")"
		} else {
			// 拨号目标 = **punch 验证过的对端地址**(p2p#33 根因①):旧实现传
			// peer.pickUDP 静态候选,与 establishQUICBudget 文档背离且可能拨到
			// 从未验证可达的地址。
			x, derr = establishQUICBudget(context.Background(), tgt.sock, session, cert, peer.CertFP, tgt.addr, false, c.quicOpBudget(), c.log)
			via = "quic-direct(" + famOf(tgt.sock) + ")"
		}
		if derr == nil {
			return x, via, nil
		}
		c.log.Warn("快打洞成功但直连建立失败,落中继+后台升级", "err", derr)
	}

	// 中继可达性探测(2s):不可用则长打洞兜底(旧行为);仅直连模式(-no-relay)跳过探测
	relayOK := false
	if !c.opt.NoRelay {
		if conn, derr := net.DialTimeout("tcp", c.relayAddr(), 2*time.Second); derr == nil {
			_ = conn.Close()
			relayOK = true
		}
	}
	if !relayOK {
		fallReason := "中继不可用"
		if c.opt.NoRelay {
			fallReason = "仅直连模式"
		}
		c.log.Info(fallReason+",长打洞兜底", "budget", c.opt.PunchBudget.String())
		// 回退长打洞的套接字前提(p2p#33 根因②):快路径若试过 QUIC,失败路径已
		// tr.Close()——quic-go 对用户 conn 是「停读循环+读截止归零+不关 fd」
		// (TestTransportCloseRestoresRawConn 钉版),叠加 punchDual 的 quiesce
		// ⇒ 两族套接字可显式复用,不再「污染空转」;败族也从未被关(快路径已改)。
		tgt2, err2 := punchDual(sock4, sock6, peer, k, c.opt.PunchBudget, mapped, c.log)
		if err2 != nil {
			return nil, "", fmt.Errorf("打洞失败且%s: %w", fallReason, err2)
		}
		var x *xport
		var derr error
		var via string
		if isSender {
			// 与快路径同款:双族监听竞速(回退段两侧同样各自竞速,错位依旧可能)。
			var fam string
			x, fam, derr = c.listenFirst([]*net.UDPConn{sock4, sock6}, session, cert, peer.CertFP)
			via = "quic-direct(" + fam + ")"
		} else {
			// ⚠️ 拨号侧预算必须与发送侧**同值**(p2p#20):两侧的 QUIC 窗口各自从
			// **自己**打洞结束那刻起算 ⇒ 打洞结束时刻相差 Δ 时,拨号方必须活过 Δ。
			// 此前拨号侧固定 8s、发送侧 PunchBudget+5s ⇒ 不对称 ⇒ 拨号方常在
			// 对侧就绪前就超时("quic 拨号: context deadline exceeded")。
			// 拨号目标=punch 验证过的 tgt2.addr(p2p#33 根因①,同快路径)。
			x, derr = establishQUICBudget(context.Background(), tgt2.sock, session, cert, peer.CertFP, tgt2.addr, false, c.quicOpBudget(), c.log)
			via = "quic-direct(" + famOf(tgt2.sock) + ")"
		}
		if derr != nil {
			_ = tgt2.sock.Close()
			return nil, "", fmt.Errorf("quic 建立: %w", derr)
		}
		return x, via, nil
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
	// 后台升级编排为即发即弃:panic 面=QUIC/TLS 握手(第三方库)与打洞栈,
	// 收编后走既有"留在中继"降级路径,不拖垮传输进程。
	async.GoSafe(func() {
		tgt := fastTgt
		if tgt == nil {
			t, err := punchDual(sock4, sock6, peer, k, 30*time.Second, mapped, c.log)
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
		async.GoSafe(func() {
			dx, err := establishQUICBudget(context.Background(), tgt.sock, session, cert, ownNew.CertFP, nil, true, upgradeOpBudget, c.log)
			if err == nil {
				dxCh <- dx
			}
		})
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
	})
}

// startUpgradeReceiver 升级编排(接收侧):等 offer(同时自身快/长打洞在
// establish 已处理),按 offer 族拨发送方新候选,成功回 ready。
func (c *Client) startUpgradeReceiver(sw *xswap, relayX *xport, sock4, sock6 *net.UDPConn, session []byte, cert tls.Certificate, ch *channel, k [32]byte) {
	// 同发送侧:即发即弃的升级编排,panic 收编后留在中继,不影响传输主流程。
	async.GoSafe(func() {
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
		// 预算与监听侧**同值**(upgradeOpBudget):监听侧等补拨、拨号侧等监听,
		// 不同步 ⇒ 拨号侧会在监听就绪前超时(p2p#20 同款根因)。
		dx, derr := establishQUICBudget(context.Background(), sock, session, cert, peerNew.CertFP, remote, false, upgradeOpBudget, c.log)
		if derr != nil {
			c.log.Info("升级拨号失败(留中继)", "err", derr)
			return
		}
		sw.store(dx)
		ready, _ := json.Marshal(map[string]any{"u": "ready"})
		_ = ch.send(ready)
		c.log.Info("直连升级拨号完成(等待发送方边界换源)", "family", offer.Fam)
	})
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
	// 失败路径保留公告（2026-10-14 GB 级自动续传设计）：公告按 15min TTL 自消，
	// 失败即注销会与 supervisor 重派的新尝试公告竞态——旧进程的 deferred
	// 注销把新公告级联删掉，接收方 resolve 永远 miss（冻结复现实锤）。
	// 成功路径注销语义不变（文件已送达，公告立即失效是正确行为）。
	sendOK := false
	defer func() {
		if sendOK {
			dereg()
		}
	}()

	code, err = c.sendChannel(paths, code)
	sendOK = err == nil
	return code, err
}

// sendChannel 信道段(公告/配对就绪后):接入→协商→PAKE→候选→承载→传输。
// 配对码模式以兑换到的 secret 为 code 复用本段——数据面零协议分支。
func (c *Client) sendChannel(paths []string, code string) (string, error) {
	ch, err := joinChannel(c.opt.Registry, code, c.id, 10*time.Minute)
	if err != nil {
		return "", err
	}
	defer ch.close() // 注:候选交换后信道归升级协程独占,此处关闭即其生命周期

	if _, err := negotiateVersion(ch); err != nil {
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
	return c.receiveFrom(winner.base, code, dir, senderID)
}

// receiveFrom 解析钉定后的信道段(接入→身份核对→协商→PAKE→候选→承载→接收)。
// 配对码模式传入 claim 兑换到的 creator 作为钉定来源,跳过公告解析。
func (c *Client) receiveFrom(regBase, code, dir, expectedPeer string) ([]string, error) {
	reg := newRegistryAPI(regBase)
	d := c.setupNode(reg)
	defer d()

	ch, err := joinChannel(regBase, code, c.id, 10*time.Minute)
	if err != nil {
		return nil, err
	}
	defer ch.close()
	if ch.peerID != expectedPeer {
		return nil, fmt.Errorf("身份核对失败: 信道对端 %s ≠ 预期节点 %s", ch.peerID, expectedPeer)
	}

	if _, err := negotiateVersion(ch); err != nil {
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

// discardHandler Quiet 模式的空日志处理器。
type discardHandler struct{}

func (discardHandler) Enabled(_ context.Context, _ slog.Level) bool  { return false }
func (discardHandler) Handle(_ context.Context, _ slog.Record) error { return nil }
func (h discardHandler) WithAttrs([]slog.Attr) slog.Handler          { return h }
func (h discardHandler) WithGroup(string) slog.Handler               { return h }
