// Package signaling 实现 M3 设备直传的 WS 信令信道（GET /v1/channel/{hash}）。
//
// 口令即房间号：双方以同一 code_hash 接入，服务端配对后在两 peer 间转发
// 不透明握手帧（PAKE blob / 候选地址）。信任模型：
//   - 准入需节点身份：hello 帧以 Ed25519 节点私钥签名（channel-join 负载），
//     且节点须处于有效租约内——匿名者连门都进不来；
//   - 服务端零知识：只见 hash 与不透明帧，PAKE 保证其无法推导会话密钥；
//     候选地址等敏感信息应由客户端在 PAKE 完成后加密传输（客户端契约，见 README）；
//   - 接收方以 resolve 拿到的源 node_id 与 paired 帧的 peer_id 交叉核对，防换人。
//
// 服务端职责止步于"配对 + 转发 + 治理"：PAKE/打洞/传输全部在对等端完成。
package signaling

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/oekit/concurrency/loop"
	"github.com/oekit/network/wsutil"

	"github.com/pigeonbox/p2p/internal/registry"
)

// Config 信令信道参数。
type Config struct {
	SessionTTL         time.Duration // 会话最长生命周期（含等待配对）
	IdleTimeout        time.Duration // 连接空闲上限（pong 与数据帧均续期）
	HelloTimeout       time.Duration // 接入后交 hello 的时限
	PingPeriod         time.Duration // 服务端 ping 周期（须 < IdleTimeout）
	WriteWait          time.Duration // 单次写超时
	MaxFrameBytes      int           // data 帧负载上限（PAKE/候选足够）
	MaxSessionsPerNode int           // 单节点并发会话上限
	MaxTotalSessions   int           // 全局并发会话上限
}

// DefaultConfig 默认参数。
func DefaultConfig() Config {
	return Config{
		SessionTTL:         10 * time.Minute,
		IdleTimeout:        2 * time.Minute,
		HelloTimeout:       10 * time.Second,
		PingPeriod:         20 * time.Second,
		WriteWait:          10 * time.Second,
		MaxFrameBytes:      16 << 10,
		MaxSessionsPerNode: 8,
		MaxTotalSessions:   1024,
	}
}

// Metrics 信令指标接口（server 侧适配注入，避免包反向依赖）。
type Metrics interface {
	SignalingSessions(delta int) // 活跃会话仪表 ±delta
	SignalingJoin(result string) // 接入计数：waiting|paired|busy|rejected
}

type noopMetrics struct{}

func (noopMetrics) SignalingSessions(int) {}
func (noopMetrics) SignalingJoin(string)  {}

// Hub 信令会话中心。并发安全。
type Hub struct {
	cfg     Config
	reg     *registry.Service
	metrics Metrics
	now     func() time.Time

	mu       sync.Mutex
	sessions map[string]*session // code_hash → session
}

// NewHub 构造信令中心；ctx 结束时停止清扫协程（连接不强制断开，随进程退出）。
func NewHub(ctx context.Context, cfg Config, reg *registry.Service, m Metrics) *Hub {
	// 构造期 fail-fast（镜像 config.validate 的启动期口径，p2p#38 守卫的第二道）：
	// 生产路径经 config.Load→validate 已拦，但 NewHub 是公开构造器——绕过 Load 的
	// 程序化构造（测试/新调用方）漏填时，原会在首个连接的 pingPump 里以
	// time.NewTicker(0) 的晦涩 panic 晚炸。这里把晚炸变成早炸+清晰信息
	//（对齐本生态「非法入参当场暴露」：redisx.NewPeriodLimit 对 nil store 同款 panic）。
	if cfg.PingPeriod <= 0 || cfg.WriteWait <= 0 || cfg.PingPeriod >= cfg.IdleTimeout {
		panic(fmt.Sprintf(
			"signaling: 非法 Config（PingPeriod=%v WriteWait=%v IdleTimeout=%v）：须 PingPeriod>0、WriteWait>0、PingPeriod<IdleTimeout——用 DefaultConfig() 起底再改字段",
			cfg.PingPeriod, cfg.WriteWait, cfg.IdleTimeout))
	}
	if m == nil {
		m = noopMetrics{}
	}
	h := &Hub{
		cfg:      cfg,
		reg:      reg,
		metrics:  m,
		now:      time.Now,
		sessions: make(map[string]*session),
	}
	h.janitor(ctx) // loop.Run 自持 goroutine（GoSafeLabeled），非阻塞
	return h
}

// ---- 会话与对等端 ----

type peer struct {
	nodeID string
	conn   *websocket.Conn
	// outbox 是这条连接唯一的帧写出口：websocket 实现不许并发写，所以帧
	// 必须先进有界队列，由它独家取走。它同时管「慢消费者」——队列满了
	// Send 只报告不处置，处置由本包按场景决定。
	outbox *wsutil.Outbox
	// writeWait 是单次写/单次控制帧的超时。
	writeWait time.Duration
}

type session struct {
	hash      string
	createdAt time.Time
	mu        sync.RWMutex
	peers     [2]*peer
}

func (s *session) other(p *peer) *peer {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, q := range s.peers {
		if q != nil && q != p {
			return q
		}
	}
	return nil
}

func (s *session) full() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.peers[0] != nil && s.peers[1] != nil
}

func (s *session) put(p *peer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.peers {
		if s.peers[i] == nil {
			s.peers[i] = p
			return
		}
	}
}

// detach 从会话摘除 p,并在**同一临界区**返回「p 离开瞬间」的同侪。
//
// 摘除与取同侪必须原子(p2p#40 TOCTOU):leave 若先 remove 再 other,两次
// 调用之间可有并发 join 补位——other 读到的是「补位后的新对端」,会把
// peer_left 发给刚配对成功的第三方(它从未与 p 配对),而 p 真正的同侪漏收
// peer_left 只能干等自己的 recv 超时。session.mu 每次调用各自上锁,跨两次
// 调用没有原子性 ⇒ 把两次操作收进一个临界区:join 的 full/put、其它 peer
// 的 detach 全走同一把锁,补位与并发摘除都不可能插入其间。
func (s *session) detach(p *peer) *peer {
	s.mu.Lock()
	defer s.mu.Unlock()
	var other *peer
	for i, q := range s.peers {
		if q == p {
			s.peers[i] = nil
		} else if q != nil {
			other = q
		}
	}
	return other
}

func (s *session) snapshot() [2]*peer {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.peers
}

// broadcast 广播帧（best-effort，慢消费者由 enqueue 断开）。
func (s *session) broadcast(f serverFrame) {
	for _, p := range s.snapshot() {
		if p != nil {
			enqueue(p, f)
		}
	}
}

func (s *session) closeAll() {
	for _, p := range s.snapshot() {
		if p != nil {
			closePeer(p)
		}
	}
}

// ---- 接入与退出 ----

// JoinOutcome join 结果。
type JoinOutcome int

const (
	JoinWaiting JoinOutcome = iota // 首个接入，等待对方
	JoinPaired                     // 已配对
	JoinBusy                       // 拒入（信道占用/超配额）
)

// join 接入信道。成功返回会话；拒绝返回原因。
func (h *Hub) join(hash string, p *peer) (JoinOutcome, *session, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if len(h.sessions) >= h.cfg.MaxTotalSessions {
		return JoinBusy, nil, errBusy("全局会话数达上限")
	}
	// 单节点并发会话配额（滥用治理）
	count := 0
	for _, sess := range h.sessions {
		for _, q := range sess.snapshot() {
			if q != nil && q.nodeID == p.nodeID {
				count++
			}
		}
	}
	if count >= h.cfg.MaxSessionsPerNode {
		return JoinBusy, nil, errBusy("单节点会话数达上限")
	}

	if sess, ok := h.sessions[hash]; ok {
		if sess.full() {
			return JoinBusy, nil, errBusy("该口令信道已被占用")
		}
		sess.put(p)
		return JoinPaired, sess, nil
	}
	sess := &session{hash: hash, createdAt: h.now()}
	sess.peers[0] = p // 未发布前赋值，无并发
	h.sessions[hash] = sess
	h.metrics.SignalingSessions(1)
	return JoinWaiting, sess, nil
}

// leave 对等端退出：仅摘除退出方。对端仍连着时保留会话回等待位，新对端可
// 直接补位配对（2026-10-05 审计 P2：此前任一端退出即删整个会话并断开双方，
// 知道 hash 的第三方可"配对即断"反复杀死会话，阻塞该口令的传输）。
// 会话最终回收由 janitor 按 SessionTTL 兜底；对端若为旧客户端，收到
// peer_left 自行退出时会走同一路径清理空会话，语义收敛不变。
func (h *Hub) leave(sess *session, p *peer) {
	// 摘除与取同侪在 detach 的同一临界区完成(p2p#40):之后的并发 join
	// 改不动这个快照 ⇒ 刚补位配对的新对端不会被误发 peer_left,漏通知的
	// 也不会再是 p 的真同侪。
	other := sess.detach(p)

	h.mu.Lock()
	empty := true
	for _, q := range sess.snapshot() {
		if q != nil {
			empty = false
			break
		}
	}
	if empty {
		if cur, ok := h.sessions[sess.hash]; ok && cur == sess {
			delete(h.sessions, sess.hash)
			h.metrics.SignalingSessions(-1)
		}
	}
	h.mu.Unlock()

	callLeaveAfterDetach() // 测试缝:p2p#40 判据注入点(生产恒空)

	if other != nil {
		enqueue(other, serverFrame{Type: "peer_left"})
		// 不再 closePeer(other)：对端保留在会话内等补位
	}
	closePeer(p)
}

// leaveAfterDetach 测试缝(p2p#40):peer 从会话摘除之后、向同侪发 peer_left
// 之前触发。生产恒为空实现;测试在此同步插入第三方 join,构造「摘除与通知
// 之间补位」的 TOCTOU 窗口(负对照:leave 退回「先 remove 后取同侪」即转红)。
// 读写经 seamMu 互斥:测试改写与残留 readPump 的触发可能并发(-race)。
var (
	seamMu           sync.Mutex
	leaveAfterDetach = func() {}
)

func callLeaveAfterDetach() {
	seamMu.Lock()
	f := leaveAfterDetach
	seamMu.Unlock()
	f()
}

// ---- 清扫 ----

// janitor 会话清扫循环。
//
// 收编 oekit/concurrency/loop.Run（2026-11-03）：手搓「ticker+select+RunSafeLabeled」
// 逐轮防护形态与 loop.runOnce 同构（每轮 async.RunSafeLabeled→全局 panic handler），
// ctx 取消即停。等价性核对：
//   - 首跑时序保持「一个 interval 后」：loop 首轮默认立即跑，用 FirstDelay=interval
//     对齐原 ticker（首轮到期后才扫）；
//   - panic 语义不变：会话清扫炸掉=过期会话永不回收、信令表只增不减，故单轮
//     防护必须保留——loop 每轮自带 RunSafeLabeled(cfg.Name)，内层手包删除；
//   - 忙时丢 tick 合并（ticker cap=1）与原 ticker 行为一致。
func (h *Hub) janitor(ctx context.Context) {
	interval := h.cfg.SessionTTL / 2
	if interval < 250*time.Millisecond {
		interval = 250 * time.Millisecond
	}
	if interval > 30*time.Second {
		interval = 30 * time.Second
	}
	loop.Run(ctx, loop.Config{
		Interval:   interval,
		FirstDelay: interval,
		Name:       "signaling-janitor",
	}, func(context.Context) {
		now := h.now()
		h.mu.Lock()
		var expired []*session
		for hash, sess := range h.sessions {
			if now.Sub(sess.createdAt) > h.cfg.SessionTTL {
				delete(h.sessions, hash)
				expired = append(expired, sess)
			}
		}
		h.mu.Unlock()
		for _, sess := range expired {
			h.metrics.SignalingSessions(-1)
			sess.broadcast(serverFrame{Type: "error", Message: "会话超时"})
			sess.closeAll()
		}
	})
}

// ---- 出入站帧 ----

func enqueue(p *peer, f serverFrame) {
	b, ok := marshalFrame(f)
	if !ok {
		return
	}
	if !p.outbox.Send(b) {
		closePeer(p) // 慢消费者：直接断开，不阻塞任何路径
	}
}

// closePeer 关掉这条连接。
//
// 它只让出站管道收工：管道会把队列里剩下的帧冲刷完，然后由 handler 里那条
// 关闭序列去握手并关连接。顺序不能反——冲刷要在连接还活着时做。
func closePeer(p *peer) {
	p.outbox.Close()
}

// ---- 小件 ----

type busyError struct{ msg string }

func (e *busyError) Error() string { return e.msg }

func errBusy(msg string) error { return &busyError{msg: msg} }

func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		isDigit := c >= '0' && c <= '9'
		isLowerHex := c >= 'a' && c <= 'f'
		if !isDigit && !isLowerHex {
			return false
		}
	}
	return true
}
