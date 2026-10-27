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
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/oekit/concurrency/async"

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
	async.GoSafeLabeled("signaling-janitor", func() { h.janitor(ctx) })
	return h
}

// ---- 会话与对等端 ----

type peer struct {
	nodeID    string
	conn      *websocket.Conn
	send      chan []byte // 出站 JSON 帧（writePump 消费）
	done      chan struct{}
	closeOnce sync.Once
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

func (s *session) remove(p *peer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.peers {
		if s.peers[i] == p {
			s.peers[i] = nil
		}
	}
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
	sess.remove(p)

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

	if other := sess.other(p); other != nil {
		enqueue(other, serverFrame{Type: "peer_left"})
		// 不再 closePeer(other)：对端保留在会话内等补位
	}
	closePeer(p)
}

// ---- 清扫 ----

func (h *Hub) janitor(ctx context.Context) {
	interval := h.cfg.SessionTTL / 2
	if interval < 250*time.Millisecond {
		interval = 250 * time.Millisecond
	}
	if interval > 30*time.Second {
		interval = 30 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			// 单轮 panic 收编（RunSafeLabeled→全局 panic handler）：会话清扫炸掉=
			// 过期会话永不回收，信令表只增不减
			async.RunSafeLabeled("signaling-janitor", func() {
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
	}
}

// ---- 出入站帧 ----

func enqueue(p *peer, f serverFrame) {
	b, ok := marshalFrame(f)
	if !ok {
		return
	}
	select {
	case p.send <- b:
	default:
		closePeer(p) // 慢消费者：直接断开，不阻塞任何路径
	}
}

func closePeer(p *peer) {
	p.closeOnce.Do(func() { close(p.done) })
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
