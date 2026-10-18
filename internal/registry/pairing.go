// 配对码会话（2026-10-18，hub docs/specs/2026-10-18-p2p-pairing-code-design.md）。
//
// 四位定时配对码是「门牌号 + 门铃」而非钥匙：亮码方登记高熵 secret，服务端
// 签发短码；敲门方凭码 claim（节点签名准入），经亮码方 approve 后一次性兑换
// secret——此后双方走既有信令信道 + PAKE + 传输链路，本服务不参与数据面。
//
// 信任模型：服务端持有 secret（签发即知情），与 Box 取件码同构；README 声明。
//
// 状态机：active → claimed → granted（secret 一次性发放即删）| denied（拒绝
// 即烧）。终态会话直接出表——后续 claim/poll 得到干净的 404，无重放窗口。
// 过期（expiresAt，active/claimed 共用码 TTL）由 Sweep 与读路径双保险回收。
package registry

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/oekit/concurrency/async"
	"github.com/pigeonbox/p2p/internal/store"
)

// PairingConfig 配对码参数（装配层从 config 注入；零值项用内置默认）。
type PairingConfig struct {
	CodeTTL    time.Duration // 配对码有效窗（默认 5m）
	SessionTTL time.Duration // 会话总寿命上限（默认 10m，GC 硬顶）
	CodeLen    int           // 码位数（默认 4，允许 4-8）
	MaxPerNode int           // 单节点活跃会话上限（默认 8）
	MaxTotal   int           // 全局会话上限（默认 4096，内存耗尽防护）
}

// Defaults 补齐零值配置项。
func (c PairingConfig) withDefaults() PairingConfig {
	if c.CodeTTL <= 0 {
		c.CodeTTL = 5 * time.Minute
	}
	if c.SessionTTL <= 0 {
		c.SessionTTL = 10 * time.Minute
	}
	if c.CodeLen < 4 || c.CodeLen > 8 {
		c.CodeLen = 4
	}
	if c.MaxPerNode <= 0 {
		c.MaxPerNode = 8
	}
	if c.MaxTotal <= 0 {
		c.MaxTotal = 4096
	}
	if c.SessionTTL < c.CodeTTL {
		c.SessionTTL = c.CodeTTL // 硬顶不得低于码窗
	}
	return c
}

// 签名负载约定（与 spec §2.2 逐字对齐，客户端实现必须一致）：
//
//	pair-create:   node_id | secret | ts
//	pair-claim:    node_id | code | claim_id | ts
//	pair-approve:  node_id | code | decision | claimer | ts
//	pair-requests: node_id | ts
const (
	pairDecisionAccept = "accept"
	pairDecisionDeny   = "deny"
)

// ---- 输入 ----

type PairCreateInput struct {
	NodeID string `json:"node_id"`
	Secret string `json:"secret"`
	TS     int64  `json:"ts"`
	Sig    string `json:"sig"`
}

type PairClaimInput struct {
	NodeID  string `json:"node_id"`
	Code    string `json:"code"`
	ClaimID string `json:"claim_id"`
	TS      int64  `json:"ts"`
	Sig     string `json:"sig"`
}

type PairApproveInput struct {
	NodeID   string `json:"node_id"`
	Code     string `json:"code"`
	Decision string `json:"decision"`
	Claimer  string `json:"claimer"`
	TS       int64  `json:"ts"`
	Sig      string `json:"sig"`
}

type PairRequestsInput struct {
	NodeID string `json:"node_id"`
	TS     int64  `json:"ts"`
	Sig    string `json:"sig"`
}

// ---- 输出视图 ----

type PairRequestView struct {
	NodeID string `json:"node_id"`
	Name   string `json:"name"`
}

type PairSessionView struct {
	Code      string            `json:"code"`
	ExpiresIn int64             `json:"expires_in"` // 秒
	Requests  []PairRequestView `json:"requests"`
}

type PairClaimResult struct {
	Status  string `json:"status"` // pending | granted
	Secret  string `json:"secret,omitempty"`
	Creator string `json:"creator,omitempty"`
	// ExpiresIn 仅 pending 态返回：码剩余秒数，claimant 据此设轮询截止。
	ExpiresIn int64 `json:"expires_in,omitempty"`
}

// ---- 会话存储 ----

type pairState int

const (
	pairActive pairState = iota
	pairClaimed
	pairGranted // 终态：批准待取（下一次同 claim_id 的 claim 兑换后删除）
)

type pairSession struct {
	code, secret, creator string
	claimer, claimerName  string
	claimID               string
	state                 pairState
	expiresAt             time.Time
}

// nodeLeaser 租约校验来源（由 *Service 实现；配对会话与节点仓同包装配注入）。
type nodeLeaser interface {
	liveNodeErr(ctx context.Context, id string) (store.Node, error)
}

// PairingService 配对码会话中心。并发安全；纯内存（码 TTL ≤10min，无持久化价值）。
type PairingService struct {
	cfg   PairingConfig
	now   func() time.Time
	nodes nodeLeaser

	mu       sync.Mutex
	sessions map[string]*pairSession // code → session（仅 active/claimed/granted 存续）
}

// NewPairingService 构造（ctx 用于 GC 协程生命周期；nodes 为租约校验来源）。
func NewPairingService(ctx context.Context, cfg PairingConfig, nodes nodeLeaser) *PairingService {
	s := &PairingService{
		cfg:      cfg.withDefaults(),
		now:      time.Now,
		nodes:    nodes,
		sessions: make(map[string]*pairSession),
	}
	go s.janitor(ctx)
	return s
}

// janitor 过期会话清扫（panic 收编同信令 janitor：清扫炸掉=表只增不减）。
func (s *PairingService) janitor(ctx context.Context) {
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			async.RunSafeLabeled("pairing-janitor", func() { s.sweep() })
		}
	}
}

// sweep 清扫过期会话；返回清理数（测试/管理端用）。
func (s *PairingService) sweep() int {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for code, sess := range s.sessions {
		if now.After(sess.expiresAt) {
			delete(s.sessions, code)
			n++
		}
	}
	return n
}

// Stats 活跃会话数（管理端/测试）。
func (s *PairingService) Stats() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sessions)
}

// ---- 业务 ----

// Create 亮码方建会话。要求有效租约 + 签名；返回全局唯一的配对码。
func (s *PairingService) Create(ctx context.Context, in PairCreateInput) (string, time.Duration, error) {
	in.NodeID = strings.ToLower(in.NodeID)
	node, err := s.nodes.liveNodeErr(ctx, in.NodeID)
	if err != nil {
		return "", 0, err
	}
	if err := checkTS(in.TS, s.now()); err != nil {
		return "", 0, err
	}
	if err := validatePairSecret(in.Secret); err != nil {
		return "", 0, err
	}
	payload := BuildPayload("pair-create", in.NodeID, in.Secret, fmt.Sprint(in.TS))
	if err := verifySig(nodeKey(node.ID), payload, in.Sig); err != nil {
		return "", 0, err
	}

	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	byCreator, total := 0, 0
	for _, sess := range s.sessions {
		total++
		if sess.creator == in.NodeID {
			byCreator++
		}
	}
	if byCreator >= s.cfg.MaxPerNode {
		return "", 0, fmt.Errorf("%w: 节点配对会话数达上限 %d", ErrQuotaExceeded, s.cfg.MaxPerNode)
	}
	if total >= s.cfg.MaxTotal {
		return "", 0, fmt.Errorf("%w: 全局配对会话数达上限 %d", ErrQuotaExceeded, s.cfg.MaxTotal)
	}
	code, err := s.newCodeLocked()
	if err != nil {
		return "", 0, err
	}
	s.sessions[code] = &pairSession{
		code: code, secret: in.Secret, creator: in.NodeID,
		state: pairActive, expiresAt: now.Add(s.cfg.CodeTTL),
	}
	return code, s.cfg.CodeTTL, nil
}

// Claim 敲门方以码换会话。首调占 pending 位；同 claim_id 轮询直到批准
// （一次性兑换 secret）或码过期；他人占用返回 ErrConflict。
func (s *PairingService) Claim(ctx context.Context, in PairClaimInput) (PairClaimResult, error) {
	in.NodeID = strings.ToLower(in.NodeID)
	node, err := s.nodes.liveNodeErr(ctx, in.NodeID)
	if err != nil {
		return PairClaimResult{}, err
	}
	if err := checkTS(in.TS, s.now()); err != nil {
		return PairClaimResult{}, err
	}
	if err := validatePairToken(in.ClaimID, "claim_id"); err != nil {
		return PairClaimResult{}, err
	}
	payload := BuildPayload("pair-claim", in.NodeID, in.Code, in.ClaimID, fmt.Sprint(in.TS))
	if err := verifySig(nodeKey(node.ID), payload, in.Sig); err != nil {
		return PairClaimResult{}, err
	}

	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[in.Code]
	if !ok {
		return PairClaimResult{}, fmt.Errorf("%w: 配对码不存在", ErrNotFound)
	}
	if now.After(sess.expiresAt) {
		delete(s.sessions, in.Code)
		return PairClaimResult{}, fmt.Errorf("%w: 配对码已过期", ErrNotFound)
	}
	switch sess.state {
	case pairGranted:
		if sess.claimID != in.ClaimID {
			return PairClaimResult{}, fmt.Errorf("%w: 配对码已被其他设备待确认", ErrConflict)
		}
		// 一次性兑换：secret 交付即删，无重放窗口
		delete(s.sessions, in.Code)
		return PairClaimResult{Status: "granted", Secret: sess.secret, Creator: sess.creator}, nil
	case pairClaimed:
		if sess.claimID != in.ClaimID {
			return PairClaimResult{}, fmt.Errorf("%w: 配对码已被其他设备待确认", ErrConflict)
		}
		return PairClaimResult{Status: "pending", ExpiresIn: int64(time.Until(sess.expiresAt).Seconds())}, nil
	}
	// active → 占 pending 位
	sess.claimID, sess.claimer, sess.claimerName = in.ClaimID, in.NodeID, node.Name
	sess.state = pairClaimed
	return PairClaimResult{Status: "pending", ExpiresIn: int64(time.Until(sess.expiresAt).Seconds())}, nil
}

// Approve 亮码方裁决 pending 请求。accept 挂起发放（claimant 下次轮询兑换）；
// deny 即烧码（会话出表，claimant 轮询得 404）。
func (s *PairingService) Approve(ctx context.Context, in PairApproveInput) error {
	in.NodeID = strings.ToLower(in.NodeID)
	node, err := s.nodes.liveNodeErr(ctx, in.NodeID)
	if err != nil {
		return err
	}
	if err := checkTS(in.TS, s.now()); err != nil {
		return err
	}
	if in.Decision != pairDecisionAccept && in.Decision != pairDecisionDeny {
		return fmt.Errorf("%w: decision 须为 accept|deny", ErrInvalidRequest)
	}
	in.Claimer = strings.ToLower(in.Claimer)
	payload := BuildPayload("pair-approve", in.NodeID, in.Code, in.Decision, in.Claimer, fmt.Sprint(in.TS))
	if err := verifySig(nodeKey(node.ID), payload, in.Sig); err != nil {
		return err
	}

	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[in.Code]
	if !ok {
		return fmt.Errorf("%w: 配对码不存在", ErrNotFound)
	}
	if now.After(sess.expiresAt) {
		delete(s.sessions, in.Code)
		return fmt.Errorf("%w: 配对码已过期", ErrNotFound)
	}
	if sess.creator != in.NodeID {
		return fmt.Errorf("%w: 仅亮码方可裁决", ErrUnauthorized)
	}
	if sess.state != pairClaimed || sess.claimer != in.Claimer {
		return fmt.Errorf("%w: 待确认请求已变化或不存在", ErrConflict)
	}
	if in.Decision == pairDecisionDeny {
		delete(s.sessions, in.Code) // 拒绝即烧
		return nil
	}
	sess.state = pairGranted
	return nil
}

// Requests 亮码方拉取自己活跃会话与待确认请求（顺带清过期，读路径兜底 GC）。
func (s *PairingService) Requests(ctx context.Context, in PairRequestsInput) ([]PairSessionView, error) {
	in.NodeID = strings.ToLower(in.NodeID)
	node, err := s.nodes.liveNodeErr(ctx, in.NodeID)
	if err != nil {
		return nil, err
	}
	if err := checkTS(in.TS, s.now()); err != nil {
		return nil, err
	}
	payload := BuildPayload("pair-requests", in.NodeID, fmt.Sprint(in.TS))
	if err := verifySig(nodeKey(node.ID), payload, in.Sig); err != nil {
		return nil, err
	}

	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []PairSessionView
	for code, sess := range s.sessions {
		if now.After(sess.expiresAt) {
			delete(s.sessions, code)
			continue
		}
		if sess.creator != in.NodeID {
			continue
		}
		view := PairSessionView{
			Code:      code,
			ExpiresIn: int64(time.Until(sess.expiresAt).Seconds()),
			Requests:  []PairRequestView{},
		}
		if sess.state == pairClaimed {
			view.Requests = append(view.Requests, PairRequestView{NodeID: sess.claimer, Name: sess.claimerName})
		}
		out = append(out, view)
	}
	return out, nil
}

// newCodeLocked 生成全局唯一配对码（crypto/rand 十进制；碰撞重试有界，
// 表容量有限故实际不会耗尽重试预算）。
func (s *PairingService) newCodeLocked() (string, error) {
	max := big.NewInt(int64(pow10(s.cfg.CodeLen)))
	for i := 0; i < 64; i++ {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", fmt.Errorf("生成配对码: %w", err)
		}
		code := fmt.Sprintf("%0*d", s.cfg.CodeLen, n.Int64())
		if _, taken := s.sessions[code]; !taken {
			return code, nil
		}
	}
	return "", fmt.Errorf("%w: 配对码空间耗尽", ErrQuotaExceeded)
}

func pow10(n int) int64 {
	v := int64(1)
	for i := 0; i < n; i++ {
		v *= 10
	}
	return v
}

// validatePairSecret secret 形态校验：12-128 字节、可打印 ASCII、无空白。
// 下限 12 = 客户端 GenerateCode 产物宽度（12 字符 Crockford base32 + 2 连字符）。
func validatePairSecret(secret string) error {
	if len(secret) < 12 || len(secret) > 128 {
		return fmt.Errorf("%w: secret 长度须在 12-128 字节", ErrInvalidRequest)
	}
	return validatePairToken(secret, "secret")
}

// validatePairToken 码元 token 校验：可打印 ASCII 且无空白（防头注入/日志脏化）。
func validatePairToken(tok, name string) error {
	if tok == "" || len(tok) > 128 {
		return fmt.Errorf("%w: %s 缺失或过长", ErrInvalidRequest, name)
	}
	for i := 0; i < len(tok); i++ {
		if tok[i] <= ' ' || tok[i] >= 0x7f {
			return fmt.Errorf("%w: %s 含非法字符", ErrInvalidRequest, name)
		}
	}
	return nil
}
