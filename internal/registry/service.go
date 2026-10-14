package registry

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/pigeonbox/p2p/internal/store"
)

// 哨兵错误:server 层按 errors.Is 映射 HTTP 状态码。
var (
	ErrInvalidRequest = errors.New("请求非法")
	ErrUnauthorized   = errors.New("未授权")
	ErrBadSignature   = errors.New("签名校验失败")
	ErrStaleTimestamp = errors.New("时间戳过期")
	ErrNotFound       = errors.New("不存在")
	ErrConflict       = errors.New("口令已被其他节点宣告")
	ErrQuotaExceeded  = errors.New("超出配额")
)

// Params 服务参数(与 config 解耦,由装配层注入)。
type Params struct {
	Store store.Store
	// RequireToken 非空时为邀请制注册,请求须携带相同 token。
	RequireToken   string
	MinNodeTTL     time.Duration
	MaxNodeTTL     time.Duration
	MaxAnnounces   int // 单节点公告配额
	MaxAnnounceTTL time.Duration
	// MaxNodes / MaxTotalAnnounces 全局容量上限(2026-10-05 审计 P2:开放注册
	// 下无限堆节点/公告可内存耗尽;0 = 用内部默认)。
	MaxNodes          int
	MaxTotalAnnounces int
}

const (
	defaultMaxNodes          = 5000
	defaultMaxTotalAnnounces = 50000
	maxURLLen                = 2048
)

// Service 注册中心业务逻辑。并发安全(依赖 Store 的并发安全)。
type Service struct {
	p   Params
	now func() time.Time

	// nonce 去重(签名时间戳窗口内同一 (node_id,nonce) 只接受一次——
	// 2026-10-05 审计 P3:此前截获的请求可在 ±5min 窗口内重放)
	nonceMu   sync.Mutex
	nonceSeen map[string]time.Time
	nonceOps  int

	// 邀请信箱(2026-10-14:密封邀请投递,纯密文,零持久化)
	mbox nodeMailbox
}

// New 构造服务。
func New(p Params) *Service {
	s := &Service{p: p, now: time.Now}
	s.mbox.nowFunc = func() time.Time { return s.now() } // 经闭包转发,测试可整体拨钟
	return s
}

// MailboxPost 密封邀请投递(目标须处于有效租约内)。
func (s *Service) MailboxPost(ctx context.Context, toNode string, in MailboxInput) error {
	toNode = strings.ToLower(toNode)
	if _, err := s.liveNodeErr(ctx, toNode); err != nil {
		return err
	}
	return s.mbox.post(toNode, in)
}

// MailboxPop 弹出全部密封条目(取后即删;目标须处于有效租约内)。
func (s *Service) MailboxPop(ctx context.Context, toNode string) ([]SealedEntry, error) {
	toNode = strings.ToLower(toNode)
	if _, err := s.liveNodeErr(ctx, toNode); err != nil {
		return nil, err
	}
	entries, _ := s.mbox.pop(toNode)
	return entries, nil
}

// RegisterInput 注册/心跳请求。node_id 即公钥,sig 对 BuildPayload(
// node_id,url,name,version,caps,ttl_seconds,nonce,ts) 的 Ed25519 签名。
// 名录扩展段(Discoverable/PublicURL/BoxPub)任一出现时,sig 改对扩展负载
// BuildPayload(旧八字段,discoverable(1/0),public_url,box_pub)——双格式
// 向后兼容:旧客户端不带=不可发现。缺省(未出现)字段注册时 sticky 保留
// 既有名录状态(federation 心跳/p2pc 直传注册与名录注册共写同一 node_id,
// 非显式字段不得互踩)。
type RegisterInput struct {
	NodeID     string   `json:"node_id"`
	URL        string   `json:"url"`
	Name       string   `json:"name"`
	Version    string   `json:"version"`
	Caps       []string `json:"caps"`
	TTLSeconds int64    `json:"ttl_seconds"`
	Nonce      string   `json:"nonce"`
	TS         int64    `json:"ts"`
	Sig        string   `json:"sig"`
	Token      string   `json:"token,omitempty"`
	// Discoverable nil=未携带(sticky);指针以区分「不带」与「显式 false」。
	Discoverable *bool  `json:"discoverable,omitempty"`
	PublicURL    string `json:"public_url,omitempty"`
	BoxPub       string `json:"box_pub,omitempty"`
}

// AnnounceInput 公告请求。sig 覆盖 BuildPayload(
// node_id,code_hash,expires_at,size_hint,ts)。
type AnnounceInput struct {
	NodeID    string `json:"node_id"`
	CodeHash  string `json:"code_hash"`
	ExpiresAt int64  `json:"expires_at"` // unix 秒
	SizeHint  int64  `json:"size_hint"`
	TS        int64  `json:"ts"`
	Sig       string `json:"sig"`
}

// RevokeInput 撤销公告/注销节点请求。
// 撤销公告 sig 覆盖 BuildPayload(node_id,code_hash,ts);
// 注销节点 sig 覆盖 BuildPayload(node_id,ts)。
type RevokeInput struct {
	NodeID   string `json:"node_id"`
	CodeHash string `json:"code_hash,omitempty"`
	TS       int64  `json:"ts"`
	Sig      string `json:"sig"`
}

const (
	maxNameLen    = 64
	maxVersionLen = 32
	maxCaps       = 16
	maxCapLen     = 32
	maxNonceLen   = 64
)

// RegisterNode 注册或续租节点(register 与 heartbeat 同语义,幂等 upsert)。
func (s *Service) RegisterNode(ctx context.Context, in RegisterInput, ip string) (store.Node, error) {
	// 恒时比较（2026-10-05 审计：普通 == 比较留时序侧信道；写路径限流已有，
	// 此处补齐防爆破语义。2026-10-09 追加：双侧先 SHA-256 定长化再比,消除
	// ConstantTimeCompare 对不等长输入的长度泄露）
	if s.p.RequireToken != "" {
		ta := sha256.Sum256([]byte(in.Token))
		tb := sha256.Sum256([]byte(s.p.RequireToken))
		if subtle.ConstantTimeCompare(ta[:], tb[:]) != 1 {
			return store.Node{}, fmt.Errorf("%w: registration token 不匹配", ErrUnauthorized)
		}
	}
	// node_id 归一化小写(2026-10-05 审计 P3:hex 大小写变体可绕过按字符串
	// 计数的配额;合法客户端 hex.EncodeToString 恒小写,归一不影响签名——
	// 载荷随归一化后的 ID 构造,大写变体的签名自然失效)
	in.NodeID = strings.ToLower(in.NodeID)
	pub, err := parseNodeID(in.NodeID)
	if err != nil {
		return store.Node{}, fmt.Errorf("%w: %v", ErrInvalidRequest, err)
	}
	ttl := time.Duration(in.TTLSeconds) * time.Second
	if ttl < s.p.MinNodeTTL || ttl > s.p.MaxNodeTTL {
		return store.Node{}, fmt.Errorf("%w: ttl_seconds 须在 [%d,%d] 秒",
			ErrInvalidRequest, int64(s.p.MinNodeTTL/time.Second), int64(s.p.MaxNodeTTL/time.Second))
	}
	if in.Nonce == "" || len(in.Nonce) > maxNonceLen {
		return store.Node{}, fmt.Errorf("%w: nonce 缺失或过长", ErrInvalidRequest)
	}
	if err := checkTS(in.TS, s.now()); err != nil {
		return store.Node{}, err
	}
	if err := validNodeURL(in.URL); err != nil {
		return store.Node{}, fmt.Errorf("%w: %v", ErrInvalidRequest, err)
	}
	name, version, caps, err := sanitizeMeta(in.Name, in.Version, in.Caps)
	if err != nil {
		return store.Node{}, fmt.Errorf("%w: %v", ErrInvalidRequest, err)
	}
	// 名录扩展段:任一出现即验扩展负载(旧签名拒绝),字段本身先行校验。
	presence, err := validatePresence(in)
	if err != nil {
		return store.Node{}, fmt.Errorf("%w: %v", ErrInvalidRequest, err)
	}
	payload := BuildPayload(in.NodeID, in.URL, in.Name, in.Version,
		strings.Join(in.Caps, ","), fmt.Sprint(in.TTLSeconds), in.Nonce, fmt.Sprint(in.TS))
	if presence.extended {
		disc := "0"
		if presence.discoverable {
			disc = "1"
		}
		payload = BuildPayload(string(payload), disc, presence.publicURL, presence.boxPub)
	}
	if err := verifySig(pub, payload, in.Sig); err != nil {
		return store.Node{}, err
	}

	// nonce 去重(签名校验通过后标记,不因攻击者伪造 nonce 提前占位)
	if !s.markNonce(in.NodeID, in.Nonce, s.now()) {
		return store.Node{}, fmt.Errorf("%w: nonce 重放", ErrInvalidRequest)
	}

	// 全局节点容量上限(已注册节点续租不受限)
	maxNodes := s.p.MaxNodes
	if maxNodes <= 0 {
		maxNodes = defaultMaxNodes
	}
	if _, ok, gerr := s.p.Store.GetNode(ctx, in.NodeID); gerr == nil && !ok {
		if live, cerr := s.countLiveNodes(ctx); cerr == nil && live >= maxNodes {
			return store.Node{}, fmt.Errorf("%w: 全局节点数达上限 %d", ErrQuotaExceeded, maxNodes)
		}
	}

	now := s.now()
	n := store.Node{
		ID: in.NodeID, URL: in.URL, Name: name, Version: version, Caps: caps,
		IP: ip, RegisteredAt: now, ExpiresAt: now.Add(ttl),
	}
	// 名录段 sticky:未携带扩展字段的注册(federation 心跳/p2pc 直传等旧格式
	// 客户端)不触碰既有名录状态;显式携带才覆写。
	if prev, ok, gerr := s.p.Store.GetNode(ctx, in.NodeID); gerr == nil && ok {
		if in.Discoverable == nil {
			n.Discoverable = prev.Discoverable
		} else {
			n.Discoverable = presence.discoverable
		}
		if in.PublicURL == "" {
			n.PublicURL = prev.PublicURL
		} else {
			n.PublicURL = presence.publicURL
		}
		if in.BoxPub == "" {
			n.BoxPub = prev.BoxPub
		} else {
			n.BoxPub = presence.boxPub
		}
	} else if in.Discoverable != nil {
		n.Discoverable = presence.discoverable
		n.PublicURL = presence.publicURL
		n.BoxPub = presence.boxPub
	}
	if err := s.p.Store.UpsertNode(ctx, n); err != nil {
		return store.Node{}, fmt.Errorf("存储节点: %w", err)
	}
	return n, nil
}

// markNonce 记录并检查 (node_id,nonce) 是否首次出现;窗口 2×时钟偏移。
func (s *Service) markNonce(nodeID, nonce string, now time.Time) bool {
	const rememberWindow = 2 * MaxClockSkew
	s.nonceMu.Lock()
	defer s.nonceMu.Unlock()
	if s.nonceSeen == nil {
		s.nonceSeen = make(map[string]time.Time, 1024)
	}
	s.nonceOps++
	if s.nonceOps%4096 == 0 { // 周期清理过期项,防无界增长
		for k, at := range s.nonceSeen {
			if now.Sub(at) > rememberWindow {
				delete(s.nonceSeen, k)
			}
		}
	}
	key := nodeID + "|" + nonce
	if at, ok := s.nonceSeen[key]; ok && now.Sub(at) <= rememberWindow {
		return false
	}
	s.nonceSeen[key] = now
	return true
}

// countLiveNodes 未过期节点数(容量上限判定用)。
func (s *Service) countLiveNodes(ctx context.Context) (int, error) {
	list, err := s.p.Store.ListNodes(ctx)
	if err != nil {
		return 0, err
	}
	now := s.now()
	live := 0
	for _, n := range list {
		if !n.Expired(now) {
			live++
		}
	}
	return live, nil
}

// countLiveAnnounces 未过期公告数。
func (s *Service) countLiveAnnounces(ctx context.Context) (int, error) {
	list, err := s.p.Store.ListAnnounces(ctx)
	if err != nil {
		return 0, err
	}
	now := s.now()
	live := 0
	for _, a := range list {
		if !a.Expired(now) {
			live++
		}
	}
	return live, nil
}

// Announce 宣告口令路由。要求节点处于有效租约内;
// 同一 code_hash 已被其他未过期节点占有时返回 ErrConflict(先到先得)。
func (s *Service) Announce(ctx context.Context, in AnnounceInput) (store.Announce, error) {
	in.NodeID = strings.ToLower(in.NodeID)
	node, err := s.liveNode(ctx, in.NodeID)
	if err != nil {
		return store.Announce{}, err
	}
	hash := strings.ToLower(in.CodeHash)
	if !isHex64(hash) {
		return store.Announce{}, fmt.Errorf("%w: code_hash 须为 sha256 hex(64 字符)", ErrInvalidRequest)
	}
	if err := checkTS(in.TS, s.now()); err != nil {
		return store.Announce{}, err
	}
	if in.SizeHint < 0 {
		return store.Announce{}, fmt.Errorf("%w: size_hint 非法", ErrInvalidRequest)
	}
	now := s.now()
	expiresAt := time.Unix(in.ExpiresAt, 0)
	if expiresAt.Before(now.Add(time.Minute)) || expiresAt.After(now.Add(s.p.MaxAnnounceTTL)) {
		return store.Announce{}, fmt.Errorf("%w: expires_at 须在 (%s,%s] 内", ErrInvalidRequest,
			now.Add(time.Minute).Format(time.RFC3339), now.Add(s.p.MaxAnnounceTTL).Format(time.RFC3339))
	}
	payload := BuildPayload(in.NodeID, in.CodeHash, fmt.Sprint(in.ExpiresAt), fmt.Sprint(in.SizeHint), fmt.Sprint(in.TS))
	if err := verifySig(nodeKey(node.ID), payload, in.Sig); err != nil {
		return store.Announce{}, err
	}

	existing, ok, err := s.p.Store.GetAnnounce(ctx, hash)
	if err != nil {
		return store.Announce{}, fmt.Errorf("读公告: %w", err)
	}
	isUpdate := ok && existing.NodeID == in.NodeID
	if ok && !isUpdate && !existing.Expired(now) {
		return store.Announce{}, fmt.Errorf("%w: %s… 已由节点 %s… 宣告", ErrConflict, hash[:12], existing.NodeID[:12])
	}
	if !isUpdate {
		cnt, err := s.p.Store.CountAnnouncesByNode(ctx, in.NodeID)
		if err != nil {
			return store.Announce{}, fmt.Errorf("读配额: %w", err)
		}
		if cnt >= s.p.MaxAnnounces {
			return store.Announce{}, fmt.Errorf("%w: 节点公告数达上限 %d", ErrQuotaExceeded, s.p.MaxAnnounces)
		}
		maxTotal := s.p.MaxTotalAnnounces
		if maxTotal <= 0 {
			maxTotal = defaultMaxTotalAnnounces
		}
		if live, cerr := s.countLiveAnnounces(ctx); cerr == nil && live >= maxTotal {
			return store.Announce{}, fmt.Errorf("%w: 全局公告数达上限 %d", ErrQuotaExceeded, maxTotal)
		}
	}
	a := store.Announce{
		CodeHash: hash, NodeID: in.NodeID, ExpiresAt: expiresAt,
		SizeHint: in.SizeHint, CreatedAt: now,
	}
	if isUpdate {
		a.CreatedAt = existing.CreatedAt
	}
	if err := s.p.Store.PutAnnounce(ctx, a); err != nil {
		return store.Announce{}, fmt.Errorf("存公告: %w", err)
	}
	return a, nil
}

// Resolve 解析口令路由。公告或其节点任一过期即视为不存在
// (读路径即时判定,清扫滞后不影响正确性)。
func (s *Service) Resolve(ctx context.Context, codeHash string) (store.Announce, store.Node, error) {
	hash := strings.ToLower(strings.TrimSpace(codeHash))
	a, ok, err := s.p.Store.GetAnnounce(ctx, hash)
	if err != nil {
		return store.Announce{}, store.Node{}, fmt.Errorf("读公告: %w", err)
	}
	now := s.now()
	if !ok || a.Expired(now) {
		return store.Announce{}, store.Node{}, fmt.Errorf("%w: 该口令未接入联邦", ErrNotFound)
	}
	node, err := s.liveNode(ctx, a.NodeID)
	if err != nil {
		return store.Announce{}, store.Node{}, ErrNotFound
	}
	return a, node, nil
}

// RevokeAnnounce 撤销口令公告,仅宣告节点本身可撤。
// 全部校验通过后才删除,避免先删后验。
func (s *Service) RevokeAnnounce(ctx context.Context, in RevokeInput) error {
	in.NodeID = strings.ToLower(in.NodeID)
	node, err := s.liveNode(ctx, in.NodeID)
	if err != nil {
		return err
	}
	hash := strings.ToLower(in.CodeHash)
	if !isHex64(hash) {
		return fmt.Errorf("%w: code_hash 非法", ErrInvalidRequest)
	}
	if err := checkTS(in.TS, s.now()); err != nil {
		return err
	}
	a, ok, err := s.p.Store.GetAnnounce(ctx, hash)
	if err != nil {
		return fmt.Errorf("读公告: %w", err)
	}
	if !ok {
		return fmt.Errorf("%w: 公告不存在", ErrNotFound)
	}
	if a.NodeID != in.NodeID {
		return fmt.Errorf("%w: 仅宣告节点可撤销", ErrUnauthorized)
	}
	payload := BuildPayload(in.NodeID, in.CodeHash, fmt.Sprint(in.TS))
	if err := verifySig(nodeKey(node.ID), payload, in.Sig); err != nil {
		return err
	}
	if _, err := s.p.Store.DeleteAnnounce(ctx, hash); err != nil {
		return fmt.Errorf("删公告: %w", err)
	}
	return nil
}

// DeregisterNode 注销节点并级联清除其公告,仅节点私钥持有者可调。
func (s *Service) DeregisterNode(ctx context.Context, in RevokeInput) error {
	in.NodeID = strings.ToLower(in.NodeID)
	node, err := s.liveNode(ctx, in.NodeID)
	if err != nil {
		return err
	}
	if err := checkTS(in.TS, s.now()); err != nil {
		return err
	}
	payload := BuildPayload(in.NodeID, fmt.Sprint(in.TS))
	if err := verifySig(nodeKey(node.ID), payload, in.Sig); err != nil {
		return err
	}
	if _, err := s.p.Store.DeleteNode(ctx, in.NodeID); err != nil {
		return fmt.Errorf("删节点: %w", err)
	}
	if _, err := s.p.Store.DeleteAnnouncesByNode(ctx, in.NodeID); err != nil {
		return fmt.Errorf("级联删公告: %w", err)
	}
	return nil
}

// Sweep 物理回收过期租约与公告,返回回收数量(供日志/指标)。
// 过期节点的公告与信箱一并级联清除。
func (s *Service) Sweep(ctx context.Context) (nodes, announces int) {
	now := s.now()
	nodeList, err := s.p.Store.ListNodes(ctx)
	if err == nil {
		for _, n := range nodeList {
			if n.Expired(now) {
				if _, derr := s.p.Store.DeleteNode(ctx, n.ID); derr == nil {
					// 单条级联失败可忽略,下轮清扫兜底
					_, _ = s.p.Store.DeleteAnnouncesByNode(ctx, n.ID)
					s.mbox.dropNode(n.ID) // 信箱随节点租约级联清除
					nodes++
				}
			}
		}
	}
	announceList, err := s.p.Store.ListAnnounces(ctx)
	if err == nil {
		for _, a := range announceList {
			if a.Expired(now) {
				if _, derr := s.p.Store.DeleteAnnounce(ctx, a.CodeHash); derr == nil {
					announces++
				}
			}
		}
	}
	return nodes, announces
}

// Stats 管理端统计(只计未过期)。
func (s *Service) Stats(ctx context.Context) (nodes, announces int, err error) {
	now := s.now()
	nodeList, err := s.p.Store.ListNodes(ctx)
	if err != nil {
		return 0, 0, fmt.Errorf("列节点: %w", err)
	}
	announceList, err := s.p.Store.ListAnnounces(ctx)
	if err != nil {
		return 0, 0, fmt.Errorf("列公告: %w", err)
	}
	for _, n := range nodeList {
		if !n.Expired(now) {
			nodes++
		}
	}
	for _, a := range announceList {
		if !a.Expired(now) {
			announces++
		}
	}
	return nodes, announces, nil
}

// ListNodes 管理端列出全部节点(含已过期,便于排障)。
func (s *Service) ListNodes(ctx context.Context) ([]store.Node, error) {
	return s.p.Store.ListNodes(ctx)
}

// ListAnnounces 管理端列出全部公告。
func (s *Service) ListAnnounces(ctx context.Context) ([]store.Announce, error) {
	return s.p.Store.ListAnnounces(ctx)
}

// GetNode 查询处于有效租约内的节点公开信息。
func (s *Service) GetNode(ctx context.Context, id string) (store.Node, error) {
	return s.liveNode(ctx, id)
}

// AdminDeleteNode 管理员强制下线节点并级联清公告(滥用治理)。
func (s *Service) AdminDeleteNode(ctx context.Context, id string) error {
	if _, err := s.liveNodeErr(ctx, id); err != nil {
		return err
	}
	if _, err := s.p.Store.DeleteNode(ctx, id); err != nil {
		return fmt.Errorf("删节点: %w", err)
	}
	_, err := s.p.Store.DeleteAnnouncesByNode(ctx, id)
	return err
}

// liveNode 取处于有效租约内的节点。
func (s *Service) liveNode(ctx context.Context, id string) (store.Node, error) {
	return s.liveNodeErr(ctx, id)
}

func (s *Service) liveNodeErr(ctx context.Context, id string) (store.Node, error) {
	n, ok, err := s.p.Store.GetNode(ctx, id)
	if err != nil {
		return store.Node{}, fmt.Errorf("读节点: %w", err)
	}
	if !ok || n.Expired(s.now()) {
		return store.Node{}, fmt.Errorf("%w: 节点未注册或租约已过期", ErrNotFound)
	}
	return n, nil
}

func validNodeURL(raw string) error {
	if len(raw) > maxURLLen {
		return fmt.Errorf("url 超长(>%d)", maxURLLen)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("url 解析失败: %v", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("url scheme 须为 http/https")
	}
	if u.Host == "" {
		return fmt.Errorf("url 缺少 host")
	}
	return nil
}

func sanitizeMeta(name, version string, caps []string) (string, string, []string, error) {
	if len(name) > maxNameLen {
		return "", "", nil, fmt.Errorf("name 超长(>%d)", maxNameLen)
	}
	if len(version) > maxVersionLen {
		return "", "", nil, fmt.Errorf("version 超长(>%d)", maxVersionLen)
	}
	if len(caps) > maxCaps {
		return "", "", nil, fmt.Errorf("caps 超过 %d 项", maxCaps)
	}
	for _, c := range caps {
		if c == "" || len(c) > maxCapLen {
			return "", "", nil, fmt.Errorf("caps 项非法: %q", c)
		}
	}
	if caps == nil {
		caps = []string{}
	}
	return name, version, caps, nil
}
