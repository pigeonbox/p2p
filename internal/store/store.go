// Package store 定义 p2p 注册中心的存储抽象。
//
// 注册中心是有状态服务里状态最薄的一层:节点租约 + 口令公告,
// 全部带 TTL 到期即清。M1 提供 memory 实现;bbolt(重启存活)/
// redis(多实例)为预留扩展点——节点侧断线会自动重注册,存储重启丢失可自愈。
package store

import (
	"context"
	"time"
)

// Node 已注册节点的租约信息。node_id 即 Ed25519 公钥 hex,
// 后续所有该节点的写操作都必须持对应私钥签名,身份绑定天然成立。
type Node struct {
	ID           string    `json:"node_id"`
	URL          string    `json:"url"` // 对外可达基址,如 https://fcb.example.com
	Name         string    `json:"name"`
	Version      string    `json:"version"`
	Caps         []string  `json:"caps"` // 能力位,如 direct / download;M3 起有语义
	IP           string    `json:"ip"`   // 注册来源 IP(管理端滥用治理用)
	RegisteredAt time.Time `json:"registered_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	// 名录(presence directory)扩展段(2026-10-14 在线名录+邀请信箱):
	// Discoverable opt-in 可发现;PublicURL 名录展示的对外基址(与 url 独立
	// ——p2pc 直传注册的 url 是占位符);BoxPub X25519 密封公钥 hex(nacl/box,
	// 自 Ed25519 seed 推导)。缺省 false/空:旧格式续租不触碰(sticky,防
	// federation 心跳与 p2pc 直传注册对同一 node_id 的 upsert 互踩)。
	Discoverable bool   `json:"discoverable"`
	PublicURL    string `json:"public_url,omitempty"`
	BoxPub       string `json:"box_pub,omitempty"`
}

// Announce 一条口令公告: code_hash → 源节点。
// code_hash = SHA-256(口令) hex,注册中心不接触明文口令;
// 离线枚举防线在宣布客户端的熵门槛(≥40bit),见 README 安全模型。
type Announce struct {
	CodeHash  string    `json:"code_hash"`
	NodeID    string    `json:"node_id"`
	ExpiresAt time.Time `json:"expires_at"`
	SizeHint  int64     `json:"size_hint"`
	CreatedAt time.Time `json:"created_at"`
}

// Expired 读路径即时判定,不依赖清扫时机(清扫只是回收内存)。
func (n Node) Expired(now time.Time) bool { return !n.ExpiresAt.After(now) }

// Expired 同上。
func (a Announce) Expired(now time.Time) bool { return !a.ExpiresAt.After(now) }

// Store 存储抽象。实现必须并发安全。
type Store interface {
	UpsertNode(ctx context.Context, n Node) error
	GetNode(ctx context.Context, id string) (Node, bool, error)
	DeleteNode(ctx context.Context, id string) (bool, error)
	ListNodes(ctx context.Context) ([]Node, error)

	PutAnnounce(ctx context.Context, a Announce) error
	GetAnnounce(ctx context.Context, codeHash string) (Announce, bool, error)
	DeleteAnnounce(ctx context.Context, codeHash string) (bool, error)
	// DeleteAnnouncesByNode 级联清除某节点的全部公告(节点注销/租约过期时调用)。
	DeleteAnnouncesByNode(ctx context.Context, nodeID string) (int64, error)
	CountAnnouncesByNode(ctx context.Context, nodeID string) (int, error)
	ListAnnounces(ctx context.Context) ([]Announce, error)
}
