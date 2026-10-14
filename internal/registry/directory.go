// directory.go — 在线名录(presence directory,2026-10-14 邀请信箱配套)。
//
// 语义:名录是「实例名录」不是「房间列表」——只含 opt-in 节点的
// node_id/显示名/对外基址/密封公钥/上线时刻,绝无口令与房间信息
// (口令即授权模型不破)。opt-in 经注册扩展字段 Discoverable 携带,
// 服务端双格式签名验证(扩展负载/旧负载),缺省不可发现。
package registry

import (
	"context"
	"encoding/hex"
	"fmt"
)

// maxBoxPubLen box_pub 上限(32 字节 hex = 64 字符)。
const maxBoxPubLen = 64

// DirectoryEntry 名录条目(仅公开信息,零敏感)。
type DirectoryEntry struct {
	NodeID      string `json:"node_id"`
	Name        string `json:"name"`
	URL         string `json:"url"`          // PublicURL(对外基址,NAT 后可为空)
	BoxPub      string `json:"box_pub"`      // X25519 密封公钥 hex(邀请密封目标)
	OnlineSince int64  `json:"online_since"` // 租约起始 unix 秒
}

// Directory 列出 discoverable 且未过期节点(读路径即时判定过期,与租约语义一致)。
func (s *Service) Directory(ctx context.Context) ([]DirectoryEntry, error) {
	nodes, err := s.p.Store.ListNodes(ctx)
	if err != nil {
		return nil, fmt.Errorf("列节点: %w", err)
	}
	now := s.now()
	out := make([]DirectoryEntry, 0, len(nodes))
	for _, n := range nodes {
		if !n.Discoverable || n.Expired(now) {
			continue
		}
		out = append(out, DirectoryEntry{
			NodeID:      n.ID,
			Name:        n.Name,
			URL:         n.PublicURL,
			BoxPub:      n.BoxPub,
			OnlineSince: n.RegisteredAt.Unix(),
		})
	}
	return out, nil
}

// presenceCtx 名录扩展段校验结果。
type presenceCtx struct {
	extended     bool // 请求携带任一扩展字段(须扩展签名)
	discoverable bool
	publicURL    string
	boxPub       string
}

// validatePresence 校验名录扩展字段并判定签名格式。
// 规则:Discoverable 显式 true 时必须携带合法 box_pub(名录条目必须可被
// 密封邀请);public_url 非空时须为 http/https;box_pub 非空时须为 32 字节 hex。
func validatePresence(in RegisterInput) (presenceCtx, error) {
	p := presenceCtx{extended: in.Discoverable != nil || in.PublicURL != "" || in.BoxPub != ""}
	if !p.extended {
		return p, nil
	}
	if in.Discoverable != nil {
		p.discoverable = *in.Discoverable
	}
	p.publicURL = in.PublicURL
	p.boxPub = in.BoxPub
	if in.PublicURL != "" {
		if err := validNodeURL(in.PublicURL); err != nil {
			return p, fmt.Errorf("public_url 非法: %v", err)
		}
	}
	if in.BoxPub != "" {
		if err := validBoxPub(in.BoxPub); err != nil {
			return p, err
		}
	}
	if p.discoverable && in.BoxPub == "" {
		return p, fmt.Errorf("discoverable 须携带 box_pub(名录条目必须可被密封)")
	}
	return p, nil
}

// validBoxPub box_pub 须为 32 字节 hex(X25519 公钥)。
func validBoxPub(s string) error {
	if len(s) > maxBoxPubLen {
		return fmt.Errorf("box_pub 超长(>%d)", maxBoxPubLen)
	}
	raw, err := hex.DecodeString(s)
	if err != nil || len(raw) != 32 {
		return fmt.Errorf("box_pub 须为 32 字节 hex")
	}
	return nil
}
