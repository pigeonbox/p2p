// invite.go — 名录邀请编排(2026-10-14):密封邀请经 p2pd 信箱投递。
//
// 语义:邀请 = 口令 bearer(与手工交接同信任级,通道只是递送);
// 发邀请=自愿入名录(带名录段注册,租约期内可发现);收端开箱验真以
// 名录为信任锚(发端 box_pub 经注册签名钉死归属),发端不在名录/开箱
// 失败/密文与封套身份不符一律静默跳过——信箱可被第三方抢收是已声明
// 边界(拒绝服务非泄密)。
package client

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/oekit/core/version"
	"github.com/pigeonbox/p2p/internal/registry"
)

// sendInviteLease 发邀请时的名录租约(p2pc send 是一次性进程,租约覆盖
// 收端 15min 信箱 TTL + 10min 配对窗口即可)。
const sendInviteLease = time.Hour

// mailboxInterval 缺省轮询间隔。
const mailboxInterval = 5 * time.Second

// mailboxLease watcher 注册租约(每轮心跳续租;进程死亡后名录残影
// 最长该时长)。
const mailboxLease = 10 * time.Minute

// registerPresence 带名录段注册/心跳(discoverable=false 时旧格式,
// sticky 不触碰既有名录状态)。
func (r *registryAPI) registerPresence(ctx context.Context, n *nodeIdentity, name string, ttl time.Duration, discoverable bool) error {
	boxPubHex := ""
	disc := ""
	if discoverable {
		pub, err := BoxPubHex(n.priv)
		if err != nil {
			return err
		}
		boxPubHex = pub
		disc = "1"
	}
	ver := "p2pc/" + version.Version // 与 register 同源(-ldflags 注入)
	body := map[string]any{
		"node_id": n.id, "url": "http://direct.invalid", "name": name, "version": ver,
		"caps": []string{"direct"}, "ttl_seconds": int64(ttl / time.Second),
		"nonce": "p2pc-" + fmt.Sprintf("%d", time.Now().UnixNano()), "ts": time.Now().Unix(),
	}
	payload := []string{n.id, "http://direct.invalid", name, ver, "direct",
		fmt.Sprintf("%d", int64(ttl/time.Second)), body["nonce"].(string), fmt.Sprintf("%d", body["ts"].(int64))}
	if discoverable {
		body["discoverable"] = true
		body["box_pub"] = boxPubHex
		payload = append(payload, disc, "", boxPubHex) // public_url 留空(sticky 保留既有)
	}
	body["sig"] = n.sign(registry.BuildPayload(payload...))
	return r.do(ctx, "POST", "/v1/nodes/register", body, nil)
}

// directory 在线名录。
func (r *registryAPI) directory(ctx context.Context) ([]registry.DirectoryEntry, error) {
	var out struct {
		Nodes []registry.DirectoryEntry `json:"nodes"`
	}
	if err := r.do(ctx, "GET", "/v1/directory", nil, &out); err != nil {
		return nil, err
	}
	return out.Nodes, nil
}

// mailboxPost 密封邀请投递。
func (r *registryAPI) mailboxPost(ctx context.Context, to, from, nonce, boxed string) error {
	body := map[string]any{"from": from, "nonce": nonce, "boxed": boxed}
	return r.do(ctx, "POST", "/v1/mailbox/"+to, body, nil)
}

// mailboxPop 弹出全部密封条目(取后即删)。
func (r *registryAPI) mailboxPop(ctx context.Context, to string) ([]registry.SealedEntry, error) {
	var out struct {
		Entries []registry.SealedEntry `json:"entries"`
	}
	if err := r.do(ctx, "GET", "/v1/mailbox/"+to, nil, &out); err != nil {
		return nil, err
	}
	return out.Entries, nil
}

// SendInvite 把口令以密封邀请投递到名录对端信箱。
// 步骤:自带名录段注册(自愿入名录)→ 名录取目标 box_pub → 密封 → 投递。
// 任一步失败即返回错误(调用方降级为普通发送,邀请是便利非通路)。
func SendInvite(opt Options, code, toNode, fromName, note string) error {
	if opt.Registry == "" {
		return fmt.Errorf("registry 地址必填")
	}
	// toNode 形态闸(纵深:调用方 p2px 已校验;CLI 直调路径在此兜底,
	// 防任意串进目录查找与信箱投递端点)
	if len(toNode) != 64 {
		return fmt.Errorf("目标 node_id 须为 64 字符 hex")
	}
	for i := 0; i < len(toNode); i++ {
		c := toNode[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return fmt.Errorf("目标 node_id 须为 64 字符 hex")
		}
	}
	toNode = strings.ToLower(toNode)
	if opt.NodeKeyPath == "" {
		opt.NodeKeyPath = DefaultNodeKeyPath()
	}
	id, err := newNodeIdentity(opt.NodeKeyPath)
	if err != nil {
		return err
	}
	if fromName == "" {
		fromName = "p2pc"
	}
	reg := newRegistryAPI(opt.Registry)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := reg.registerPresence(ctx, id, fromName, sendInviteLease, true); err != nil {
		return fmt.Errorf("名录注册失败: %w", err)
	}
	entries, err := reg.directory(ctx)
	if err != nil {
		return fmt.Errorf("名录查询失败: %w", err)
	}
	var targetBox *[32]byte
	for _, e := range entries {
		if e.NodeID == toNode {
			raw, derr := hex.DecodeString(e.BoxPub)
			if derr != nil || len(raw) != 32 {
				return fmt.Errorf("对端 %s… box_pub 非法", toNode[:min12(toNode)])
			}
			targetBox = new([32]byte)
			copy(targetBox[:], raw)
			break
		}
	}
	if targetBox == nil {
		return fmt.Errorf("对端 %s… 不在在线名录(未开启可被发现或离线)", toNode[:min12(toNode)])
	}
	nonceB64, boxedB64, err := SealInvite(targetBox, id.priv, InvitePayload{
		NodeID: id.id, Code: code, Name: fromName, Note: note,
	})
	if err != nil {
		return fmt.Errorf("邀请密封失败: %w", err)
	}
	if err := reg.mailboxPost(ctx, toNode, id.id, nonceB64, boxedB64); err != nil {
		return fmt.Errorf("邀请投递失败: %w", err)
	}
	return nil
}

// InviteSink 开箱成功的邀请出口(RunMailbox 回调)。
type InviteSink func(InvitePayload)

// MailboxOptions 信箱运行参数(cmd mailbox / core supervisor 共用)。
type MailboxOptions struct {
	Options
	Watch        bool          // 长驻轮询(缺省一次性弹出)
	Interval     time.Duration // 轮询间隔(Watch 时;缺省 5s)
	Discoverable bool          // 注册名录(opt-in;收邀请的前提)
	DisplayName  string        // 名录显示名(缺省 p2pc)
	// MaxCycles 轮询轮数上限(0=无限;测试钩子)。
	MaxCycles int
}

// RunMailbox 信箱取件:注册保活(按需入名录)→ 弹出全部密封条目 →
// 逐条以名录 box_pub 开箱验真 → Emit。发端不在名录/开箱失败/密文与
// 封套身份不符一律跳过(stderr 记因,绝不冒进收件)。
// Watch 时按 Interval 长驻轮询,每轮心跳续租;一次性模式弹出即返回。
func RunMailbox(opt MailboxOptions, emit InviteSink) error {
	if opt.Registry == "" {
		return fmt.Errorf("registry 地址必填")
	}
	if opt.NodeKeyPath == "" {
		opt.NodeKeyPath = DefaultNodeKeyPath()
	}
	if opt.Interval <= 0 {
		opt.Interval = mailboxInterval
	}
	id, err := newNodeIdentity(opt.NodeKeyPath)
	if err != nil {
		return err
	}
	_, boxPriv, err := BoxKeypair(id.priv)
	if err != nil {
		return err
	}
	name := opt.DisplayName
	if name == "" {
		name = "p2pc"
	}
	reg := newRegistryAPI(opt.Registry)

	for cycle := 0; ; cycle++ {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		// 注册/心跳保活(幂等 upsert;discoverable 时同时刷新名录状态)
		if err := reg.registerPresence(ctx, id, name, mailboxLease, opt.Discoverable); err != nil {
			fmt.Fprintf(os.Stderr, "⚠ 节点注册失败(下轮重试): %v\n", err)
		}
		entries, err := reg.mailboxPop(ctx, id.id)
		if err != nil {
			fmt.Fprintf(os.Stderr, "⚠ 信箱取件失败(下轮重试): %v\n", err)
		}
		cancel()
		if err == nil && len(entries) > 0 {
			emitSealedEntries(reg, id, boxPriv, entries, emit)
		}
		if !opt.Watch || (opt.MaxCycles > 0 && cycle+1 >= opt.MaxCycles) {
			return nil
		}
		time.Sleep(opt.Interval)
	}
}

// emitSealedEntries 开箱验真并出口(名录 box_pub 为信任锚)。
func emitSealedEntries(reg *registryAPI, id *nodeIdentity, boxPriv *[32]byte, entries []registry.SealedEntry, emit InviteSink) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	entries0, err := reg.directory(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "⚠ 名录查询失败,放弃本轮 %d 条邀请: %v\n", len(entries), err)
		return
	}
	boxPubs := make(map[string]*[32]byte, len(entries0))
	for _, e := range entries0 {
		if raw, err := hex.DecodeString(e.BoxPub); err == nil && len(raw) == 32 {
			var b [32]byte
			copy(b[:], raw)
			boxPubs[e.NodeID] = &b
		}
	}
	for _, en := range entries {
		senderBox, ok := boxPubs[en.From]
		if !ok {
			fmt.Fprintf(os.Stderr, "⚠ 跳过密文:发端 %s… 不在名录\n", short(en.From))
			continue
		}
		inv, err := OpenInvite(en.Nonce, en.Boxed, senderBox, boxPriv)
		if err != nil {
			fmt.Fprintf(os.Stderr, "⚠ 跳过密文: %v\n", err)
			continue
		}
		if inv.NodeID != en.From { // 密文内身份与封套交叉验真
			fmt.Fprintf(os.Stderr, "⚠ 跳过密文:身份不符(封套 %s… ≠ 密文 %s…)\n", short(en.From), short(inv.NodeID))
			continue
		}
		emit(inv)
	}
}

func short(s string) string {
	if len(s) <= 12 {
		return s
	}
	return s[:12]
}

func min12(s string) int {
	if len(s) < 12 {
		return len(s)
	}
	return 12
}

// DirectoryPeers 拉取在线名录(cmd directory 用)。
func DirectoryPeers(opt Options) ([]registry.DirectoryEntry, error) {
	if opt.Registry == "" {
		return nil, fmt.Errorf("registry 地址必填")
	}
	reg := newRegistryAPI(opt.Registry)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return reg.directory(ctx)
}
