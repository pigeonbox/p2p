// mailbox.go — 邀请信箱(2026-10-14 在线名录配套):密封邀请投递。
//
// 语义:p2pd 是纯密文搬运工——条目 {from, nonce, boxed} 的 boxed 是
// nacl/box 密文(收端公钥密封),服务端不验内容、无法解密;收端开箱验真。
// 约束:TTL 15min / 每箱 ≤10 条 / 单条密封体解码后 ≤4KB;取后即删
// (窃取信箱=拒绝服务非泄密——密文打不开即跳过);零持久化与会话/公告
// 同模型,节点租约过期即级联清除。
package registry

import (
	"encoding/base64"
	"fmt"
	"strings"
	"sync"
	"time"
)

const (
	// mailboxTTL 密封条目存活期(≥ p2pc 配对窗口 10min,留接收方轮询余量)。
	mailboxTTL = 15 * time.Minute
	// maxMailboxPerNode 单箱条目上限(防第三方无界灌箱=挤占合法邀请)。
	maxMailboxPerNode = 10
	// maxSealedBytes 密封体解码后上限(nacl/box 头 48B + 邀请负载,4KB 富余)。
	maxSealedBytes = 4 << 10
	// maxNonceChars nonce 载体上限(服务端不解释内容,只做尺寸闸)。
	maxNonceChars = 64
)

// SealedEntry 信箱条目(纯密文载体)。
type SealedEntry struct {
	From  string `json:"from"`          // 发端 node_id hex(收端据此查名录 box_pub 开箱)
	Nonce string `json:"nonce"`         // 加密 nonce 载体(对 p2pd 不透明)
	Boxed string `json:"boxed"`         // base64 密文(收端公钥密封)
	TS    int64  `json:"ts"`            // 服务端到达 unix 秒(TTL 基准)
}

// MailboxInput 投递请求体。
type MailboxInput struct {
	From  string `json:"from"`
	Nonce string `json:"nonce"`
	Boxed string `json:"boxed"`
}

// errInvalidf / errQuotaf 哨兵错误包装(server 层按 errors.Is 映射状态码)。
func errInvalidf(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidRequest, fmt.Sprintf(format, a...))
}

func errQuotaf(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrQuotaExceeded, fmt.Sprintf(format, a...))
}

// nodeMailbox 单节点信箱(内存态,Service 持有;并发安全由 mboxMu 保证)。
type nodeMailbox struct {
	mu      sync.Mutex
	boxes   map[string][]SealedEntry
	nowFunc func() time.Time
}

func (m *nodeMailbox) now() time.Time {
	if m.nowFunc != nil {
		return m.nowFunc()
	}
	return time.Now()
}

// post 校验后投递(满箱拒绝;TTL 到期即不可取)。
func (m *nodeMailbox) post(to string, in MailboxInput) error {
	if err := validateSealed(in); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.boxes == nil {
		m.boxes = make(map[string][]SealedEntry)
	}
	m.dropExpiredLocked()
	box := m.boxes[to]
	if len(box) >= maxMailboxPerNode {
		return errQuotaf("信箱已满(%d),先取件或等待过期", maxMailboxPerNode)
	}
	m.boxes[to] = append(box, SealedEntry{
		From: strings.ToLower(in.From), Nonce: in.Nonce, Boxed: in.Boxed,
		TS: m.now().Unix(),
	})
	return nil
}

// pop 弹出全部未过期条目(取后即删)。to 必须处于有效租约内——
// 节点身份消失信箱即消失(与零持久化模型一致)。
func (m *nodeMailbox) pop(to string) ([]SealedEntry, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.dropExpiredLocked()
	entries := m.boxes[to]
	delete(m.boxes, to)
	return entries, len(entries) > 0
}

// dropNode 节点租约失效时级联清除整箱(Sweep 调用)。
func (m *nodeMailbox) dropNode(nodeID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.boxes, nodeID)
}

// dropExpiredLocked 清 TTL 过期条目(调用方持 mu)。
func (m *nodeMailbox) dropExpiredLocked() {
	now := m.now()
	for id, box := range m.boxes {
		kept := box[:0]
		for _, e := range box {
			if now.Unix()-e.TS < int64(mailboxTTL/time.Second) {
				kept = append(kept, e)
			}
		}
		if len(kept) == 0 {
			delete(m.boxes, id)
		} else {
			m.boxes[id] = kept
		}
	}
}

// validateSealed 投递体尺寸与形态闸(不解释内容)。
func validateSealed(in MailboxInput) error {
	if !isHex64(strings.ToLower(in.From)) {
		return errInvalidf("from 须为 64 字符 node_id hex")
	}
	if in.Nonce == "" || len(in.Nonce) > maxNonceChars {
		return errInvalidf("nonce 缺失或超长")
	}
	raw, err := base64.StdEncoding.DecodeString(in.Boxed)
	if err != nil {
		return errInvalidf("boxed 须为 base64")
	}
	if len(raw) == 0 || len(raw) > maxSealedBytes {
		return errInvalidf("boxed 解码后须在 (0,%d] 字节", maxSealedBytes)
	}
	return nil
}
