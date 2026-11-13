// Package registry 实现注册中心业务逻辑:节点租约、口令公告、解析。
//
// 身份模型: node_id = Ed25519 公钥 hex(64 字符)。节点的所有写操作
// (注册/心跳/注销/公告/撤销)都必须携带对规范化负载的 Ed25519 签名,
// 公钥即从 node_id 推导——"首次注册钉死身份"由该绑定天然保证。
package registry

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// MaxClockSkew 签名时间戳允许的最大偏移。
const MaxClockSkew = 5 * time.Minute

// 签名负载格式:字段按下列顺序以 "\n" 连接,再做 Ed25519 签名,
// 签名值取 base64(std)。客户端实现必须与此逐字节一致(见 README):
//
//	注册/心跳:   node_id | url | name | version | caps | ttl_seconds | nonce | ts
//	公告:        node_id | code_hash | expires_at | size_hint | ts
//	注销节点:    node_id | ts
//	撤销公告:    node_id | code_hash | ts
//
// caps 为逗号连接;缺省字段以空字符串占位。

// BuildPayload 按 README 约定构造规范化签名字节。
func BuildPayload(parts ...string) []byte {
	return []byte(strings.Join(parts, "\n"))
}

// CodeHash 口令 → SHA-256 hex(小写)。注册中心不接触明文口令,
// 该函数供宣布客户端与测试复用。
func CodeHash(code string) string {
	sum := sha256.Sum256([]byte(code))
	return hex.EncodeToString(sum[:])
}

// NormalizeHash code_hash 归一(小写 + 去首尾空白)。
//
// 这是 code_hash 的**唯一归一入口**:业务查找(registry.Service.Resolve)与
// 服务端 per-hash 限流键(internal/server handleResolve)必须共用本函数——
// 两处口径一旦分叉,空白变体就能各自折成新键,绕过「IP 池绕不过」的枚举
// 限流(p2p#37)。新增消费方一律调这里,勿自抄第二份。
func NormalizeHash(codeHash string) string {
	return strings.ToLower(strings.TrimSpace(codeHash))
}

// parseNodeID node_id hex → Ed25519 公钥。
func parseNodeID(id string) (ed25519.PublicKey, error) {
	raw, err := hex.DecodeString(id)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("node_id 须为 %d 字节公钥的 hex", ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

// verifySig 校验 base64(std) 签名。
func verifySig(pub ed25519.PublicKey, payload []byte, sigB64 string) error {
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return ErrBadSignature
	}
	if !ed25519.Verify(pub, payload, sig) {
		return ErrBadSignature
	}
	return nil
}

// checkTS 签名时间戳防重放窗口。
func checkTS(ts int64, now time.Time) error {
	drift := now.Unix() - ts
	if drift < 0 {
		drift = -drift
	}
	if drift > int64(MaxClockSkew/time.Second) {
		return fmt.Errorf("%w: ts 偏移超过 %s", ErrStaleTimestamp, MaxClockSkew)
	}
	return nil
}

func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// ---- 导出包装：信令等子包复用同一套身份/签名/时间戳约定，避免各处自抄 ----

// ParseNodeID 导出节点身份解析：node_id hex → Ed25519 公钥。
func ParseNodeID(id string) (ed25519.PublicKey, error) { return parseNodeID(id) }

// VerifySignature 导出签名校验（base64 std，Ed25519）。
func VerifySignature(pub ed25519.PublicKey, payload []byte, sigB64 string) error {
	return verifySig(pub, payload, sigB64)
}

// CheckTimestamp 导出时间戳防重放窗口校验（±MaxClockSkew）。
func CheckTimestamp(ts int64, now time.Time) error { return checkTS(ts, now) }

// nodeKey 从 node_id 还原公钥。只用于已通过注册校验的节点记录,
// 解析失败时返回 nil,verifySig 会自然拒绝。
func nodeKey(id string) ed25519.PublicKey {
	pub, err := parseNodeID(id)
	if err != nil {
		return nil
	}
	return pub
}
