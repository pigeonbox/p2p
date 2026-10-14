// sealed.go — 邀请密封原语(2026-10-14 在线名录+邀请信箱配套)。
//
// 密钥模型:节点身份是 Ed25519(node_id 即公钥);nacl/box 需要 X25519。
// x/crypto 无远端 Ed25519→X25519 公钥转换 API(需 edwards→montgomery 点
// 运算,未导出),故双端各自从**本端私钥 seed** 推导 box 密钥对
// (sha512(seed)[:32] 后 clamp → X25519 basepoint),并把 box 公钥经注册
// 扩展字段(box_pub)发布进名录——发端密封用目标在名录公布的 box_pub,
// 收端开箱用名录公布的发端 box_pub,目录即信任锚(注册签名钉死归属)。
package client

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

// BoxKeypair 从 Ed25519 私钥确定性推导 X25519 密封密钥对。
// 同一节点密钥恒得同一 box 公钥(双端各推各的,名录负责发布)。
func BoxKeypair(priv ed25519.PrivateKey) (boxPub, boxPriv *[32]byte, err error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, nil, fmt.Errorf("节点私钥尺寸非法(%d)", len(priv))
	}
	h := sha512.Sum512(priv.Seed())
	var k [32]byte
	copy(k[:], h[:32])
	k[0] &= 248 // RFC 7748 clamp(确定性,双端推导结果一致的前提)
	k[31] &= 127
	k[31] |= 64
	pub, err := curve25519.X25519(k[:], curve25519.Basepoint)
	if err != nil {
		return nil, nil, fmt.Errorf("X25519 推导: %w", err)
	}
	var pub32 [32]byte
	copy(pub32[:], pub)
	priv32 := k
	return &pub32, &priv32, nil
}

// BoxPubHex 节点密封公钥 hex(注册名录扩展字段用)。
func BoxPubHex(priv ed25519.PrivateKey) (string, error) {
	pub, _, err := BoxKeypair(priv)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(pub[:]), nil
}

// InvitePayload 密封邀请明文。NodeID 入密文供收端开箱后与信箱封套
// from 交叉验真(封套字段可被第三方篡改,密文内字段不可)。
type InvitePayload struct {
	NodeID string `json:"node_id"`        // 发端 node_id(hex)
	Code   string `json:"code"`           // 口令(与手工交接同信任级)
	Name   string `json:"name,omitempty"` // 发端显示名
	Note   string `json:"note,omitempty"` // 附言
}

// SealInvite 密封邀请(收端名录 box_pub 密封;p2pd 全程只见密文)。
// 返回 (nonceB64, boxedB64) 即信箱投递体的 nonce/boxed 字段。
func SealInvite(toBoxPub *[32]byte, priv ed25519.PrivateKey, inv InvitePayload) (string, string, error) {
	if toBoxPub == nil {
		return "", "", fmt.Errorf("目标 box_pub 缺失")
	}
	_, boxPriv, err := BoxKeypair(priv)
	if err != nil {
		return "", "", err
	}
	plaintext, err := json.Marshal(inv)
	if err != nil {
		return "", "", err
	}
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", "", err
	}
	boxed := box.Seal(nil, plaintext, &nonce, toBoxPub, boxPriv)
	return base64.StdEncoding.EncodeToString(nonce[:]),
		base64.StdEncoding.EncodeToString(boxed), nil
}

// OpenInvite 开箱验真。senderBoxPub 来自名录(信任锚),密文非该公钥
// 对应私钥所封即失败——第三方伪造/篡改在此被拒。
func OpenInvite(nonceB64, boxedB64 string, senderBoxPub, myBoxPriv *[32]byte) (InvitePayload, error) {
	var inv InvitePayload
	nonceRaw, err := base64.StdEncoding.DecodeString(nonceB64)
	if err != nil || len(nonceRaw) != 24 {
		return inv, fmt.Errorf("nonce 非法")
	}
	boxed, err := base64.StdEncoding.DecodeString(boxedB64)
	if err != nil || len(boxed) < box.Overhead {
		return inv, fmt.Errorf("密封体非法")
	}
	var nonce [24]byte
	copy(nonce[:], nonceRaw)
	plaintext, ok := box.Open(nil, boxed, &nonce, senderBoxPub, myBoxPriv)
	if !ok {
		return inv, fmt.Errorf("开箱失败(密文非本节点或发端身份不符)")
	}
	if err := json.Unmarshal(plaintext, &inv); err != nil {
		return inv, fmt.Errorf("邀请负载解析失败: %w", err)
	}
	return inv, nil
}
