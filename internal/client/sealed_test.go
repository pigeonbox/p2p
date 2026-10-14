package client

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

// ---- T3 密封原语 ----

func testKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

func TestBoxKeypairDeterministic(t *testing.T) {
	priv := testKey(t)
	pub1, priv1, err := BoxKeypair(priv)
	if err != nil {
		t.Fatal(err)
	}
	pub2, priv2, err := BoxKeypair(priv)
	if err != nil {
		t.Fatal(err)
	}
	if *pub1 != *pub2 || *priv1 != *priv2 {
		t.Fatal("同一 Ed25519 私钥推导必须确定(双端一致的前提)")
	}
	if pub1 == priv1 {
		t.Fatal("公私钥不得相同(clamp 后仍须互异)")
	}
}

func TestSealOpenRoundtrip(t *testing.T) {
	sender, receiver := testKey(t), testKey(t)
	rxPub, _, err := BoxKeypair(receiver)
	if err != nil {
		t.Fatal(err)
	}
	nonce, boxed, err := SealInvite(rxPub, sender, InvitePayload{
		NodeID: "aaaa", Code: "KJ8Y-WCYZ-E249", Name: "发送站", Note: "设计稿",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, rxPriv, _ := BoxKeypair(receiver)
	senderPub, _, _ := BoxKeypair(sender)
	inv, err := OpenInvite(nonce, boxed, senderPub, rxPriv)
	if err != nil {
		t.Fatal(err)
	}
	if inv.Code != "KJ8Y-WCYZ-E249" || inv.NodeID != "aaaa" || inv.Name != "发送站" || inv.Note != "设计稿" {
		t.Fatalf("开箱负载不符: %+v", inv)
	}
}

func TestOpenRejectsTamperedBox(t *testing.T) {
	sender, receiver := testKey(t), testKey(t)
	rxPub, rxPriv, _ := BoxKeypair(receiver)
	nonce, boxed, err := SealInvite(rxPub, sender, InvitePayload{NodeID: "a", Code: "KJ8Y-WCYZ-E249"})
	if err != nil {
		t.Fatal(err)
	}
	// 篡改密文单字节
	raw, _ := base64.StdEncoding.DecodeString(boxed)
	raw[len(raw)-1] ^= 0x01
	tampered := base64.StdEncoding.EncodeToString(raw)
	senderPub, _, _ := BoxKeypair(sender)
	if _, err := OpenInvite(nonce, tampered, senderPub, rxPriv); err == nil {
		t.Fatal("篡改密文必须开箱失败")
	}
}

func TestOpenRejectsWrongSenderKey(t *testing.T) {
	sender, receiver, impostor := testKey(t), testKey(t), testKey(t)
	rxPub, rxPriv, _ := BoxKeypair(receiver)
	nonce, boxed, err := SealInvite(rxPub, sender, InvitePayload{NodeID: "a", Code: "KJ8Y-WCYZ-E249"})
	if err != nil {
		t.Fatal(err)
	}
	// 冒名者公钥开箱(封套 from 被顶替的形态)必须失败
	impPub, _, _ := BoxKeypair(impostor)
	if _, err := OpenInvite(nonce, boxed, impPub, rxPriv); err == nil {
		t.Fatal("发端身份不符必须开箱失败")
	}
}

func TestOpenRejectsWrongReceiverKey(t *testing.T) {
	sender, receiver, stranger := testKey(t), testKey(t), testKey(t)
	rxPub, _, _ := BoxKeypair(receiver)
	nonce, boxed, err := SealInvite(rxPub, sender, InvitePayload{NodeID: "a", Code: "KJ8Y-WCYZ-E249"})
	if err != nil {
		t.Fatal(err)
	}
	_, strangerPriv, _ := BoxKeypair(stranger)
	senderPub, _, _ := BoxKeypair(sender)
	if _, err := OpenInvite(nonce, boxed, senderPub, strangerPriv); err == nil {
		t.Fatal("非收端私钥必须开箱失败(第三方抢收=只浪费不泄密)")
	}
}
