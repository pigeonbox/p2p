package client

import (
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

// 回归锁（2026-11-06 P0）：打洞探针的**长度判据必须先于切片**。
//
// 缺陷：读循环里直接 buf[NonceSize:n]，n < NonceSize(12) 时 start > end
// ⇒ "slice bounds out of range" panic；该循环在 establish → Send/Receive
// 主链上、无 GoSafe 兜底 ⇒ 任一第三方/损坏 UDP 包即可打死传输进程。
//
// 本用例覆盖 n=0..NonceSize 的每一个短包长度（负对照：把 probeMatches 的
// 长度判据删掉后，这些用例会 panic 而不是返回 false）。
func TestProbeMatches_ShortPacketDoesNotPanic(t *testing.T) {
	key := make([]byte, chacha20poly1305.KeySize)
	for i := range key {
		key[i] = byte(i)
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		t.Fatalf("chacha20poly1305.New: %v", err)
	}
	buf := make([]byte, 128) // 与 punchDual 的读缓冲同尺寸

	for n := 0; n < aead.NonceSize()+aead.Overhead(); n++ {
		if probeMatches(aead, buf, n) {
			t.Fatalf("n=%d 不可能被认作合法探针（短于 Nonce+Tag）", n)
		}
	}

	// 长度够了但内容是垃圾 ⇒ 解密失败 ⇒ false（不得 panic）
	if probeMatches(aead, buf, aead.NonceSize()+aead.Overhead()) {
		t.Fatal("随机内容不应被认作合法探针")
	}
}

// 正对照：真实探针（sealProbe 形态）必须被认出——否则上面的判据可能靠
// 「恒定返回 false」蒙过去。
func TestProbeMatches_RealProbeAccepted(t *testing.T) {
	key := make([]byte, chacha20poly1305.KeySize)
	for i := range key {
		key[i] = byte(255 - i)
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		t.Fatalf("chacha20poly1305.New: %v", err)
	}
	nonce := make([]byte, chacha20poly1305.NonceSize)
	pkt := aead.Seal(nonce, nonce, []byte("fcb-punch-v1"), nil)

	if !probeMatches(aead, pkt, len(pkt)) {
		t.Fatal("真实探针必须被认出（否则对端永远确认不了身份）")
	}
	// 少一个字节 ⇒ 必须判否（长度判据不能放过截断包）
	if probeMatches(aead, pkt, len(pkt)-1) {
		t.Fatal("截断的探针不得被接受")
	}
}
