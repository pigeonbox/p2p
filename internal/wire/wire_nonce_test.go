package wire

// nonce 空间与重放窗口守卫（2026-10-26 审计 P0/P2 修复）：
//   - P0:同一会话密钥下中继腿与直连腿复用同一 (key, nonce) ⇒ 密钥流重用 +
//     Poly1305 一次性密钥复用（可伪造任意合法帧）；
//   - P2:帧层无重放窗口（nonce 明文在帧内，接收侧不校验序号）。
//
// 帧格式未变（nonce 仍 12B、逐字节在帧内传输）⇒ 与 v2~v4 旧端互操作不受
// 影响——由 TestLegacyPeerInterop 机械验证（故无需 N-1 双格式实现）。

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

// roRW 只读 ReadWriter（测试用：只喂入站帧；Write 丢弃）。
type roRW struct{ r *bytes.Reader }

func (n roRW) Read(p []byte) (int, error)  { return n.r.Read(p) }
func (n roRW) Write(p []byte) (int, error) { return len(p), nil }

// frameNonce 取帧内的 nonce（帧格式：u32(len) || nonce(12) || ciphertext）。
func frameNonce(frame []byte) []byte {
	if len(frame) < 4+chacha20poly1305.NonceSize {
		return nil
	}
	return frame[4 : 4+chacha20poly1305.NonceSize]
}

// TestLegsNonceSpaceDisjoint 同密钥派生两条承载（中继腿 + 直连腿）各写一帧，
// 断言两者 nonce 不相交——(key, nonce) 重用的直接守卫。
//
// 负对照：把 epoch 置 0（回到「两条连接共用同 nonce 空间」的缺陷态）⇒ 红。
func TestLegsNonceSpaceDisjoint(t *testing.T) {
	key := [32]byte{42}
	var b1, b2 bytes.Buffer
	leg1, err := New(&nopWriteReader{buf: &b1}, key, true)
	if err != nil {
		t.Fatalf("构造中继腿: %v", err)
	}
	leg2, err := New(&nopWriteReader{buf: &b2}, key, true)
	if err != nil {
		t.Fatalf("构造直连腿: %v", err)
	}
	if err := leg1.WriteMsg(MsgMeta, []byte(`{"name":"a.bin"}`)); err != nil {
		t.Fatalf("中继腿写帧: %v", err)
	}
	if err := leg2.WriteMsg(MsgMeta, []byte(`{"name":"b.bin"}`)); err != nil {
		t.Fatalf("直连腿写帧: %v", err)
	}

	n1 := frameNonce(b1.Bytes())
	n2 := frameNonce(b2.Bytes())
	if n1 == nil || n2 == nil {
		t.Fatal("帧内未取到 nonce")
	}
	if bytes.Equal(n1, n2) {
		t.Fatalf("两条腿 nonce 相同 ⇒ (key, nonce) 重用: %x", n1)
	}
	// 差异必须落在 epoch 字节 [1:4]；方向标签与序号位置不得漂移
	// （序号位置漂移会连带破坏重放窗口的判定）。
	if n1[0] != dirSend || n2[0] != dirSend {
		t.Fatalf("方向标签漂移: %q %q", n1[0], n2[0])
	}
	if bytes.Equal(n1[1:4], n2[1:4]) {
		t.Fatalf("epoch 字节相同 ⇒ 两条腿仍共用 nonce 空间: %x %x", n1[1:4], n2[1:4])
	}
	if binary.BigEndian.Uint64(n1[4:]) != 0 || binary.BigEndian.Uint64(n2[4:]) != 0 {
		t.Fatal("首帧序号应为 0（nonce[4:12] 仍是序号位）")
	}
}

// TestLegacyPeerInterop 新旧端互操作：epoch 只改 nonce 的空闲字节，帧格式
// 未变 ⇒ v2~v4 旧端（epoch 恒零）仍能与新端互通，反之亦然。
// 这就是「不需要 N-1 双格式实现」的机械证据。
func TestLegacyPeerInterop(t *testing.T) {
	key := [32]byte{43}

	t.Run("旧端→新端", func(t *testing.T) {
		var buf bytes.Buffer
		legacy, err := newConn(&nopWriteReader{buf: &buf}, key, true, 0)
		if err != nil {
			t.Fatalf("构造旧端: %v", err)
		}
		if err := legacy.WriteMsg(MsgMeta, []byte(`{"name":"legacy.bin"}`)); err != nil {
			t.Fatalf("旧端写帧: %v", err)
		}
		// 旧端帧的 epoch 字节必须恒零（与历史实现逐字节一致）
		if !bytes.Equal(frameNonce(buf.Bytes())[1:4], []byte{0, 0, 0}) {
			t.Fatalf("旧端 epoch 字节应恒零: %x", frameNonce(buf.Bytes())[1:4])
		}
		newSide, err := New(roRW{bytes.NewReader(buf.Bytes())}, key, false)
		if err != nil {
			t.Fatalf("构造新端: %v", err)
		}
		typ, body, err := newSide.ReadMsg()
		if err != nil || typ != MsgMeta || string(body) != `{"name":"legacy.bin"}` {
			t.Fatalf("新端读旧端帧: typ=%d body=%q err=%v", typ, body, err)
		}
	})

	t.Run("新端→旧端", func(t *testing.T) {
		var buf bytes.Buffer
		fresh, err := New(&nopWriteReader{buf: &buf}, key, true)
		if err != nil {
			t.Fatalf("构造新端: %v", err)
		}
		if err := fresh.WriteMsg(MsgMeta, []byte(`{"name":"fresh.bin"}`)); err != nil {
			t.Fatalf("新端写帧: %v", err)
		}
		// 旧端实现：只校验 nonce[0] 方向标签 + AEAD，epoch 字节不参与判定
		legacy, err := newConn(roRW{bytes.NewReader(buf.Bytes())}, key, false, 0)
		if err != nil {
			t.Fatalf("构造旧端: %v", err)
		}
		typ, body, err := legacy.ReadMsg()
		if err != nil || typ != MsgMeta || string(body) != `{"name":"fresh.bin"}` {
			t.Fatalf("旧端读新端帧: typ=%d body=%q err=%v", typ, body, err)
		}
	})
}

// TestReplayFrameRejected 同一帧字节二次喂入必须被拒（重放窗口）。
//
// 负对照：去掉 seq 窗口判定 ⇒ 红。
func TestReplayFrameRejected(t *testing.T) {
	key := [32]byte{44}
	var buf bytes.Buffer
	snd, err := New(&nopWriteReader{buf: &buf}, key, true)
	if err != nil {
		t.Fatalf("构造发送端: %v", err)
	}
	if err := snd.WriteMsg(MsgChunk, []byte("payload")); err != nil {
		t.Fatalf("写帧: %v", err)
	}
	frame := buf.Bytes()

	// 重放：被动观察者抓到帧字节后原样再注入一次（中继腿是明文 TCP，
	// 攻击者可往流里塞重复字节）⇒ 同一条连接第二次读到同 nonce ⇒ 必须拒。
	stream := make([]byte, 0, len(frame)*2)
	stream = append(stream, frame...)
	stream = append(stream, frame...)

	rcv, err := New(roRW{bytes.NewReader(stream)}, key, false)
	if err != nil {
		t.Fatalf("构造接收端: %v", err)
	}
	typ, body, err := rcv.ReadMsg()
	if err != nil || typ != MsgChunk || string(body) != "payload" {
		t.Fatalf("首帧应正常读出: typ=%d body=%q err=%v", typ, body, err)
	}
	if _, _, err := rcv.ReadMsg(); !errors.Is(err, ErrReplay) {
		t.Fatalf("重放帧应被拒(ErrReplay),实际 err=%v", err)
	}
}

// TestReplayWindowPerConn 换源=新承载=新窗口：新承载的首帧(seq=0)必须被
// 接受（否则「先中继后直连」的正常升级会被自己的重放窗口打死）。
func TestReplayWindowPerConn(t *testing.T) {
	key := [32]byte{45}
	var buf bytes.Buffer
	snd, err := New(&nopWriteReader{buf: &buf}, key, true)
	if err != nil {
		t.Fatalf("构造发送端: %v", err)
	}
	if err := snd.WriteMsg(MsgMeta, []byte("x")); err != nil {
		t.Fatalf("写帧: %v", err)
	}
	// 两条独立承载（模拟中继腿 → 直连腿），各自 seq 从 0 起算
	rcv1, _ := New(roRW{bytes.NewReader(buf.Bytes())}, key, false)
	if _, _, err := rcv1.ReadMsg(); err != nil {
		t.Fatalf("中继腿首帧: %v", err)
	}
	rcv2, _ := New(roRW{bytes.NewReader(buf.Bytes())}, key, false)
	if _, _, err := rcv2.ReadMsg(); err != nil {
		t.Fatalf("直连腿首帧(seq=0,新窗口)应被接受: %v", err)
	}
}

// TestEmptyPlaintextFrameRejected total==28（nonce 12 + tag 16，零长明文）
// 的**合法**帧（tag 用真密钥 seal 空明文算出）必须被拒而不是 panic。
//
// 负对照：把长度下界改回 NonceSize+16 ⇒ 旧码会走到 plaintext[0] 越界
// panic ⇒ 测试红。
func TestEmptyPlaintextFrameRejected(t *testing.T) {
	key := [32]byte{46}
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		t.Fatalf("构造 AEAD: %v", err)
	}
	nonce := make([]byte, chacha20poly1305.NonceSize)
	nonce[0] = dirSend // 接收侧(peerTag=dirSend)的方向标签
	ct := aead.Seal(nil, nonce, []byte{}, nil)

	frame := make([]byte, 4+len(nonce)+len(ct))
	binary.BigEndian.PutUint32(frame, uint32(len(nonce)+len(ct)))
	copy(frame[4:], nonce)
	copy(frame[4+len(nonce):], ct)

	rcv, err := New(roRW{bytes.NewReader(frame)}, key, false)
	if err != nil {
		t.Fatalf("构造接收端: %v", err)
	}
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("零长明文帧导致 panic: %v", r)
		}
	}()
	// 必须由**长度下界**拦下（帧格式层），而不是靠解密后的空明文兜底——
	// 两道防线要可分辨，否则任何一道被改都观测不到。
	if _, _, err := rcv.ReadMsg(); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("零长明文帧应由长度下界判为 ErrCorrupt,实际 err=%v", err)
	}
}

// TestSplitPlaintextRejectsEmpty splitPlaintext 的零长明文守卫（长度下界的
// 兜底防线）。
//
// 负对照：去掉 len==0 检查 ⇒ 旧码越界 panic ⇒ 测试红。
func TestSplitPlaintextRejectsEmpty(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("零长明文导致 panic: %v", r)
		}
	}()
	if _, _, err := splitPlaintext(nil); !errors.Is(err, ErrEmptyPlaintext) {
		t.Fatalf("零长明文应判为 ErrEmptyPlaintext,实际 err=%v", err)
	}
	if typ, body, err := splitPlaintext([]byte{MsgFinal, 'o', 'k'}); err != nil ||
		typ != MsgFinal || string(body) != "ok" {
		t.Fatalf("正常明文拆分错: typ=%d body=%q err=%v", typ, body, err)
	}
}
