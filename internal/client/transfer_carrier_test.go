package client

// 传输承载与收尾语义的守卫（2026-10-26 审计 P1/P2 修复）：
//   - P1:交互式选文件若非升序 ⇒ 首个文件回执 ID 与发送侧期望不符 ⇒ 整场失败；
//   - P2:接收侧在收到对端 MsgSwap 之前就切到新承载 ⇒ 双端读写不同流；
//   - P2:recvAll 把「读不到 final 帧」当成功返回（错误被吞）。

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pigeonbox/p2p/internal/wire"
)

// pipeXport 建立一对内存 wire.Conn（同密钥、发送侧/接收侧角色）并包成 xport。
func pipeXport(t *testing.T, key [32]byte) (snd, rcv *xport) {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	s, err := wire.New(a, key, true)
	if err != nil {
		t.Fatalf("构造发送侧: %v", err)
	}
	r, err := wire.New(b, key, false)
	if err != nil {
		t.Fatalf("构造接收侧: %v", err)
	}
	return &xport{ctrl: s, cleanup: func() { _ = a.Close() }},
		&xport{ctrl: r, cleanup: func() { _ = b.Close() }}
}

// manifestOf 构造单文件 manifest。
func manifestOf(name string, size int64) []byte {
	b, _ := json.Marshal(manifestMsg{Files: []manifestEntry{{ID: 0, Name: name, Size: size}}})
	return b
}

// driveSingleFile 发送侧手工驱动一个文件：manifest → accept → meta → ready
// → chunk → ack。ack 后置 final=true 时补发 final 帧；否则**不补**（模拟
// 发送方在最后一个 ack 之后崩溃/断链）。返回错误而不调 t.Fatalf——本函数
// 会在测试协程之外被调用（FailNow 只能在测试协程里调）。
func driveSingleFile(ctrl *wire.Conn, name, content string, sendFinal bool) error {
	if err := ctrl.WriteMsg(wire.MsgManifest, manifestOf(name, int64(len(content)))); err != nil {
		return fmt.Errorf("写 manifest: %w", err)
	}
	typ, _, err := ctrl.ReadMsg()
	if err != nil || typ != wire.MsgAccept {
		return fmt.Errorf("读 accept: typ=%d err=%v", typ, err)
	}
	sum := sha256.Sum256([]byte(content))
	meta, _ := json.Marshal(metaMsg{Name: name, Size: int64(len(content)), SHA256: hex.EncodeToString(sum[:])})
	if err := ctrl.WriteMsg(wire.MsgMeta, meta); err != nil {
		return fmt.Errorf("写 meta: %w", err)
	}
	typ, _, err = ctrl.ReadMsg()
	if err != nil || typ != wire.MsgReady {
		return fmt.Errorf("读 ready: typ=%d err=%v", typ, err)
	}
	if err := ctrl.WriteMsg(wire.MsgChunk, []byte(content)); err != nil {
		return fmt.Errorf("写 chunk: %w", err)
	}
	typ, _, err = ctrl.ReadMsg()
	if err != nil || typ != wire.MsgFileAck {
		return fmt.Errorf("读 fileAck: typ=%d err=%v", typ, err)
	}
	if sendFinal {
		fin, _ := json.Marshal(finalMsg{OK: true, Message: "1 个文件"})
		if err := ctrl.WriteMsg(wire.MsgFinal, fin); err != nil {
			return fmt.Errorf("写 final: %w", err)
		}
	}
	return nil
}

// TestRecvAllMissingFinalIsError 发送方在最后一个 ack 之后断链（不发 final），
// recvAll 必须返回错误——final 是强制协议帧，「读不到」= 失败。
//
// 负对照：把判定改回 `if err == nil && msgType != wire.MsgFinal` ⇒ 红。
func TestRecvAllMissingFinalIsError(t *testing.T) {
	key := [32]byte{61}
	snd, rcv := pipeXport(t, key)

	dir := t.TempDir()
	errCh := make(chan error, 1)
	go func() {
		_, err := recvAll(func() *xport { return rcv }, dir, nil, nil)
		errCh <- err
	}()

	// 发完文件回执即断链（不发 final）
	if err := driveSingleFile(snd.ctrl, "a.bin", "hello", false); err != nil {
		t.Fatalf("发送侧: %v", err)
	}
	_ = snd.ctrl.Close() // 断链：接收侧读到 EOF

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("缺 final 帧时 recvAll 应返回错误，实际 nil（成功）")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("recvAll 10s 未返回")
	}
}

// TestRecvAllFinalOK recvAll 正常路径：final 帧到达 ⇒ 成功返回。
func TestRecvAllFinalOK(t *testing.T) {
	key := [32]byte{62}
	snd, rcv := pipeXport(t, key)

	dir := t.TempDir()
	errCh := make(chan error, 1)
	go func() {
		files, err := recvAll(func() *xport { return rcv }, dir, nil, nil)
		if err == nil && len(files) != 1 {
			err = errExpectFiles
		}
		errCh <- err
	}()

	if err := driveSingleFile(snd.ctrl, "a.bin", "hello", true); err != nil {
		t.Fatalf("发送侧: %v", err)
	}

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("正常路径不应报错: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("recvAll 10s 未返回")
	}
	got, err := os.ReadFile(filepath.Join(dir, "a.bin"))
	if err != nil || string(got) != "hello" {
		t.Fatalf("落盘内容错: %q err=%v", got, err)
	}
}

var errExpectFiles = errExpect("文件数不符")

type errExpect string

func (e errExpect) Error() string { return string(e) }

// TestRecvAllKeepsCarrierUntilSwap 接收侧**不得**在收到对端 MsgSwap 之前
// 切到新承载：假 srcGetter 第二次返回另一条连接，若接收侧抢跑换源，读到的
// meta 永远不来（对端在旧承载上写）⇒ 传输卡死。
//
// 负对照：恢复「循环开头无条件 getX()」⇒ 红（超时 + getX 调用次数 >1）。
func TestRecvAllKeepsCarrierUntilSwap(t *testing.T) {
	key := [32]byte{63}
	sndA, rcvA := pipeXport(t, key)
	_, rcvB := pipeXport(t, key) // 「直连腿」：无人写

	var calls atomic.Int64
	getX := func() *xport {
		if calls.Add(1) == 1 {
			return rcvA
		}
		return rcvB
	}

	dir := t.TempDir()
	errCh := make(chan error, 1)
	go func() {
		_, err := recvAll(getX, dir, nil, nil)
		errCh <- err
	}()

	// 发送侧放协程：缺陷态下接收侧抢跑换源 ⇒ 发送侧写 meta 无人接收 ⇒
	// 阻塞；测试体的超时闸门必须能观察到（故不能同步调用）。
	sendErr := make(chan error, 1)
	go func() { sendErr <- driveSingleFile(sndA.ctrl, "a.bin", "hello", true) }()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("传输应成功: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("recvAll 10s 未返回（接收侧读到新承载上——getX 调用 %d 次）", calls.Load())
	}
	if err := <-sendErr; err != nil {
		t.Fatalf("发送侧: %v", err)
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("接收侧在未收到 MsgSwap 前就换了承载（getX 调用 %d 次,期望 1 次）", n)
	}
	got, err := os.ReadFile(filepath.Join(dir, "a.bin"))
	if err != nil || string(got) != "hello" {
		t.Fatalf("落盘内容错: %q err=%v", got, err)
	}
}

// TestReceiveDescendingSelectionE2E 端到端：接收侧按**用户输入顺序**降序选
// 文件（交互式输入 "3,2"），传输仍须完成且两个文件内容正确——
// 2026-10-26 审计 P1 的确定性复现（缺陷态：首个回执带上非首个文件的 ID
// ⇒ 发送侧判「fileAck id 不符」⇒ 整场失败）。
//
// 负对照：去掉接收侧的 manifest 序归一 ⇒ 红（"fileAck id 不符"）。
func TestReceiveDescendingSelectionE2E(t *testing.T) {
	f := newFixture(t, true)
	code, _ := GenerateCode()
	sendDir := t.TempDir()
	recvDir := t.TempDir()
	f1 := randomFile(t, sendDir, "甲.bin", 1024)
	f2 := randomFile(t, sendDir, "乙.bin", 2048)
	f3 := randomFile(t, sendDir, "丙.bin", 4096)

	so := testOpts(f, "send")
	so.DisablePunch = true
	errCh := make(chan error, 1)
	go func() {
		c, err := New(so)
		if err != nil {
			errCh <- err
			return
		}
		_, err = c.Send([]string{f1, f2, f3}, code)
		errCh <- err
	}()

	waitForAnnounce(t, f.base, code)
	ro := testOpts(f, "recv")
	ro.DisablePunch = true
	// 用户输入 "3,2"（降序，很自然：先选大的）⇒ 回调按输入顺序返回
	ro.ChooseFiles = func(mf Manifest) []ManifestEntry {
		return []ManifestEntry{mf.Files[2], mf.Files[1]}
	}
	c, err := New(ro)
	if err != nil {
		t.Fatal(err)
	}
	files, err := c.Receive(code, recvDir)
	if err != nil {
		t.Fatalf("接收: %v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("发送: %v", err)
	}
	if len(files) != 2 {
		t.Fatalf("应收 2 个文件,实际 %d: %v", len(files), files)
	}
	byName := map[string]string{}
	for _, p := range files {
		byName[filepath.Base(p)] = p
	}
	assertSameFile(t, f2, byName["乙.bin"])
	assertSameFile(t, f3, byName["丙.bin"])
}

// （如用户输入 "2,1"）时，传输仍须完成且两个文件内容正确——接收方按
// manifest 序归一（发送方恒按 manifest 序发送）。
//
// 负对照：去掉归一（直接用 choose() 返回值）⇒ 红（fileAck id 不符）。
func TestRecvAllNormalizesSelectionOrder(t *testing.T) {
	key := [32]byte{64}
	snd, rcv := pipeXport(t, key)

	dir := t.TempDir()
	// 两个文件，ID 0/1
	names := []string{"f0.bin", "f1.bin"}
	contents := []string{"zero", "one"}
	mf := manifestMsg{Files: []manifestEntry{
		{ID: 0, Name: names[0], Size: int64(len(contents[0]))},
		{ID: 1, Name: names[1], Size: int64(len(contents[1]))},
	}}
	mfBytes, _ := json.Marshal(mf)

	// 选文件回调：按「用户输入顺序」返回降序（2,1）
	choose := func(m manifestMsg) []manifestEntry {
		return []manifestEntry{m.Files[1], m.Files[0]}
	}

	errCh := make(chan error, 1)
	go func() {
		_, err := recvAll(func() *xport { return rcv }, dir, choose, nil)
		errCh <- err
	}()

	// 发送侧：按 manifest 序发两个文件
	if err := snd.ctrl.WriteMsg(wire.MsgManifest, mfBytes); err != nil {
		t.Fatalf("写 manifest: %v", err)
	}
	typ, body, err := snd.ctrl.ReadMsg()
	if err != nil || typ != wire.MsgAccept {
		t.Fatalf("读 accept: typ=%d err=%v", typ, err)
	}
	var acc acceptMsg
	if err := json.Unmarshal(body, &acc); err != nil {
		t.Fatalf("解析 accept: %v", err)
	}
	if len(acc.Accepted) != 2 {
		t.Fatalf("accept 应含 2 个文件,实际 %v", acc.Accepted)
	}
	for i, e := range mf.Files {
		sum := sha256.Sum256([]byte(contents[i]))
		meta, _ := json.Marshal(metaMsg{Name: e.Name, Size: e.Size, SHA256: hex.EncodeToString(sum[:])})
		if err := snd.ctrl.WriteMsg(wire.MsgMeta, meta); err != nil {
			t.Fatalf("写 meta: %v", err)
		}
		typ, _, err = snd.ctrl.ReadMsg()
		if err != nil || typ != wire.MsgReady {
			t.Fatalf("读 ready: typ=%d err=%v", typ, err)
		}
		if err := snd.ctrl.WriteMsg(wire.MsgChunk, []byte(contents[i])); err != nil {
			t.Fatalf("写 chunk: %v", err)
		}
		typ, body, err = snd.ctrl.ReadMsg()
		if err != nil || typ != wire.MsgFileAck {
			t.Fatalf("读 fileAck: typ=%d err=%v", typ, err)
		}
		var ack fileAckMsg
		if err := json.Unmarshal(body, &ack); err != nil {
			t.Fatalf("解析 fileAck: %v", err)
		}
		if ack.ID != e.ID {
			t.Fatalf("fileAck id 不符: %d≠%d", ack.ID, e.ID)
		}
	}
	fin, _ := json.Marshal(finalMsg{OK: true, Message: "2 个文件"})
	if err := snd.ctrl.WriteMsg(wire.MsgFinal, fin); err != nil {
		t.Fatalf("写 final: %v", err)
	}

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("传输应成功: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("recvAll 10s 未返回")
	}
	for i, n := range names {
		got, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil || string(got) != contents[i] {
			t.Fatalf("落盘内容错 %s: %q err=%v", n, got, err)
		}
	}
}
