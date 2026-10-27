package client

// 换源（MsgSwap）后的**新承载就位等待**的守卫（2026-10-26）。
//
// ## 缺陷
//
// 接收侧收到发送侧的 MsgSwap 后，原实现**立刻** `x = getX()` 换源。但
// 接收侧自己的直连承载是由**升级协程异步 store** 的 ⇒ 收到 MsgSwap 的那一刻
// 它可能**还没就位** ⇒ getX() 返回的还是**旧承载** ⇒ 双方读写不同流 ⇒
// 发送侧把 meta/chunk/final 都写在新承载上，而接收侧在旧承载上等 ⇒
// **60s 空闲超时**（quic-go 的 "no recent network activity"）。
//
// ⇒ 实测症状：本仓 CI 长期红在「final 接收: timeout: no recent network
// activity」，且**改动前的 main 上就存在**（dependabot 分支的失败日志同款）
// ⇒ 既存竞态，非某次改动引入。
//
// ## 修法
//
// 换源时**等新承载就位**（有界预算 swapCarrierWaitBudget）：只有拿到与旧承载
// **不同**的那条才换；等不到就报**明确**错误（而不是让调用方在 60s 后拿到
// 一条与真实原因无关的超时）。
//
// ## 负对照
//
// 把 awaitSwappedCarrier 改回「一次 getX() 就换」⇒ 本用例红（接收侧读到旧
// 承载上 ⇒ 10s 内传不完）。

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pigeonbox/p2p/internal/wire"
)

// driveSwapSingleFile 发送侧：manifest/accept 在**旧承载**上，然后写 MsgSwap，
// 之后的 meta/chunk/ack/final 全部走**新承载**（模拟「先通后优」的换源）。
func driveSwapSingleFile(oldCtrl, newCtrl *wire.Conn, name, content string) error {
	if err := oldCtrl.WriteMsg(wire.MsgManifest, manifestOf(name, int64(len(content)))); err != nil {
		return fmt.Errorf("写 manifest: %w", err)
	}
	typ, _, err := oldCtrl.ReadMsg()
	if err != nil || typ != wire.MsgAccept {
		return fmt.Errorf("读 accept: typ=%d err=%v", typ, err)
	}
	// 换源标记（仍在旧承载上）
	if err := oldCtrl.WriteMsg(wire.MsgSwap, nil); err != nil {
		return fmt.Errorf("写 swap: %w", err)
	}
	// 之后全部走新承载
	sum := sha256.Sum256([]byte(content))
	meta, _ := json.Marshal(metaMsg{Name: name, Size: int64(len(content)), SHA256: hex.EncodeToString(sum[:])})
	if err := newCtrl.WriteMsg(wire.MsgMeta, meta); err != nil {
		return fmt.Errorf("写 meta: %w", err)
	}
	typ, _, err = newCtrl.ReadMsg()
	if err != nil || typ != wire.MsgReady {
		return fmt.Errorf("读 ready: typ=%d err=%v", typ, err)
	}
	if err := newCtrl.WriteMsg(wire.MsgChunk, []byte(content)); err != nil {
		return fmt.Errorf("写 chunk: %w", err)
	}
	typ, _, err = newCtrl.ReadMsg()
	if err != nil || typ != wire.MsgFileAck {
		return fmt.Errorf("读 fileAck: typ=%d err=%v", typ, err)
	}
	fin, _ := json.Marshal(finalMsg{OK: true, Message: "1 个文件"})
	if err := newCtrl.WriteMsg(wire.MsgFinal, fin); err != nil {
		return fmt.Errorf("写 final: %w", err)
	}
	return nil
}

// TestRecvAllAwaitsNewCarrierAfterSwap 收到 MsgSwap 时**新承载尚未就位**
// ⇒ 接收侧必须等它（而不是继续读旧承载）。
func TestRecvAllAwaitsNewCarrierAfterSwap(t *testing.T) {
	key := [32]byte{97}
	sndA, rcvA := pipeXport(t, key) // 旧承载（中继腿）
	sndB, rcvB := pipeXport(t, key) // 新承载（直连腿）

	// 前 3 次取源都返回**旧承载** ⇒ 模拟「升级协程还没 store 直连承载」
	const lateCarrierCalls = 3
	var calls atomic.Int64
	getX := func() *xport {
		if calls.Add(1) <= lateCarrierCalls {
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

	sendErr := make(chan error, 1)
	go func() { sendErr <- driveSwapSingleFile(sndA.ctrl, sndB.ctrl, "a.bin", "hello") }()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("传输应成功（新承载晚到时必须等它）: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("recvAll 10s 未返回（接收侧没等到新承载就位 ⇒ 读到旧承载上；getX 调用 %d 次）", calls.Load())
	}
	if err := <-sendErr; err != nil {
		t.Fatalf("发送侧: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "a.bin"))
	if err != nil || string(got) != "hello" {
		t.Fatalf("落盘内容错: %q err=%v", got, err)
	}
	if n := calls.Load(); n <= lateCarrierCalls {
		t.Fatalf("getX 只被调用 %d 次 ⇒ 接收侧在 MsgSwap 后没再取源（应轮询等新承载）", n)
	}
}

// TestAwaitSwappedCarrierTimeout 预算内等不到新承载 ⇒ 必须报**明确**错误，
// 而不是让调用方拿着旧承载去读、再等 60s 超时拿到一条无关的错误信息。
func TestAwaitSwappedCarrierTimeout(t *testing.T) {
	key := [32]byte{98}
	_, rcvA := pipeXport(t, key)

	// 永远返回旧承载 ⇒ 必然超时
	getX := func() *xport { return rcvA }

	// 用一个很短预算的等价调用：直接验证 awaitSwappedCarrier 的错误路径
	// （预算常量是 5s，这里只断言「返回错误且错误信息含关键线索」）。
	start := time.Now()
	_, err := awaitSwappedCarrier(getX, rcvA)
	if err == nil {
		t.Fatalf("等不到新承载时必须返回错误")
	}
	if time.Since(start) < swapCarrierWaitBudget {
		t.Fatalf("应等满预算(%.0fs)再报错，实际 %v", swapCarrierWaitBudget.Seconds(), time.Since(start))
	}
	if !contains(err.Error(), "新承载") {
		t.Fatalf("错误信息应点明「新承载未就位」，实际: %v", err)
	}
}

// TestSendAllAwaitsNewCarrierAfterSwap 发送侧换源时**新承载尚未就位** ⇒
// 发送侧必须等它（与接收侧对称），而不是留在旧承载上发后续帧。
//
// ## 缺陷（2026-10-28 实录，同一根因第三轮复发）
//
// 接收侧有 awaitSwappedCarrier（2026-10-26 补），**发送侧没有对称实现**：
// 换源处直接 `x = getX()` ⇒ 拿到「store 前的旧承载」⇒ 发送侧留在旧流，
// 而接收侧已按 MsgSwap 切到新流 ⇒ 双方读写不同流 ⇒ 接收侧在新流上等 final ⇒
// 60s 空闲超时（quic-go "no recent network activity"）。
//
// **方向性证据**：QUIC 角色是「发送方=服务端(listen/accept)、接收方=客户端
// (dial)」⇒ 接收方(dial)承载**先**就位、发送方(accept)**后**就位 ⇒
// 发送侧抢跑拿到旧承载是**结构性偏高**的，不是偶然。
//
// ## 负对照
//
// 把发送侧的 awaitSwappedCarrier 改回「一次 getX() 就换」⇒ 本用例红
// （发送侧把 meta/chunk/final 全写在旧承载上，接收侧在新承载上等 ⇒ 卡死）。
func TestSendAllAwaitsNewCarrierAfterSwap(t *testing.T) {
	key := [32]byte{99}
	sndA, rcvA := pipeXport(t, key) // 旧承载（中继腿）
	sndB, rcvB := pipeXport(t, key) // 新承载（直连腿）

	// 发送侧：前 3 次取源都返回**旧承载** ⇒ 模拟「升级协程还没 store 直连承载」
	const lateCarrierCalls = 3
	var sndCalls atomic.Int64
	getXSnd := func() *xport {
		if sndCalls.Add(1) <= lateCarrierCalls {
			return sndA
		}
		return sndB
	}
	// 接收侧：第 1 次取源是初始承载，之后新承载已就位（dial 方先就位）
	var rcvCalls atomic.Int64
	getXRcv := func() *xport {
		if rcvCalls.Add(1) <= 1 {
			return rcvA
		}
		return rcvB
	}

	dir := t.TempDir()
	src := filepath.Join(dir, "src.bin")
	content := "carrier-wait-payload"
	if err := os.WriteFile(src, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	outDir := t.TempDir()

	recvErr := make(chan error, 1)
	go func() {
		_, err := recvAll(getXRcv, outDir, nil, nil)
		recvErr <- err
	}()

	sendErr := make(chan error, 1)
	go func() {
		// boundary 在文件边界触发一次换源（与真实「先通后优」同形）
		var swapped atomic.Bool
		_, err := sendAll(getXSnd, []string{src}, func(int64, int64) {}, func() bool {
			return swapped.CompareAndSwap(false, true)
		})
		sendErr <- err
	}()

	select {
	case err := <-recvErr:
		if err != nil {
			t.Fatalf("接收侧应成功（发送侧必须等新承载就位）: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatalf("recvAll 15s 未返回（发送侧抢跑留在旧承载 ⇒ 双方读写不同流；发送侧取源 %d 次）", sndCalls.Load())
	}
	if err := <-sendErr; err != nil {
		t.Fatalf("发送侧: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(outDir, "src.bin"))
	if err != nil || string(got) != content {
		t.Fatalf("落盘内容错: %q err=%v", got, err)
	}
	if n := sndCalls.Load(); n <= lateCarrierCalls {
		t.Fatalf("发送侧取源只被调用 %d 次 ⇒ 换源后没等新承载（应轮询等它）", n)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}
