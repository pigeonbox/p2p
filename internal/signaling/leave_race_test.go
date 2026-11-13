package signaling

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pigeonbox/p2p/internal/registry"
)

// setLeaveAfterDetach 装配 p2p#40 测试缝,测试结束还原(经 seamMu,与残留
// readPump 的触发并发也 -race 安全)。
func setLeaveAfterDetach(t *testing.T, f func()) {
	t.Helper()
	seamMu.Lock()
	prev := leaveAfterDetach
	leaveAfterDetach = f
	seamMu.Unlock()
	t.Cleanup(func() {
		seamMu.Lock()
		leaveAfterDetach = prev
		seamMu.Unlock()
	})
}

// TestLeaveDoesNotMistakenlyNotifyNewlyPairedPeer 是 p2p#40 的 TOCTOU 判据:
// A/B 已配对 → A 断线进 leave → 在「摘除 A 之后、向同侪发 peer_left 之前」的
// 窗口(测试缝)里 C 恰好补位与 B 配对 → 断言:
//   - A 的真同侪 B 收到 peer_left(不漏通知);
//   - C(刚配对成功的新对端,与 A 从未配对)不收 peer_left(不误通知)。
//
// 负对照:leave 退回「先 remove 后取同侪」的旧顺序(测试缝不动)⇒ other(A)
// 在补位后取到 C ⇒ C 被误发 peer_left、B 漏收 ⇒ 第一步断言即转红。
func TestLeaveDoesNotMistakenlyNotifyNewlyPairedPeer(t *testing.T) {
	srv, svc := newFixture(t, nil)
	ws := "ws" + strings.TrimPrefix(srv.URL, "http")
	a := registerNode(t, svc, "https://a")
	b := registerNode(t, svc, "https://b")
	c := registerNode(t, svc, "https://c")
	hash := registry.CodeHash("leave-toctou-code-12345")
	ts := time.Now().Unix()

	// 1) A 接入(waiting)→ B 接入(双方 paired)
	connA := dial(t, ws, hash)
	hello(t, connA, a, hash, ts)
	if f := mustFrame(t, connA); f.Type != "waiting" {
		t.Fatalf("A 应 waiting,得到 %+v", f)
	}
	connB := dial(t, ws, hash)
	hello(t, connB, b, hash, ts)
	if f := mustFrame(t, connA); f.Type != "paired" || f.PeerID != b.id {
		t.Fatalf("A 应收到 paired(peer_id=%s),得到 %+v", b.id, f)
	}
	if f := mustFrame(t, connB); f.Type != "paired" || f.PeerID != a.id {
		t.Fatalf("B 应收到 paired(peer_id=%s),得到 %+v", a.id, f)
	}

	// 2) 测试缝:leave 摘除 A 之后阻塞,等待测试在窗口内插入 C 的补位 join
	detached := make(chan struct{})
	release := make(chan struct{})
	var detachedOnce, releaseOnce sync.Once
	closeRelease := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(closeRelease) // 用例中途 Fatal 也要放行,避免 leave 永久阻塞
	setLeaveAfterDetach(t, func() {
		detachedOnce.Do(func() { close(detached) })
		<-release
	})

	// 3) 断开 A 触发 leave
	_ = connA.Close()
	select {
	case <-detached:
	case <-time.After(5 * time.Second):
		t.Fatal("5s 内 leave 未走到测试缝")
	}

	// 4) 窗口内 C 补位:与 B 配对(这正是旧代码 other(A) 会读到的「新对端」)
	connC := dial(t, ws, hash)
	hello(t, connC, c, hash, ts)
	if f := mustFrame(t, connC); f.Type != "paired" || f.PeerID != b.id {
		t.Fatalf("C 应与 B 配对,得到 %+v", f)
	}
	if f := mustFrame(t, connB); f.Type != "paired" || f.PeerID != c.id {
		t.Fatalf("B 应收到与 C 的 paired,得到 %+v", f)
	}
	closeRelease()
	// 等 leave 走完尾段(纯内存操作,200ms 是巨量余量;即便极端负载下未走完,
	// 下面 B 的断言仍会转红,判据不依赖本次等待的精确性)。
	time.Sleep(200 * time.Millisecond)

	// 5) C 不得收到 peer_left:用 B→C 的转发帧钉住时序——若 C 曾被误发,
	// peer_left 必然先于该数据帧出队被读到(负对照:旧顺序下 C 收到 peer_left,
	// 本步即转红)。
	sendData(t, connB, []byte("still-alive"))
	if f := mustFrame(t, connC); f.Type != "data" || string(f.Payload) != "still-alive" {
		t.Fatalf("C 不应收到 peer_left(它与 A 从未配对),得到 %+v", f)
	}

	// 6) A 的真同侪 B 必须收到 peer_left(不漏通知)
	if f := mustFrame(t, connB); f.Type != "peer_left" {
		t.Fatalf("B 应收到 peer_left(A 的真同侪),得到 %+v", f)
	}
}
