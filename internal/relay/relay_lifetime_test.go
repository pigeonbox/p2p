package relay

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net"
	"testing"
	"time"
)

// p2p#49 复现组:配对后管道无空闲/最长生命周期超时、活动信道无全局上限。
//
// 判据统一用「测试自己设的读超时 = 服务端从未关连接 = 红」,
// EOF/connection closed = 服务端主动掐断 = 绿(修复前三种场景全部红)。

// newRelay 起一个中继,返回监听地址。
func newRelay(t *testing.T, p Params) string {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close(); cancel() })
	go func() { _ = Serve(ctx, ln, p) }()
	return ln.Addr().String()
}

func randToken(t *testing.T) string {
	t.Helper()
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(raw)
}

// isOurDeadlineErr 区分「测试自己设的读超时」与「对端被服务端关闭」。
func isOurDeadlineErr(err error) bool {
	nerr, ok := err.(net.Error)
	return ok && nerr.Timeout()
}

// p2p#49-1:配对后空闲(无任何字节)超过 IdleTimeout 必须被服务端关闭。
// 修复前:读首行后 SetDeadline(time.Time{}) 清除一切超时,连接可无限期挂起
// ——攻击者两端同 token 配对后保持空闲即可长期占用活动信道与中继带宽。
func TestPairedPipeIdleTimeout(t *testing.T) {
	addr := newRelay(t, Params{IdleTimeout: 300 * time.Millisecond})
	token := randToken(t)

	a := dialToken(t, addr, token)
	defer func() { _ = a.Close() }()
	b := dialToken(t, addr, token)
	defer func() { _ = b.Close() }()

	// 配对完成的判据:任一端写入能到达对端(此后不再发任何字节)
	if _, err := a.Write([]byte("warmup")); err != nil {
		t.Fatal(err)
	}
	_ = b.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 6)
	if _, err := ioReadFull(b, buf); err != nil {
		t.Fatalf("配对通路应可用: %v", err)
	}

	// 空闲等待:300ms 后服务端应掐断
	_ = b.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := b.Read(buf); err == nil {
		t.Fatal("空闲超时后对端必须被服务端关闭(读应报错)")
	} else if isOurDeadlineErr(err) {
		t.Fatalf("服务端未在 IdleTimeout 内关闭空闲管道(读到测试自身 deadline 超时): %v", err)
	}
}

// p2p#49-2:管道即使持续有流量,超过 MaxChannelLifetime 也必须被掐断
// (防活动信道被长连接永久占用)。修复前无生命周期上限,可持续占用到对端断开。
func TestPairedPipeMaxLifetime(t *testing.T) {
	addr := newRelay(t, Params{
		IdleTimeout:        10 * time.Second,
		MaxChannelLifetime: 500 * time.Millisecond,
	})
	token := randToken(t)

	a := dialToken(t, addr, token)
	defer func() { _ = a.Close() }()
	b := dialToken(t, addr, token)
	defer func() { _ = b.Close() }()

	// a 持续灌字节(20ms/1字节)——空闲超时不会触发,只有生命周期上限能掐断
	go func() {
		for {
			if _, err := a.Write([]byte("x")); err != nil {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
	}()

	start := time.Now()
	_ = b.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1)
	for {
		if _, err := b.Read(buf); err != nil {
			if isOurDeadlineErr(err) {
				t.Fatalf("持续流量下服务端未在 MaxChannelLifetime 掐断(读到测试自身 deadline 超时): %v", err)
			}
			// 对端被服务端关闭 = 绿
			if elapsed := time.Since(start); elapsed > 2*time.Second {
				t.Fatalf("掐断应在生命周期上限附近(≈500ms),实测 %v", elapsed)
			}
			return
		}
	}
}

// p2p#49-3:活动信道(配对完成)受全局上限约束——超限拒绝新配对,
// 而不是无限增长。修复前 maxWaiting 只约束等待表,配对后无任何闸。
func TestActiveChannelGlobalLimit(t *testing.T) {
	addr := newRelay(t, Params{MaxActiveChannels: 1, IdleTimeout: 10 * time.Second})

	// 第一对:占满唯一的活动信道名额
	tok1 := randToken(t)
	a1 := dialToken(t, addr, tok1)
	defer func() { _ = a1.Close() }()
	b1 := dialToken(t, addr, tok1)
	defer func() { _ = b1.Close() }()
	if _, err := a1.Write([]byte("go")); err != nil {
		t.Fatal(err)
	}
	_ = b1.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := ioReadFull(b1, make([]byte, 2)); err != nil {
		t.Fatalf("第一对应正常配对: %v", err)
	}

	// 第二对:名额已满,新到的配对连接必须被服务端拒绝(关闭)
	tok2 := randToken(t)
	a2 := dialToken(t, addr, tok2)
	defer func() { _ = a2.Close() }()
	b2 := dialToken(t, addr, tok2)
	defer func() { _ = b2.Close() }()

	_ = b2.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := b2.Read(make([]byte, 1)); err == nil {
		t.Fatal("活动信道满时新配对必须被拒(读应报错)")
	} else if isOurDeadlineErr(err) {
		t.Fatalf("活动信道满时服务端未拒绝新配对(读到测试自身 deadline 超时): %v", err)
	}

	// 第一对不受影响
	if _, err := a1.Write([]byte("still")); err != nil {
		t.Fatalf("第一对不应受第二对被拒影响: %v", err)
	}
	if _, err := ioReadFull(b1, make([]byte, 5)); err != nil {
		t.Fatalf("第一对信道应仍存活: %v", err)
	}
}
