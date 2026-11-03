package client

import (
	"bytes"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// 反射协议字面量（与 internal/reflect 内部常量一致；那边未导出，这里用字面量
// 避免为测试扩大公共面）。
const (
	reflectReqMagic  = "fcb-reflect-v1"
	reflectRespMagic = "fcb-reflect-v1-addr "
)

// fakeReflector 假反射器：前 dropN 个请求**静默丢弃**（复刻真实反射器的
// per-IP 令牌桶超限行为：不回任何响应），之后正常回应。
//
// 统计收到的请求数 ⇒ 可断言「客户端确实重试了」。
type fakeReflector struct {
	conn     *net.UDPConn
	mu       sync.Mutex
	received int
	dropped  int // 前 N 个丢弃
}

func newFakeReflector(t *testing.T, dropN int) *fakeReflector {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("假反射器监听: %v", err)
	}
	f := &fakeReflector{conn: conn, dropped: dropN}
	go f.loop()
	t.Cleanup(func() { _ = conn.Close() })
	return f
}

func (f *fakeReflector) loop() {
	buf := make([]byte, 256)
	for {
		_ = f.conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, raddr, err := f.conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		if !strings.HasPrefix(string(buf[:n]), reflectReqMagic) {
			continue
		}
		f.mu.Lock()
		f.received++
		drop := f.received <= f.dropped
		f.mu.Unlock()
		if drop {
			continue // 静默丢弃 = 令牌桶超限的复刻
		}
		resp := reflectRespMagic + raddr.String() + "\n"
		_, _ = f.conn.WriteToUDP([]byte(resp), raddr)
	}
}

func (f *fakeReflector) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.received
}

func (f *fakeReflector) addr() string { return f.conn.LocalAddr().String() }

// TestReflectOwnRetriesAfterSilentDrop 守卫：反射查询被**静默丢包**时必须重试。
//
// 背景（p2p#20）：真实反射器按源 IP 限流（令牌桶 10/s、突发 20）且超限
// **静默丢包**（不回响应）⇒ 并发客户端（同 IP）随机收不到回应 ⇒ UDPPublic 为空
// ⇒ 打洞没有可达目标 ⇒ 直连必然失败。
//
// ⇒ reflectOwn 必须重试到成功；负对照：把重试次数改成 1 ⇒ 本用例红。
func TestReflectOwnRetriesAfterSilentDrop(t *testing.T) {
	f := newFakeReflector(t, 2) // 前 2 次静默丢弃
	client, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	addr, err := reflectOwn(client, "http://"+f.addr())
	if err != nil {
		t.Fatalf("反射查询应重试到成功: %v", err)
	}
	if addr == nil {
		t.Fatalf("反射查询返回空地址")
	}
	if got := f.count(); got < 3 {
		t.Fatalf("反射器只收到 %d 次请求 ⇒ 客户端没重试（应≥3：丢 2 次后第 3 次命中）", got)
	}
}

// TestReflectOwnGivesUpWithError 守卫：彻底失败必须**返回错误**，不许静默降级。
//
// 原实现是「失败即返回 nil，调用方不知道发生了什么」⇒ 现场只剩「打洞失败」，
// 查不到根因。⇒ 这里断言错误非空、且请求次数 == 重试上限（不多打）。
func TestReflectOwnGivesUpWithError(t *testing.T) {
	f := newFakeReflector(t, 1000) // 一直丢
	client, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	addr, err := reflectOwn(client, "http://"+f.addr())
	if err == nil {
		t.Fatalf("反射查询全失败时必须返回错误（got addr=%v）", addr)
	}
	if addr != nil {
		t.Fatalf("失败时不应返回地址: %v", addr)
	}
	if got := f.count(); got != reflectAttempts {
		t.Fatalf("反射器收到 %d 次请求，期望恰好 %d 次（重试上限）", got, reflectAttempts)
	}
}

// TestBuildCandidatesWarnsOnReflectFailure 守卫：反射失败**必须留日志**。
//
// 「静默降级」是这类故障最难查的形态：现场只看到「打洞失败(v4/v6 均未通)」，
// 看不到「公网候选缺失」这个真因。⇒ 必须有 WARN 落在日志里。
func TestBuildCandidatesWarnsOnReflectFailure(t *testing.T) {
	f := newFakeReflector(t, 1000) // 一直丢 ⇒ 反射必失败
	client, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	var buf bytes.Buffer
	c := &Client{
		opt: Options{Registry: "http://" + f.addr()},
		log: slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}
	c.buildCandidates(client, nil, "")

	out := buf.String()
	if !strings.Contains(out, "反射失败") {
		t.Fatalf("反射失败必须留 WARN 日志，实际日志:\n%s", out)
	}
	if !strings.Contains(out, "level=WARN") {
		t.Fatalf("反射失败的日志级别应为 WARN，实际日志:\n%s", out)
	}
}

// TestBuildCandidatesNilSocketNoPanic 守卫：**无 IPv6 环境不得 panic**。
//
// ⚠️ 这是 P0 级隐患（2026-11-03 由本轮改动顺手查出）：
// punchSockets 在 ListenUDP("udp6") 失败时把 sock6 置 nil（纯 v4 走通），
// 而 buildCandidates 无条件调 lanCandidates6(sock6) ⇒ 内部
// sock.LocalAddr().(*net.UDPAddr) 在 nil 接收者上返回 nil ⇒ 裸类型断言
// **panic** ⇒ 没有 IPv6 的机器（NAS/容器常见）上一建会话就崩。
//
// 负对照：把 localPortOf 的 nil 判断去掉 ⇒ 本用例 panic 红。
func TestBuildCandidatesNilSocketNoPanic(t *testing.T) {
	if got := localPortOf(nil); got != 0 {
		t.Fatalf("localPortOf(nil) 应为 0，实际 %d", got)
	}
	if got := lanCandidates6(nil); got != nil {
		t.Fatalf("lanCandidates6(nil) 应为 nil，实际 %v", got)
	}
	if got := lanCandidates(nil); got != nil {
		t.Fatalf("lanCandidates(nil) 应为 nil，实际 %v", got)
	}

	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	c := &Client{opt: Options{Registry: "http://127.0.0.1:1"}, log: slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))}
	ci := c.buildCandidates(client, nil, "") // 无 v6 ⇒ 不得 panic
	if ci == nil {
		t.Fatalf("buildCandidates 返回空")
	}
}
