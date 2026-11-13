package reflect

import (
	"context"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// recHandler 记录型 slog.Handler:断言 Serve 是否留了日志。
type recHandler struct {
	mu      sync.Mutex
	records []slog.Record
}

func (h *recHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *recHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, r)
	return nil
}

func (h *recHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *recHandler) WithGroup(string) slog.Handler      { return h }

// errorMsgs 返回 Error 级记录的文案。
func (h *recHandler) errorMsgs() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []string
	for _, r := range h.records {
		if r.Level >= slog.LevelError {
			out = append(out, r.Message)
		}
	}
	return out
}

func (h *recHandler) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.records)
}

// p2p#39 正判据:非超时读错误(套接字已关/EMFILE/ENOBUFS 等)不得静默退出。
// 此前 Serve 直接 return 且签名无 error、调用方闭包拿不到任何东西 ⇒ p2pd 活着
// 但打洞前提全网失效、日志零线索。
func TestServeLogsNonTimeoutReadError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	_ = udp.Close() // 后续 ReadFromUDP 返回 use of closed network connection(非 net.Error.Timeout())

	h := &recHandler{}
	Serve(ctx, udp, slog.New(h)) // 同步调用:必须返回,不挂死

	msgs := h.errorMsgs()
	if len(msgs) == 0 {
		t.Fatal("非超时读错误必须留 Error 日志(当前行为:静默退出,运维零线索)")
	}
	found := false
	for _, m := range msgs {
		if strings.Contains(m, "反射器") {
			found = true
		}
	}
	if !found {
		t.Fatalf("日志应点名反射器退出,得到: %v", msgs)
	}
}

// p2p#39 语义边界①:关机路径(ctx 已取消)保持静默——那是设计的退出方式,
// 不是故障;把关机也打成 Error 会让告警噪声淹没真实故障。
func TestServeSilentOnShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	h := &recHandler{}
	// 取消后关闭套接字:无论 Serve 走 select 的 ctx.Done 分支还是读错误分支,
	// ctx 已取消 ⇒ 一律静默返回。
	cancel()
	_ = udp.Close()
	Serve(ctx, udp, slog.New(h))
	if n := h.count(); n != 0 {
		t.Fatalf("关机路径不得打日志,得到 %d 条", n)
	}
}

// p2p#39 语义边界②:健康空闲连接上的周期性读超时(1s 读截止)是轮询语义,
// 不是故障——不得被打成 Error,否则每秒一条刷屏、真实故障被淹没。
func TestServeQuietOnReadTimeout(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = udp.Close() }()

	h := &recHandler{}
	done := make(chan struct{})
	go func() {
		Serve(ctx, udp, slog.New(h))
		close(done)
	}()
	// ≥1 个 1s 读截止周期:期间只应发生超时 continue。
	time.Sleep(1500 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("cancel 后 Serve 必须退出")
	}
	if n := h.count(); n != 0 {
		t.Fatalf("读超时不得打日志(轮询语义),得到 %d 条", n)
	}
}
