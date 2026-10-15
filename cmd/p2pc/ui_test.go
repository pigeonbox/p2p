package main

// 终端 UI 层单测：原位进度行渲染（百分比/速度/ETA/不定态）、单调闸、
// 行宽封顶、日志整形前缀。TTY 探测在 newUIHandler 构造层,此处直接
// 构造 handler 以 bytes.Buffer 驱动。

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

func newTestUI() (*uiHandler, *bytes.Buffer) {
	var buf bytes.Buffer
	h := &uiHandler{w: &buf, mu: &sync.Mutex{}, dir: "⇣"}
	return h, &buf
}

func TestUIRenderDeterminate(t *testing.T) {
	h, _ := newTestUI()
	now := time.Now()
	h.samples = []uiSample{{t: now.Add(-2 * time.Second), got: 0}, {t: now, got: 5 << 20}}
	h.lastGot, h.lastTotal = 5<<20, 10<<20

	out := h.renderLocked()
	for _, want := range []string{"⇣  50%", "2.5 MiB/s", "剩 0:02", "5.0 MiB/10.0 MiB", "[" + strings.Repeat("=", 11) + ">"} {
		if !strings.Contains(out, want) {
			t.Errorf("进度行缺 %q:\n%q", want, out)
		}
	}
	if len(out) < uiLineWidth {
		t.Errorf("进度行应补空至定宽(抹上一帧残留): %d", len(out))
	}
}

func TestUIRenderIndeterminate(t *testing.T) {
	h, _ := newTestUI()
	h.lastGot, h.lastTotal = 3<<20, 0
	out := h.renderLocked()
	if !strings.Contains(out, "已传 3.0 MiB") || strings.Contains(out, "%") {
		t.Errorf("不定态应无百分比只报已传: %q", out)
	}
}

func TestUIUpdateMonotonic(t *testing.T) {
	h, _ := newTestUI()
	h.updateLocked(100, 1000)
	h.updateLocked(50, 1000) // 回绕拒绝
	if h.lastGot != 100 {
		t.Fatalf("回绕样本应被拒: got=%d", h.lastGot)
	}
	h.updateLocked(100, 2000) // total 变化(新传输段)放行
	if h.lastGot != 100 || h.lastTotal != 2000 {
		t.Fatalf("total 变化应放行: got=%d total=%d", h.lastGot, h.lastTotal)
	}
}

func TestUISpeedWindowTooShort(t *testing.T) {
	h, _ := newTestUI()
	now := time.Now()
	h.samples = []uiSample{{t: now, got: 0}, {t: now.Add(100 * time.Millisecond), got: 1 << 20}}
	if sp := h.speedLocked(); sp != 0 {
		t.Fatalf("窗口 <400ms 应报 0 速度, got %f", sp)
	}
}

func TestUILogLinePrefixes(t *testing.T) {
	h, buf := newTestUI()
	rec := slog.NewRecord(time.Now(), slog.LevelInfo, "对端已接入,开始 PAKE", 0)
	if err := h.Handle(context.Background(), rec); err != nil {
		t.Fatal(err)
	}
	rec = slog.NewRecord(time.Now(), slog.LevelError, "中继接入失败", 0)
	rec.AddAttrs(slog.String("err", "timeout"))
	if err := h.Handle(context.Background(), rec); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "· 对端已接入,开始 PAKE\n") {
		t.Errorf("信息行应 · 前缀: %q", out)
	}
	if !strings.Contains(out, "✗ 中继接入失败  err=timeout\n") {
		t.Errorf("错误行应 ✗ 前缀+attrs: %q", out)
	}
	if strings.Contains(out, "level=") || strings.Contains(out, "time=") {
		t.Errorf("不应残留 slog 结构化前缀: %q", out)
	}
}

func TestUIProgressRecordRendersInPlace(t *testing.T) {
	h, buf := newTestUI()
	rec := slog.NewRecord(time.Now(), slog.LevelInfo, "传输进度", 0)
	rec.AddAttrs(slog.Int64("got", 1<<20), slog.Int64("total", 4<<20))
	if err := h.Handle(context.Background(), rec); err != nil {
		t.Fatal(err)
	}
	if !h.active {
		t.Fatal("进度记录后应在屏")
	}
	out := buf.String()
	if !strings.Contains(out, "\r") || !strings.Contains(out, "25%") {
		t.Errorf("进度记录应原位渲染 25%%: %q", out)
	}
	// 随后普通日志先清行
	rec2 := slog.NewRecord(time.Now(), slog.LevelInfo, "传输通道建立", 0)
	if err := h.Handle(context.Background(), rec2); err != nil {
		t.Fatal(err)
	}
	if h.active {
		t.Fatal("普通日志后进度行应让位")
	}
	if !strings.Contains(buf.String(), "· 传输通道建立\n") {
		t.Errorf("普通日志应整形输出: %q", buf.String())
	}
}

func TestHumanBytesAndMMSS(t *testing.T) {
	if humanBytes(0) != "0 B" || humanBytes(1<<20) != "1.0 MiB" || humanBytes(1536) != "1.5 KiB" {
		t.Fatalf("humanBytes 形态异常: %q %q %q", humanBytes(0), humanBytes(1<<20), humanBytes(1536))
	}
	if fmtMMSS(5) != "0:05" || fmtMMSS(75) != "1:15" {
		t.Fatalf("fmtMMSS 异常: %q %q", fmtMMSS(5), fmtMMSS(75))
	}
}
