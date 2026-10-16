// ui.go — p2pc 终端人性化输出层（2026-10-16 易用性）。
//
// TTY 直连终端时：slog 整形为「· 消息 k=v」行；「传输进度」记录不刷屏，
// 渲染成单行原位进度条（百分比/速度/ETA，\r 原位更新）。非 TTY（管道/
// 重定向/CI）返回 nil——保持 slog 默认格式（可 grep）；--json 模式由调用方
// 跳过（NDJSON 面不受影响）。

package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/term"
)

// uiLineWidth 原位进度条按 80 列保守渲染（不探测终端宽度——窄终端截断
// 即可，宽终端留白无害）。
const uiLineWidth = 78

// uiSample 速度采样点。
type uiSample struct {
	t   time.Time
	got int64
}

// uiHandler 终端整形 handler（仅 TTY 构造）。
type uiHandler struct {
	w   io.Writer
	mu  *sync.Mutex
	dir string // ⇡ send | ⇣ recv（原位行方向符号）

	active     bool // 进度行在屏上（后续输出须先清行）
	lastGot    int64
	lastTotal  int64
	samples    []uiSample // 近 ~2.5s 采样窗
	lastRender string
}

// newUIHandler stderr 为 TTY 时返回整形 handler；否则 (nil, nil)。
func newUIHandler(w *os.File) (slog.Handler, func()) {
	if w == nil || !term.IsTerminal(int(w.Fd())) {
		return nil, nil
	}
	h := &uiHandler{w: w, mu: &sync.Mutex{}}
	return h, h.clear
}

// uiSetDirection 设置原位进度方向符号（send ⇡ / recv ⇣）。
func (h *uiHandler) setDirection(dir string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if dir == "send" {
		h.dir = "⇡"
	} else {
		h.dir = "⇣"
	}
}

// clear 清掉在屏进度行（收尾/让位其他输出）。
func (h *uiHandler) clear() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.active {
		_, _ = fmt.Fprint(h.w, "\r"+strings.Repeat(" ", uiLineWidth)+"\r")
		h.active = false
	}
}

func (h *uiHandler) Enabled(_ context.Context, l slog.Level) bool { return l >= slog.LevelInfo }

func (h *uiHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if r.Message == "传输进度" {
		var got, total int64
		r.Attrs(func(a slog.Attr) bool {
			switch a.Key {
			case "got":
				got = a.Value.Int64()
			case "total":
				total = a.Value.Int64()
			}
			return true
		})
		h.updateLocked(got, total)
		_, _ = fmt.Fprint(h.w, "\r"+h.renderLocked())
		h.active = true
		return nil
	}
	// 普通日志:先清进度行,打完再让位（下一次进度记录会重画）
	if h.active {
		_, _ = fmt.Fprint(h.w, "\r"+strings.Repeat(" ", uiLineWidth)+"\r")
		h.active = false
	}
	var b strings.Builder
	switch {
	case r.Level >= slog.LevelError:
		b.WriteString("✗ ")
	case r.Level >= slog.LevelWarn:
		b.WriteString("⚠ ")
	default:
		b.WriteString("· ")
	}
	b.WriteString(r.Message)
	r.Attrs(func(a slog.Attr) bool {
		b.WriteString("  " + a.Key + "=" + a.Value.String())
		return true
	})
	_, _ = fmt.Fprintln(h.w, strings.TrimRight(b.String(), " "))
	return nil
}

func (h *uiHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *uiHandler) WithGroup(string) slog.Handler      { return h }

// updateLocked 记录采样并维护速度窗（调用方持锁）。
func (h *uiHandler) updateLocked(got, total int64) {
	now := time.Now()
	if got < h.lastGot && total == h.lastTotal && total > 0 {
		return // 单调闸：重试期回绕/双流乱序防御
	}
	h.lastGot, h.lastTotal = got, total
	h.samples = append(h.samples, uiSample{t: now, got: got})
	cut := now.Add(-2500 * time.Millisecond)
	i := 0
	for i < len(h.samples) && h.samples[i].t.Before(cut) {
		i++
	}
	h.samples = append([]uiSample(nil), h.samples[i:]...)
}

// renderLocked 原位进度行（调用方持锁）：
//
//	⇡ 45% [========>           ]  8.2 MB/s · 剩 0:12
//	⇣ 已传 6.0 MB …（总量未知时不定态）
func (h *uiHandler) renderLocked() string {
	dir := h.dir
	if dir == "" {
		dir = "⇣"
	}
	if h.lastTotal <= 0 {
		return truncatePad(fmt.Sprintf("%s 已传 %s …", dir, humanBytes(h.lastGot)))
	}
	pct := float64(h.lastGot) / float64(h.lastTotal) * 100
	if pct > 100 {
		pct = 100
	}
	barW := 22
	filled := int(pct / 100 * float64(barW))
	bar := strings.Repeat("=", filled)
	if filled < barW {
		bar += ">"
		bar += strings.Repeat(" ", barW-filled-1)
	}
	line := fmt.Sprintf("%s %3.0f%% [%s]", dir, pct, bar)
	if sp := h.speedLocked(); sp > 0 {
		line += fmt.Sprintf(" %s/s", humanBytes(int64(sp)))
		if left := time.Duration(float64(h.lastTotal-h.lastGot) / sp * float64(time.Second)); left > 0 {
			line += " · 剩 " + fmtMMSS(int(left.Seconds()))
		}
	}
	line += "  " + humanBytes(h.lastGot) + "/" + humanBytes(h.lastTotal)
	return truncatePad(line)
}

// speedLocked 窗口差分速度（字节/秒；窗口不足 400ms 时报 0——宁缺毋滥）。
func (h *uiHandler) speedLocked() float64 {
	if len(h.samples) < 2 {
		return 0
	}
	first, last := h.samples[0], h.samples[len(h.samples)-1]
	dt := last.t.Sub(first.t).Seconds()
	if dt < 0.4 || last.got <= first.got {
		return 0
	}
	return float64(last.got-first.got) / dt
}

// truncatePad 定宽截断+右侧补空（抹掉上一帧残留）。
func truncatePad(s string) string {
	if len(s) > uiLineWidth {
		s = s[:uiLineWidth]
	}
	return s + strings.Repeat(" ", uiLineWidth-len(s)) + "\r"
}

func humanBytes(n int64) string {
	const u = "BKMGT"
	f, i := float64(n), 0
	for f >= 1024 && i < len(u)-1 {
		f /= 1024
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%d B", n)
	}
	return fmt.Sprintf("%.1f %ciB", f, u[i])
}

func fmtMMSS(s int) string {
	if s < 0 {
		s = 0
	}
	if s < 60 {
		return fmt.Sprintf("0:%02d", s)
	}
	return fmt.Sprintf("%d:%02d", s/60, s%60)
}
