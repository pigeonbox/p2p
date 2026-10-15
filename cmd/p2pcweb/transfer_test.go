package main

// 传输编排单测:进度标记行解析 + 子进程日志整形(进度走标记行,不进日志面)
// + Manager.pipe 的事件分流(结构化 progress 与普通日志互不串扰)。

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func TestParseProgressLine(t *testing.T) {
	cases := []struct {
		line       string
		got, total int64
		ok         bool
	}{
		{"P2PCWEB-PROGRESS got=1048576 total=10485760", 1048576, 10485760, true},
		{"P2PCWEB-PROGRESS got=0 total=0", 0, 0, true},
		{"P2PCWEB-PROGRESS got=42", 42, 0, true},
		{"P2PCWEB-PROGRESS total=7 got=3", 3, 7, true},
		{"P2PCWEB-PROGRESS", 0, 0, false},
		{"P2PCWEB-PROGRESS got=abc total=1", 0, 1, false},
		{"· 传输进度  got=1  total=2", 0, 0, false}, // 日志面形态,不识别
		{"P2PCWEB-DONE /tmp/x", 0, 0, false},
		{"", 0, 0, false},
	}
	for _, c := range cases {
		got, total, ok := parseProgressLine(c.line)
		if ok != c.ok || got != c.got || total != c.total {
			t.Errorf("parseProgressLine(%q) = (%d,%d,%v), want (%d,%d,%v)",
				c.line, got, total, ok, c.got, c.total, c.ok)
		}
	}
}

// TestPrettyHandler 普通日志人类可读;「传输进度」记录必须转标记行。
func TestPrettyHandler(t *testing.T) {
	var buf bytes.Buffer
	h := &prettyHandler{w: &buf}
	log := slog.New(h)

	log.Info("传输通道建立", "via", "relay")
	log.Warn("非回环监听")
	log.Error("中继接入失败", "err", "timeout")
	log.Info("传输进度", "got", 1<<20, "total", 10<<20)

	out := buf.String()
	for _, want := range []string{
		"· 传输通道建立  via=relay\n",
		"⚠ 非回环监听\n",
		"✗ 中继接入失败  err=timeout\n",
		"P2PCWEB-PROGRESS got=1048576 total=10485760\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("输出缺 %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "level=") || strings.Contains(out, "time=") {
		t.Errorf("不应残留 slog 结构化前缀:\n%s", out)
	}
}

// TestPipeProgressRouting 喂混合行,断言 progress 结构化事件与日志事件分流。
func TestPipeProgressRouting(t *testing.T) {
	m := NewManager()
	ch := m.Subscribe()
	defer m.Unsubscribe(ch)

	r := strings.NewReader(strings.Join([]string{
		"· 公告就绪  base=http://r",
		"P2PCWEB-PROGRESS got=100 total=200",
		"· 传输通道建立  via=quic-direct(v4)",
		"P2PCWEB-DONE /tmp/out/file.bin",
	}, "\n"))
	go m.pipe(r)

	read := func() Event {
		select {
		case ev := <-ch:
			return ev
		case <-time.After(2 * time.Second):
			t.Fatal("2s 内未收到事件")
			return Event{}
		}
	}

	ev := read()
	if ev.Type != "log" || !strings.Contains(ev.Line, "公告就绪") {
		t.Fatalf("第一条应为日志, got %+v", ev)
	}
	ev = read()
	if ev.Type != "progress" || ev.Got != 100 || ev.Total != 200 {
		t.Fatalf("第二条应为结构化进度, got %+v", ev)
	}
	ev = read()
	if ev.Type != "log" || !strings.Contains(ev.Line, "传输通道建立") {
		t.Fatalf("第三条应为日志, got %+v", ev)
	}
	// DONE 不广播,消费面只剩后续事件;此处应再无事件
	select {
	case ev := <-ch:
		t.Fatalf("DONE 不应产生事件, got %+v", ev)
	case <-time.After(150 * time.Millisecond):
	}
}
