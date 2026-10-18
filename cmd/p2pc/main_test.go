package main

import (
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
)

// TestRecvCodeFromEnv "p2pc recv -" 从 PB_P2P_CODE 读口令（argv 不留码，
// 同机 ps 不可见——server supervisor 硬化通道，2026-10-14 安全评审留位项）。
func TestRecvCodeFromEnv(t *testing.T) {
	t.Setenv("PB_P2P_CODE", "kj8y-wcyz-e249")
	got, err := resolveRecvCode([]string{"-"})
	if err != nil || got != "KJ8Y-WCYZ-E249" {
		t.Fatalf("got=%q err=%v", got, err)
	}
	// 位置参数直传兼容（desktop/CLI 现状）
	t.Setenv("PB_P2P_CODE", "")
	got, err = resolveRecvCode([]string{"abcd-efgh-jkmn"})
	if err != nil || got != "ABCD-EFGH-JKMN" {
		t.Fatalf("positional got=%q err=%v", got, err)
	}
	// "-" 但 env 空 → 报错
	if _, err = resolveRecvCode([]string{"-"}); err == nil {
		t.Fatal("env 空应报错")
	}
}

// captureStdout 捕获 fn 的 stdout 输出。
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	fn()
	_ = w.Close()
	os.Stdout = old
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

// TestPrintCodeFormat 口令行格式锁——server supervisor(p2px.scanLines)与
// desktop sidecar 都按 "口令: XXXX-XXXX-XXXX" 解析 stdout,此格式即契约,
// 变更必须同步(本测试红=下游解析器同步改)。
func TestPrintCodeFormat(t *testing.T) {
	got := captureStdout(t, func() { printCode("ABCD-1234-WXYZ") })
	if !strings.Contains(got, "口令: ABCD-1234-WXYZ\n") {
		t.Fatalf("口令行格式漂移: %q", got)
	}
	if !strings.Contains(got, "p2pc recv ABCD-1234-WXYZ") {
		t.Fatalf("接收提示行漂移: %q", got)
	}
}

// TestJSONEventShape --json 事件形态锁(NDJSON:单行合法 JSON,event 字段在场)。
func TestJSONEventShape(t *testing.T) {
	jsonOut = true
	t.Cleanup(func() { jsonOut = false })
	got := captureStdout(t, func() {
		emitEvent("code", map[string]any{"code": "ABCD-1234-WXYZ"})
		emitEvent("done", map[string]any{"kind": "recv", "files": 1, "paths": []string{"/a/b"}})
	})
	lines := strings.Split(strings.TrimSpace(got), "\n")
	if len(lines) != 2 {
		t.Fatalf("应两行事件: %q", got)
	}
	for i, ln := range lines {
		var m map[string]any
		if err := json.Unmarshal([]byte(ln), &m); err != nil {
			t.Fatalf("行%d 非 JSON: %q", i, ln)
		}
		if m["event"] == nil {
			t.Fatalf("行%d 缺 event 字段: %q", i, ln)
		}
	}
	if !strings.Contains(lines[0], `"code":"ABCD-1234-WXYZ"`) {
		t.Fatalf("code 事件形态漂移: %q", lines[0])
	}
	// 非 JSON 模式静默
	jsonOut = false
	if out := captureStdout(t, func() { emitEvent("code", nil) }); out != "" {
		t.Fatalf("非 JSON 模式应静默: %q", out)
	}
}

func TestGateDecision(t *testing.T) {
	accept := []string{"", "y", "Y", "yes", "YES\n", "y\n"}
	for _, in := range accept {
		if !gateDecision(in) {
			t.Fatalf("%q 应接受", in)
		}
	}
	deny := []string{"n", "n\n", "no", "Y n", "随便"}
	for _, in := range deny {
		if gateDecision(in) {
			t.Fatalf("%q 应拒绝", in)
		}
	}
}
