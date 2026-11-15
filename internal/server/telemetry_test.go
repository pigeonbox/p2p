package server

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/pigeonbox/p2p/internal/registry"
)

// testCounter 读计数器(带 label 精确匹配;未打点返回 0)。
func testCounter(t *testing.T, m *Metrics, name string, labels map[string]string) float64 {
	t.Helper()
	mfs, err := m.reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		for _, met := range mf.GetMetric() {
			if len(met.GetLabel()) != len(labels) {
				continue
			}
			match := true
			for _, lp := range met.GetLabel() {
				if want, ok := labels[lp.GetName()]; !ok || want != lp.GetValue() {
					match = false
				}
			}
			if match {
				return met.GetCounter().GetValue()
			}
		}
	}
	return 0
}

// telemetryBody 构造合法签名的遥测请求体。
func telemetryBody(t *testing.T, k nodeKey, kind, path, reason string) map[string]any {
	t.Helper()
	ts := time.Now().Unix()
	return map[string]any{
		"node_id": k.id, "kind": kind, "path": path, "reason": reason,
		"ts": ts, "sig": k.sign(t, k.id, kind, path, reason, fmt.Sprint(ts)),
	}
}

// TestTelemetrySession 端点主链:注册存在 + 打点后读数正确。
func TestTelemetrySession(t *testing.T) {
	ts, m := newTestServer(t, nil)
	c := testClient{t: t, base: ts}
	k := newNodeKey(t)

	// 打点后读数正确:path=punch 计 1
	resp, body := c.do(http.MethodPost, "/v1/telemetry/session", telemetryBody(t, k, registry.TelemetryEstablished, "punch", ""), nil)
	if resp.StatusCode != 200 {
		t.Fatalf("established 上报: %d %s", resp.StatusCode, body)
	}
	if got := testCounter(t, m, "p2p_session_established_total", map[string]string{"path": "punch"}); got != 1 {
		t.Fatalf("punch 读数 = %v, want 1", got)
	}

	// relay/fallback 路径各自独立计数
	_, _ = c.do(http.MethodPost, "/v1/telemetry/session", telemetryBody(t, k, registry.TelemetryEstablished, "relay", ""), nil)
	_, _ = c.do(http.MethodPost, "/v1/telemetry/session", telemetryBody(t, k, registry.TelemetryEstablished, "relay", ""), nil)
	_, _ = c.do(http.MethodPost, "/v1/telemetry/session", telemetryBody(t, k, registry.TelemetryEstablished, "fallback", ""), nil)
	if got := testCounter(t, m, "p2p_session_established_total", map[string]string{"path": "relay"}); got != 2 {
		t.Fatalf("relay 读数 = %v, want 2", got)
	}
	if got := testCounter(t, m, "p2p_session_established_total", map[string]string{"path": "fallback"}); got != 1 {
		t.Fatalf("fallback 读数 = %v, want 1", got)
	}

	// 失败与回退打点
	_, _ = c.do(http.MethodPost, "/v1/telemetry/session", telemetryBody(t, k, registry.TelemetryFailed, "", "punch_failed"), nil)
	_, _ = c.do(http.MethodPost, "/v1/telemetry/session", telemetryBody(t, k, registry.TelemetryRelayFallback, "", "direct_failed"), nil)
	_, _ = c.do(http.MethodPost, "/v1/telemetry/session", telemetryBody(t, k, registry.TelemetryRelayFallback, "", "punch_failed"), nil)
	if got := testCounter(t, m, "p2p_session_failed_total", map[string]string{"reason": "punch_failed"}); got != 1 {
		t.Fatalf("failed 读数 = %v, want 1", got)
	}
	if got := testCounter(t, m, "p2p_relay_fallback_total", map[string]string{"reason": "direct_failed"}); got != 1 {
		t.Fatalf("fallback(direct_failed) 读数 = %v, want 1", got)
	}
	if got := testCounter(t, m, "p2p_relay_fallback_total", map[string]string{"reason": "punch_failed"}); got != 1 {
		t.Fatalf("fallback(punch_failed) 读数 = %v, want 1", got)
	}

	// 注册存在:/metrics 含三个新指标名。
	// (CounterVec 无子序列时不出序列,故检查放在全部打点之后)
	resp, body = c.do(http.MethodGet, "/metrics", nil, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("metrics: %d", resp.StatusCode)
	}
	for _, name := range []string{"p2p_session_established_total", "p2p_session_failed_total", "p2p_relay_fallback_total"} {
		if !strings.Contains(string(body), name) {
			t.Fatalf("指标 %s 未注册于 /metrics", name)
		}
	}
}

// TestTelemetryWhitelist 枚举白名单:集合外取值 400 且不打点(label 注入防线)。
func TestTelemetryWhitelist(t *testing.T) {
	ts, m := newTestServer(t, nil)
	c := testClient{t: t, base: ts}
	k := newNodeKey(t)

	cases := []struct {
		name string
		body map[string]any
	}{
		// path 带对端地址形态 → 拒(脱敏铁律:自由文本进不了 label)
		{"path 自由文本", map[string]any{"node_id": k.id, "kind": "established", "path": "punch(1.2.3.4:56789)", "ts": time.Now().Unix()}},
		{"path 缺失", map[string]any{"node_id": k.id, "kind": "established", "ts": time.Now().Unix()}},
		{"kind 未知", map[string]any{"node_id": k.id, "kind": "exploded", "ts": time.Now().Unix()}},
		{"reason 自由文本", map[string]any{"node_id": k.id, "kind": "failed", "reason": "dial 10.0.0.1:22 refused", "ts": time.Now().Unix()}},
		{"reason 集合外交叉", map[string]any{"node_id": k.id, "kind": "relay_fallback", "reason": "relay_failed", "ts": time.Now().Unix()}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, body := c.do(http.MethodPost, "/v1/telemetry/session", tc.body, nil)
			if resp.StatusCode != 400 {
				t.Fatalf("want 400, got %d %s", resp.StatusCode, body)
			}
		})
	}
	// 白名单拒绝不打点
	if got := testCounter(t, m, "p2p_session_established_total", map[string]string{"path": "punch"}); got != 0 {
		t.Fatalf("白名单拒绝却打了点: %v", got)
	}
}

// TestTelemetrySignature 坏签名/过期时间窗拒绝(写面必须带调用方签名)。
func TestTelemetrySignature(t *testing.T) {
	ts, m := newTestServer(t, nil)
	c := testClient{t: t, base: ts}
	k := newNodeKey(t)
	other := newNodeKey(t)

	// 用别人的身份签 → 401
	b := telemetryBody(t, k, registry.TelemetryEstablished, "punch", "")
	b["node_id"] = other.id // 签名按 k 的身份造,node_id 换掉即验签失败
	resp, body := c.do(http.MethodPost, "/v1/telemetry/session", b, nil)
	if resp.StatusCode != 401 {
		t.Fatalf("want 401, got %d %s", resp.StatusCode, body)
	}

	// 过期时间窗 → 400
	old := time.Now().Add(-time.Hour).Unix()
	b2 := map[string]any{
		"node_id": k.id, "kind": registry.TelemetryEstablished, "path": "punch",
		"ts": old, "sig": k.sign(t, k.id, registry.TelemetryEstablished, "punch", "", fmt.Sprint(old)),
	}
	resp, body = c.do(http.MethodPost, "/v1/telemetry/session", b2, nil)
	if resp.StatusCode != 400 {
		t.Fatalf("过期 ts want 400, got %d %s", resp.StatusCode, body)
	}

	if got := testCounter(t, m, "p2p_session_established_total", map[string]string{"path": "punch"}); got != 0 {
		t.Fatalf("非法上报却打了点: %v", got)
	}
}
