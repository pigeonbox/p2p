package client

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pigeonbox/p2p/internal/registry"
)

// TestRegistryAPITelemetry 上报报文必须能被服务端契约(registry.TelemetryInput)
// 原样接受:字段齐 + 签名验过 + 时间窗内——防两端签名字节漂移。
func TestRegistryAPITelemetry(t *testing.T) {
	var got registry.TelemetryInput
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/telemetry/session" {
			t.Errorf("路径 = %s", r.URL.Path)
		}
		raw, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Errorf("报文非法: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	id, err := newNodeIdentity(t.TempDir() + "/node.key")
	if err != nil {
		t.Fatal(err)
	}
	reg := newRegistryAPI(ts.URL)
	if err := reg.telemetry(t.Context(), id, registry.TelemetryEstablished, "punch", ""); err != nil {
		t.Fatalf("上报: %v", err)
	}
	// 服务端契约视角:validate + 验签 + 时间窗全过
	if err := got.Validate(); err != nil {
		t.Fatalf("服务端契约拒绝: %v", err)
	}
	if err := got.TelemetrySign(time.Now()); err != nil {
		t.Fatalf("验签/时间窗拒绝: %v", err)
	}
	if got.NodeID != id.id {
		t.Fatalf("node_id = %s, want %s", got.NodeID, id.id)
	}
}

// TestReportSessionSkipsEmptyBase regBase 为空(单测/未知基址)时不上报——
// 不发请求、不 panic。
func TestReportSessionSkipsEmptyBase(t *testing.T) {
	c, err := New(Options{Registry: "http://127.0.0.1:1", NodeKeyPath: t.TempDir() + "/k", Quiet: true})
	if err != nil {
		t.Fatal(err)
	}
	c.reportSession("", registry.TelemetryEstablished, "relay", "")
	c.reportSession("", registry.TelemetryFailed, "", "relay_failed")
	// 返回即完成(空 base 是同步短路),无泄漏可断言
}
