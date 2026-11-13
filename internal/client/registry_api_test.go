package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// validNodeID 64 字符 hex(Ed25519 公钥),满足 node_id 形态。
const validNodeID = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// newResolveStub 假注册中心:/v1/resolve/* 按给定状态码 + 报文回(无需真 p2pd)。
func newResolveStub(t *testing.T, status int, body string) *registryAPI {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/v1/resolve/") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return newRegistryAPI(srv.URL)
}

// TestResolveRejectsIllegalNodeID 200 + 缺/坏 node_id 必须当失败(p2p#41):
// 否则 Receive 的 HRW failover 链被第一个「200 但没 node_id」的端点静默截断
// (client.go Receive:err==nil 即认准该节点 break,不顺延、不进重试窗口),
// 且 expectedPeer="" 把「注册中心报文非法」误报成「身份核对失败」。
func TestResolveRejectsIllegalNodeID(t *testing.T) {
	cases := []struct {
		name    string
		status  int
		body    string
		wantErr bool
	}{
		{"缺字段_200空对象", http.StatusOK, `{}`, true},
		{"空node_id_200", http.StatusOK, `{"node_id":""}`, true},
		{"字段不符_非hex", http.StatusOK, `{"node_id":"not-a-node-id"}`, true},
		{"字段不符_长度不足", http.StatusOK, `{"node_id":"abcd"}`, true},
		{"合法node_id_200", http.StatusOK, `{"node_id":"` + validNodeID + `"}`, false},
		{"网关500", http.StatusInternalServerError, `{"error":"boom"}`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			api := newResolveStub(t, tc.status, tc.body)
			id, err := api.resolve(context.Background(), "ABCD-EFGH-JKMN")
			if tc.wantErr {
				if err == nil {
					t.Fatalf("期望报错,得到 id=%q err=nil", id)
				}
				if id != "" {
					t.Fatalf("报错时不得回传 node_id,得到 %q", id)
				}
				return
			}
			if err != nil {
				t.Fatalf("合法 node_id 不应报错: %v", err)
			}
			if id != validNodeID {
				t.Fatalf("node_id 不符: 得到 %q", id)
			}
		})
	}
}

// TestResolveRetryFailsOverOnMissingNodeID resolveRetry 是 Receive failover 的
// 触发器:err==nil 即认准该节点(不顺延、4s 重试窗口不生效)。200+{} 必须让
// 重试真正走到超时并回 err —— 这正是「触发 failover 而非当成功」的断言点。
func TestResolveRetryFailsOverOnMissingNodeID(t *testing.T) {
	api := newResolveStub(t, http.StatusOK, `{}`)
	var c Client
	id, err := c.resolveRetry(api, "ABCD-EFGH-JKMN", 50*time.Millisecond)
	if err == nil {
		t.Fatalf("期望超时报错,得到 id=%q err=nil", id)
	}
	if id != "" {
		t.Fatalf("报错时不得回传 node_id,得到 %q", id)
	}
}
