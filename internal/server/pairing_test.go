package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/pigeonbox/p2p/internal/config"
)

// ---- 配对码 HTTP 契约测试 ----

func pairCreateBody(t *testing.T, k nodeKey, secret string) map[string]any {
	t.Helper()
	ts := time.Now().Unix()
	return map[string]any{
		"node_id": k.id, "secret": secret, "ts": ts,
		"sig": k.sign(t, "pair-create", k.id, secret, fmt.Sprint(ts)),
	}
}

func TestPairFlowOverHTTP(t *testing.T) {
	ts, _ := newTestServer(t, nil)
	c := testClient{t: t, base: ts}
	creator, claimant, other := newNodeKey(t), newNodeKey(t), newNodeKey(t)
	for _, k := range []nodeKey{creator, claimant, other} {
		if resp := c.register(k, "https://x.example.com"); resp.StatusCode != 200 {
			t.Fatalf("register: %d", resp.StatusCode)
		}
	}

	// create
	resp, body := c.do(http.MethodPost, "/v1/pair", pairCreateBody(t, creator, "SECRETXSECRETX12"), nil)
	if resp.StatusCode != 200 {
		t.Fatalf("pair create: %d %s", resp.StatusCode, body)
	}
	var created struct {
		Code string `json:"code"`
		TTL  int64  `json:"ttl"`
	}
	if err := json.Unmarshal(body, &created); err != nil || created.Code == "" || created.TTL != 300 {
		t.Fatalf("create 响应异常: %s err=%v", body, err)
	}
	code := created.Code

	claimBody := func(k nodeKey, claimID string) map[string]any {
		ts := time.Now().Unix()
		return map[string]any{
			"node_id": k.id, "code": code, "claim_id": claimID, "ts": ts,
			"sig": k.sign(t, "pair-claim", k.id, code, claimID, fmt.Sprint(ts)),
		}
	}
	approveBody := func(k nodeKey, decision, claimer string) map[string]any {
		ts := time.Now().Unix()
		return map[string]any{
			"node_id": k.id, "code": code, "decision": decision, "claimer": claimer, "ts": ts,
			"sig": k.sign(t, "pair-approve", k.id, code, decision, claimer, fmt.Sprint(ts)),
		}
	}

	// 未知码 404(客户端据此回退口令解析)
	resp, _ = c.do(http.MethodPost, "/v1/pair/claim", func() map[string]any {
		ts := time.Now().Unix()
		return map[string]any{
			"node_id": claimant.id, "code": "9999", "claim_id": "x", "ts": ts,
			"sig": claimant.sign(t, "pair-claim", claimant.id, "9999", "x", fmt.Sprint(ts)),
		}
	}(), nil)
	if resp.StatusCode != 404 {
		t.Fatalf("未知码应 404, 实际 %d", resp.StatusCode)
	}

	// claim → pending
	resp, body = c.do(http.MethodPost, "/v1/pair/claim", claimBody(claimant, "c1"), nil)
	if resp.StatusCode != 200 {
		t.Fatalf("claim: %d %s", resp.StatusCode, body)
	}
	var res struct {
		Status    string `json:"status"`
		ExpiresIn int64  `json:"expires_in"`
	}
	_ = json.Unmarshal(body, &res)
	if res.Status != "pending" || res.ExpiresIn <= 0 {
		t.Fatalf("claim 应 pending 带剩余窗: %s", body)
	}

	// requests 应见 claimant
	resp, body = c.do(http.MethodPost, "/v1/pair/requests", func() map[string]any {
		ts := time.Now().Unix()
		return map[string]any{
			"node_id": creator.id, "ts": ts,
			"sig": creator.sign(t, "pair-requests", creator.id, fmt.Sprint(ts)),
		}
	}(), nil)
	if resp.StatusCode != 200 {
		t.Fatalf("requests: %d %s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), claimant.id[:12]) {
		t.Fatalf("requests 应含 claimant: %s", body)
	}

	// 第三人抢入 → 409
	resp, _ = c.do(http.MethodPost, "/v1/pair/claim", claimBody(other, "hijack"), nil)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("抢入应 409, 实际 %d", resp.StatusCode)
	}

	// approve → granted 一次性兑换
	resp, _ = c.do(http.MethodPost, "/v1/pair/approve", approveBody(creator, "accept", claimant.id), nil)
	if resp.StatusCode != 200 {
		t.Fatalf("approve: %d", resp.StatusCode)
	}
	resp, body = c.do(http.MethodPost, "/v1/pair/claim", claimBody(claimant, "c1"), nil)
	if resp.StatusCode != 200 || !strings.Contains(string(body), "SECRETXSECRETX12") || !strings.Contains(string(body), `"granted"`) {
		t.Fatalf("兑换应返回 secret: %d %s", resp.StatusCode, body)
	}
	// 出表后重复轮询 404
	resp, _ = c.do(http.MethodPost, "/v1/pair/claim", claimBody(claimant, "c1"), nil)
	if resp.StatusCode != 404 {
		t.Fatalf("兑换后应 404, 实际 %d", resp.StatusCode)
	}
}

func TestPairDenyOverHTTP(t *testing.T) {
	ts, _ := newTestServer(t, nil)
	c := testClient{t: t, base: ts}
	creator, claimant := newNodeKey(t), newNodeKey(t)
	for _, k := range []nodeKey{creator, claimant} {
		if resp := c.register(k, "https://x.example.com"); resp.StatusCode != 200 {
			t.Fatalf("register: %d", resp.StatusCode)
		}
	}
	resp, body := c.do(http.MethodPost, "/v1/pair", pairCreateBody(t, creator, "SECRETXSECRETX12"), nil)
	if resp.StatusCode != 200 {
		t.Fatalf("create: %d %s", resp.StatusCode, body)
	}
	var created struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(body, &created)
	code := created.Code

	claim := func() map[string]any {
		ts := time.Now().Unix()
		return map[string]any{
			"node_id": claimant.id, "code": code, "claim_id": "c1", "ts": ts,
			"sig": claimant.sign(t, "pair-claim", claimant.id, code, "c1", fmt.Sprint(ts)),
		}
	}
	if resp, _ = c.do(http.MethodPost, "/v1/pair/claim", claim(), nil); resp.StatusCode != 200 {
		t.Fatalf("claim: %d", resp.StatusCode)
	}
	now := time.Now().Unix()
	deny := map[string]any{
		"node_id": creator.id, "code": code, "decision": "deny", "claimer": claimant.id, "ts": now,
		"sig": creator.sign(t, "pair-approve", creator.id, code, "deny", claimant.id, fmt.Sprint(now)),
	}
	if resp, _ = c.do(http.MethodPost, "/v1/pair/approve", deny, nil); resp.StatusCode != 200 {
		t.Fatalf("deny: %d", resp.StatusCode)
	}
	if resp, _ = c.do(http.MethodPost, "/v1/pair/claim", claim(), nil); resp.StatusCode != 404 {
		t.Fatalf("拒绝后轮询应 404, 实际 %d", resp.StatusCode)
	}
}

func TestPairDisabledConfigOverHTTP(t *testing.T) {
	ts, _ := newTestServer(t, func(cfg *config.Config) { cfg.Pairing.Enabled = false })
	c := testClient{t: t, base: ts}
	k := newNodeKey(t)
	resp, _ := c.do(http.MethodPost, "/v1/pair", pairCreateBody(t, k, "SECRETXSECRETX12"), nil)
	if resp.StatusCode != 404 {
		t.Fatalf("pairing 关闭时应 404, 实际 %d", resp.StatusCode)
	}
}

func TestPairClaimRateLimited(t *testing.T) {
	ts, _ := newTestServer(t, nil)
	c := testClient{t: t, base: ts}
	k := newNodeKey(t)
	if resp := c.register(k, "https://x.example.com"); resp.StatusCode != 200 {
		t.Fatalf("register: %d", resp.StatusCode)
	}
	// burst 30:第 31 连发应 429(body 无需合法——限流在 decode 前)
	last := 0
	for i := 0; i < 31; i++ {
		resp, _ := c.do(http.MethodPost, "/v1/pair/claim", map[string]any{"junk": true}, nil)
		last = resp.StatusCode
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("第 31 连发应 429, 实际 %d", last)
	}
}
