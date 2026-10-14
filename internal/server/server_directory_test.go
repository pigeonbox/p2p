package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"
)

// ---- GET /v1/directory(在线名录,2026-10-14) ----

const testBoxPubHex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

// registerDiscoverable 注册 discoverable 节点(扩展负载签名)。
func (c testClient) registerDiscoverable(k nodeKey) *http.Response {
	c.t.Helper()
	ts := time.Now().Unix()
	body := map[string]any{
		"node_id": k.id, "url": "http://direct.invalid", "name": "peer", "version": "v",
		"caps": []string{"direct"}, "ttl_seconds": 600,
		"nonce": "nd", "ts": ts,
		"discoverable": true, "public_url": "https://peer.example.com", "box_pub": testBoxPubHex,
		"sig": k.sign(c.t, k.id, "http://direct.invalid", "peer", "v", "direct", "600", "nd", fmt.Sprint(ts),
			"1", "https://peer.example.com", testBoxPubHex),
	}
	resp, _ := c.do(http.MethodPost, "/v1/nodes/register", body, nil)
	return resp
}

func TestDirectoryEndpointOptInOnly(t *testing.T) {
	ts, _ := newTestServer(t, nil)
	c := testClient{t: t, base: ts}

	hidden := newNodeKey(t)
	if resp := c.register(hidden, "https://hidden.example.com"); resp.StatusCode != http.StatusOK {
		t.Fatalf("旧格式注册失败: %d %s", resp.StatusCode, resp.Body)
	}
	visible := newNodeKey(t)
	if resp := c.registerDiscoverable(visible); resp.StatusCode != http.StatusOK {
		t.Fatalf("discoverable 注册失败: %d %s", resp.StatusCode, resp.Body)
	}

	resp, body := c.do(http.MethodGet, "/v1/directory", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("名录查询失败: %d %s", resp.StatusCode, body)
	}
	var out struct {
		Nodes []struct {
			NodeID      string `json:"node_id"`
			Name        string `json:"name"`
			URL         string `json:"url"`
			BoxPub      string `json:"box_pub"`
			OnlineSince int64  `json:"online_since"`
		} `json:"nodes"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Nodes) != 1 {
		t.Fatalf("名录应仅含 opt-in 节点,实得 %d: %s", len(out.Nodes), body)
	}
	n := out.Nodes[0]
	if n.NodeID != visible.id || n.BoxPub != testBoxPubHex ||
		n.URL != "https://peer.example.com" || n.OnlineSince <= 0 {
		t.Fatalf("名录条目字段不符: %+v", n)
	}
}

func TestDirectoryEndpointForgedPresenceRejected(t *testing.T) {
	ts, _ := newTestServer(t, nil)
	c := testClient{t: t, base: ts}
	k := newNodeKey(t)
	ts2 := time.Now().Unix()
	// 带扩展字段但旧负载签名 → 401
	body := map[string]any{
		"node_id": k.id, "url": "http://direct.invalid", "name": "evil", "version": "v",
		"caps": []string{"direct"}, "ttl_seconds": 600,
		"nonce": "ne", "ts": ts2,
		"discoverable": true, "box_pub": testBoxPubHex,
		"sig": k.sign(t, k.id, "http://direct.invalid", "evil", "v", "download", "600", "ne", fmt.Sprint(ts2)),
	}
	resp, _ := c.do(http.MethodPost, "/v1/nodes/register", body, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("伪造扩展字段应 401,实得 %d", resp.StatusCode)
	}
}

func TestMailboxEndpointsRoundtrip(t *testing.T) {
	ts, _ := newTestServer(t, nil)
	c := testClient{t: t, base: ts}
	k := newNodeKey(t)
	if resp := c.register(k, "http://direct.invalid"); resp.StatusCode != http.StatusOK {
		t.Fatalf("注册失败: %d", resp.StatusCode)
	}

	const fromHex = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	// 投递(纯密文,服务端不验内容)
	resp, body := c.do(http.MethodPost, "/v1/mailbox/"+k.id, map[string]any{
		"from": fromHex, "nonce": "b(nonNzb24NCg==", "boxed": "Ym94ZWQ=",
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("投递失败: %d %s", resp.StatusCode, body)
	}
	// 弹出(取后即删)
	resp, body = c.do(http.MethodGet, "/v1/mailbox/"+k.id, nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("弹出失败: %d %s", resp.StatusCode, body)
	}
	var out struct {
		Entries []struct {
			From  string `json:"from"`
			Nonce string `json:"nonce"`
			Boxed string `json:"boxed"`
			TS    int64  `json:"ts"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Entries) != 1 || out.Entries[0].Boxed != "Ym94ZWQ=" || out.Entries[0].TS <= 0 {
		t.Fatalf("弹出条目不符: %s", body)
	}
	_, body = c.do(http.MethodGet, "/v1/mailbox/"+k.id, nil, nil)
	if err := json.Unmarshal(body, &out); err != nil || len(out.Entries) != 0 {
		t.Fatalf("取后即删违反: %s", body)
	}
}

func TestMailboxEndpointUnknownNode404(t *testing.T) {
	ts, _ := newTestServer(t, nil)
	c := testClient{t: t, base: ts}
	const ghost = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	resp, _ := c.do(http.MethodPost, "/v1/mailbox/"+ghost, map[string]any{
		"from": ghost, "nonce": "n", "boxed": "Yg==",
	}, nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("投递到未注册节点应 404,实得 %d", resp.StatusCode)
	}
}
