package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pigeonbox/p2p/internal/config"
	"github.com/pigeonbox/p2p/internal/registry"
	"github.com/pigeonbox/p2p/internal/store/memory"
)

// ---- 脚手架 ----

type testClient struct {
	t    *testing.T
	base *httptest.Server
}

type nodeKey struct {
	id   string
	priv ed25519.PrivateKey
}

func newNodeKey(t *testing.T) nodeKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return nodeKey{id: hex.EncodeToString(pub), priv: priv}
}

func (k nodeKey) sign(t *testing.T, parts ...string) string {
	t.Helper()
	return base64.StdEncoding.EncodeToString(ed25519.Sign(k.priv, registry.BuildPayload(parts...)))
}

func testConfig(adminPW string) config.Config {
	return config.Config{
		Server: config.Server{
			Port: 0, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second,
			IdleTimeout: 30 * time.Second, BehindProxy: false,
		},
		Registration: config.Registration{
			Mode: "open", MinNodeTTL: time.Minute, MaxNodeTTL: time.Hour,
		},
		Announce: config.Announce{MaxPerNode: 10, MaxTTL: time.Hour},
		Admin:    config.Admin{Password: adminPW},
		// 配对码:测试与生产同参(TTL 5min 级别不影响用例速度,过期路径走
		// mutate 注入短 TTL)
		Pairing: config.Pairing{
			Enabled: true, CodeTTL: 5 * time.Minute, SessionTTL: 10 * time.Minute,
			CodeLen: 4, MaxPerNode: 8, MaxTotal: 4096,
		},
		Log: config.Log{Level: "error"},
	}
}

func newTestServer(t *testing.T, mutate func(*config.Config)) (*httptest.Server, *Metrics) {
	t.Helper()
	cfg := testConfig("")
	if mutate != nil {
		mutate(&cfg)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	svc := registry.New(registry.Params{
		Store:          memory.New(),
		MinNodeTTL:     cfg.Registration.MinNodeTTL,
		MaxNodeTTL:     cfg.Registration.MaxNodeTTL,
		MaxAnnounces:   cfg.Announce.MaxPerNode,
		MaxAnnounceTTL: cfg.Announce.MaxTTL,
		RequireToken:   cfg.Registration.Token,
	})
	metrics := NewMetrics()
	var pairingSvc *registry.PairingService
	if cfg.Pairing.Enabled {
		pairingSvc = registry.NewPairingService(ctx, registry.PairingConfig{
			CodeTTL: cfg.Pairing.CodeTTL, SessionTTL: cfg.Pairing.SessionTTL,
			CodeLen: cfg.Pairing.CodeLen, MaxPerNode: cfg.Pairing.MaxPerNode,
			MaxTotal: cfg.Pairing.MaxTotal,
		}, svc)
	}
	srv := New(ctx, Params{Service: svc, Pairing: pairingSvc, Config: cfg, Metrics: metrics, Version: "test"})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, metrics
}

func (c testClient) do(method, path string, body any, headers map[string]string) (*http.Response, []byte) {
	c.t.Helper()
	var rd *strings.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			c.t.Fatal(err)
		}
		rd = strings.NewReader(string(b))
	} else {
		rd = strings.NewReader("")
	}
	req, err := http.NewRequest(method, c.base.URL+path, rd)
	if err != nil {
		c.t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		c.t.Fatal(err)
	}
	return resp, respBody
}

func (c testClient) register(k nodeKey, url string) *http.Response {
	c.t.Helper()
	ts := time.Now().Unix()
	body := map[string]any{
		"node_id": k.id, "url": url, "name": "t", "version": "v",
		"caps": []string{"download"}, "ttl_seconds": 600,
		"nonce": "n", "ts": ts,
		"sig": k.sign(c.t, k.id, url, "t", "v", "download", "600", "n", fmt.Sprint(ts)),
	}
	resp, _ := c.do(http.MethodPost, "/v1/nodes/register", body, nil)
	return resp
}

func (c testClient) announce(k nodeKey, code string) *http.Response {
	c.t.Helper()
	hash := registry.CodeHash(code)
	expires := time.Now().Add(time.Hour).Unix()
	ts := time.Now().Unix()
	body := map[string]any{
		"node_id": k.id, "code_hash": hash, "expires_at": expires,
		"size_hint": 0, "ts": ts,
		"sig": k.sign(c.t, k.id, hash, fmt.Sprint(expires), "0", fmt.Sprint(ts)),
	}
	resp, _ := c.do(http.MethodPost, "/v1/announces", body, nil)
	return resp
}

// ---- 用例 ----

func TestHealthAndMetrics(t *testing.T) {
	ts, _ := newTestServer(t, nil)
	c := testClient{t: t, base: ts}

	resp, body := c.do(http.MethodGet, "/health", nil, nil)
	if resp.StatusCode != 200 || !strings.Contains(string(body), `"status":"ok"`) {
		t.Fatalf("health: %d %s", resp.StatusCode, body)
	}
	resp, body = c.do(http.MethodGet, "/metrics", nil, nil)
	if resp.StatusCode != 200 || !strings.Contains(string(body), "p2p_nodes_active") {
		t.Fatalf("metrics: %d", resp.StatusCode)
	}
}

func TestFullLifecycleOverHTTP(t *testing.T) {
	ts, m := newTestServer(t, nil)
	c := testClient{t: t, base: ts}
	k := newNodeKey(t)

	if resp := c.register(k, "https://a.example.com"); resp.StatusCode != 200 {
		t.Fatalf("register: %d", resp.StatusCode)
	}
	// 心跳别名同语义
	resp, _ := c.do(http.MethodPost, "/v1/nodes/heartbeat", map[string]any{}, nil)
	if resp.StatusCode != 400 { // 缺字段 → 400,证明路由通
		t.Fatalf("heartbeat 路由: %d", resp.StatusCode)
	}

	if resp := c.announce(k, "http-code-1234567890"); resp.StatusCode != 200 {
		t.Fatalf("announce: %d", resp.StatusCode)
	}

	resp, body := c.do(http.MethodGet, "/v1/resolve/"+registry.CodeHash("http-code-1234567890"), nil, nil)
	if resp.StatusCode != 200 || !strings.Contains(string(body), "https://a.example.com") {
		t.Fatalf("resolve: %d %s", resp.StatusCode, body)
	}

	// GET 节点
	resp, _ = c.do(http.MethodGet, "/v1/nodes/"+k.id, nil, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("node get: %d", resp.StatusCode)
	}

	// 撤销
	tsNow := time.Now().Unix()
	hash := registry.CodeHash("http-code-1234567890")
	resp, _ = c.do(http.MethodDelete, "/v1/announces/"+hash,
		map[string]any{"node_id": k.id, "ts": tsNow, "sig": k.sign(t, k.id, hash, fmt.Sprint(tsNow))}, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("revoke: %d", resp.StatusCode)
	}

	resp, _ = c.do(http.MethodGet, "/v1/resolve/"+hash, nil, nil)
	if resp.StatusCode != 404 {
		t.Fatalf("撤销后 resolve 期望 404,得到 %d", resp.StatusCode)
	}

	// 注销
	tsNow = time.Now().Unix()
	resp, _ = c.do(http.MethodDelete, "/v1/nodes/"+k.id,
		map[string]any{"node_id": k.id, "ts": tsNow, "sig": k.sign(t, k.id, fmt.Sprint(tsNow))}, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("deregister: %d", resp.StatusCode)
	}
	if got := testGauge(t, m, "p2p_announces_active"); got != 0 {
		t.Fatalf("公告仪表应清零,得到 %v", got)
	}
}

func TestRegisterBadSignatureOverHTTP(t *testing.T) {
	ts, _ := newTestServer(t, nil)
	c := testClient{t: t, base: ts}
	k := newNodeKey(t)
	wrong := newNodeKey(t)

	tsNow := time.Now().Unix()
	body := map[string]any{
		"node_id": k.id, "url": "https://x.com", "ttl_seconds": 600,
		"nonce": "n", "ts": tsNow,
		"sig": wrong.sign(t, k.id, "https://x.com", "", "", "", "600", "n", fmt.Sprint(tsNow)),
	}
	resp, _ := c.do(http.MethodPost, "/v1/nodes/register", body, nil)
	if resp.StatusCode != 401 {
		t.Fatalf("坏签名期望 401,得到 %d", resp.StatusCode)
	}
}

func TestRateLimit429(t *testing.T) {
	ts, _ := newTestServer(t, nil)
	c := testClient{t: t, base: ts}
	// resolve 桶:突发 120;打满后必见 429
	sawLimit := false
	for i := 0; i < 200; i++ {
		resp, _ := c.do(http.MethodGet, "/v1/resolve/0000000000000000000000000000000000000000000000000000000000000000", nil, nil)
		if resp.StatusCode == 429 {
			sawLimit = true
			break
		}
	}
	if !sawLimit {
		t.Fatal("200 次请求未触发限流")
	}
}

func TestAdminAuth(t *testing.T) {
	// 未配置口令 → 403
	ts, _ := newTestServer(t, func(c *config.Config) { c.Admin.Password = "" })
	c := testClient{t: t, base: ts}
	resp, _ := c.do(http.MethodGet, "/v1/admin/stats", nil, nil)
	if resp.StatusCode != 403 {
		t.Fatalf("无口令期望 403,得到 %d", resp.StatusCode)
	}

	// 配置口令:错凭据 401,对凭据 200
	ts2, _ := newTestServer(t, func(c *config.Config) { c.Admin.Password = "pw" })
	c2 := testClient{t: t, base: ts2}
	resp, _ = c2.do(http.MethodGet, "/v1/admin/stats", nil, nil)
	if resp.StatusCode != 401 {
		t.Fatalf("错口令期望 401,得到 %d", resp.StatusCode)
	}
	resp, body := c2.do(http.MethodGet, "/v1/admin/stats", nil, map[string]string{"Authorization": "Bearer pw"})
	if resp.StatusCode != 200 || !strings.Contains(string(body), `"nodes":0`) {
		t.Fatalf("admin stats: %d %s", resp.StatusCode, body)
	}
}

func TestBehindProxyClientIP(t *testing.T) {
	ts, _ := newTestServer(t, func(c *config.Config) {
		c.Server.BehindProxy = true
		c.Admin.Password = "pw"
	})
	c := testClient{t: t, base: ts}
	k := newNodeKey(t)

	// IP 在注册时记录:XFF 首段应成为节点记录的 ip
	tsNow := time.Now().Unix()
	body := map[string]any{
		"node_id": k.id, "url": "https://b.example.com", "name": "t", "version": "v",
		"caps": []string{"download"}, "ttl_seconds": 600,
		"nonce": "n", "ts": tsNow,
		"sig": k.sign(t, k.id, "https://b.example.com", "t", "v", "download", "600", "n", fmt.Sprint(tsNow)),
	}
	resp, _ := c.do(http.MethodPost, "/v1/nodes/register", body, map[string]string{
		"X-Forwarded-For": "203.0.113.7, 10.0.0.1",
	})
	if resp.StatusCode != 200 {
		t.Fatalf("register: %d", resp.StatusCode)
	}
	_, list := c.do(http.MethodGet, "/v1/admin/nodes", nil, map[string]string{
		"Authorization": "Bearer pw",
	})
	// 首段是客户端自带可伪造的,末段才是可信反代 append 的真实来源
	if !strings.Contains(string(list), `"ip":"10.0.0.1"`) {
		t.Fatalf("应取 XFF 末段(反代追加段)为客户端 IP: %s", list)
	}
}

func TestClientIPXFFSemantics(t *testing.T) {
	mk := func(behindProxy bool, proxies []string) *Server {
		return &Server{cfg: config.Config{Server: config.Server{
			BehindProxy: behindProxy, TrustedProxies: proxies,
		}}}
	}
	req := func(remote, xff string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/v1/nodes/register", nil)
		r.RemoteAddr = remote
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		return r
	}

	t.Run("未开 behind_proxy 时忽略 XFF", func(t *testing.T) {
		s := mk(false, nil)
		if got := s.clientIP(req("10.0.0.1:5555", "203.0.113.7")); got != "10.0.0.1" {
			t.Fatalf("got %q", got)
		}
	})
	t.Run("behind_proxy 取末段(反代追加段)", func(t *testing.T) {
		s := mk(true, nil)
		if got := s.clientIP(req("10.0.0.1:5555", "203.0.113.7, 10.0.0.1")); got != "10.0.0.1" {
			t.Fatalf("got %q", got)
		}
		if got := s.clientIP(req("10.0.0.1:5555", "203.0.113.7")); got != "203.0.113.7" {
			t.Fatalf("got %q", got)
		}
	})
	t.Run("可信跳向左走,取第一个不可信地址", func(t *testing.T) {
		s := mk(true, []string{"10.0.0.0/8", "127.0.0.0/8"})
		// 10.0.0.1 是可信代理跳,继续向左
		if got := s.clientIP(req("10.0.0.1:5555", "1.2.3.4, 10.0.0.1")); got != "1.2.3.4" {
			t.Fatalf("got %q", got)
		}
		// 全部为可信跳:客户端直连可信代理,取最左段
		if got := s.clientIP(req("10.0.0.1:5555", "5.6.7.8, 10.0.0.2")); got != "5.6.7.8" {
			t.Fatalf("got %q", got)
		}
	})
	t.Run("直连对端不在可信网段则忽略 XFF", func(t *testing.T) {
		s := mk(true, []string{"192.168.0.0/16"})
		// RemoteAddr=10.0.0.1 不在可信网段,XFF 整体不采信
		if got := s.clientIP(req("10.0.0.1:5555", "1.2.3.4")); got != "10.0.0.1" {
			t.Fatalf("got %q", got)
		}
	})
	t.Run("畸形 XFF 段按不可信处理不 panic", func(t *testing.T) {
		s := mk(true, nil)
		if got := s.clientIP(req("10.0.0.1:5555", "not-an-ip, 10.0.0.1")); got != "10.0.0.1" {
			t.Fatalf("got %q", got)
		}
	})
}

func testGauge(t *testing.T, m *Metrics, name string) float64 {
	t.Helper()
	mfs, err := m.reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range mfs {
		if mf.GetName() == name && len(mf.GetMetric()) > 0 {
			return mf.GetMetric()[0].GetGauge().GetValue()
		}
	}
	t.Fatalf("指标 %s 未找到", name)
	return 0
}

func TestMetricsStrict(t *testing.T) {
	ts, _ := newTestServer(t, func(c *config.Config) {
		c.Metrics.Strict = true // 未配管理口令 + strict → 404 不暴露
	})
	c := testClient{t: t, base: ts}
	resp, _ := c.do(http.MethodGet, "/metrics", nil, nil)
	if resp.StatusCode != 404 {
		t.Fatalf("strict 模式未配口令应 404: %d", resp.StatusCode)
	}
	// 配了口令时 strict 不影响 adminGate 路径
	ts2, _ := newTestServer(t, func(c *config.Config) {
		c.Metrics.Strict = true
		c.Admin.Password = "pw"
	})
	c2 := testClient{t: t, base: ts2}
	resp, _ = c2.do(http.MethodGet, "/metrics", nil, map[string]string{"Authorization": "Bearer pw"})
	if resp.StatusCode != 200 {
		t.Fatalf("配口令后 metrics 应正常: %d", resp.StatusCode)
	}
}

func TestResolvePerHashRateLimit(t *testing.T) {
	ts, _ := newTestServer(t, nil)
	c := testClient{t: t, base: ts}
	hash := strings.Repeat("a", 64)
	// 单 hash 超过 10/s 突发 60 后必须 429(IP 维度限额远未触顶)
	var last int
	for i := 0; i < 70; i++ {
		resp, _ := c.do(http.MethodGet, "/v1/resolve/"+hash, nil, nil)
		last = resp.StatusCode
		if last == http.StatusTooManyRequests {
			return
		}
	}
	t.Fatalf("per-hash 限流未生效,最后状态 %d", last)
}

func TestHealthReportsRelayPort(t *testing.T) {
	base, _ := newTestServer(t, func(c *config.Config) { c.Relay.Port = 56787 })
	resp, err := http.Get(base.URL + "/health")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out struct {
		Status    string `json:"status"`
		RelayPort int    `json:"relay_port"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.Status != "ok" || out.RelayPort != 56787 {
		t.Fatalf("health = %+v, want status=ok relay_port=56787", out)
	}
}
