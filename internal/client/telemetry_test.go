package client

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pigeonbox/p2p/internal/directpolicy"
	"github.com/pigeonbox/p2p/internal/registry"
)

// ---- ① 网络环境分桶 ----

// TestClassifyNetClass 网络环境分桶判定(纯函数)。
//
// 负对照:把 CGNAT(100.64/10)判成公网、或把私网判成公网 ⇒ 运营商 NAT
// 后的家庭宽带会被算进「公网直连率极高」那桶,结论直接反了 ⇒ 本用例逐值
// 断言三个分桶。
func TestClassifyNetClass(t *testing.T) {
	addrs := func(ss ...string) []netip.Addr {
		t.Helper()
		var out []netip.Addr
		for _, s := range ss {
			a, err := netip.ParseAddr(s)
			if err != nil {
				t.Fatalf("地址非法 %q: %v", s, err)
			}
			out = append(out, a)
		}
		return out
	}
	cases := []struct {
		name string
		in   []netip.Addr
		want string
	}{
		{"公网地址", addrs("203.0.113.10"), netPublic},
		{"私网地址", addrs("192.168.1.5"), netNAT},
		{"十进制私网", addrs("10.0.0.7"), netNAT},
		{"ULA 私网(v6)", addrs("fd00::1"), netNAT},
		{"CGNAT 归 NAT 侧", addrs("100.64.0.1"), netNAT},
		{"回环与链路本地=未知", addrs("127.0.0.1", "fe80::1"), netUnknown},
		{"公网优先于私网", addrs("192.168.1.5", "203.0.113.10"), netPublic},
		{"IPv4-mapped 私网", addrs("::ffff:192.168.1.5"), netNAT},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyNetClass(tc.in); got != tc.want {
				t.Fatalf("分桶 = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestLocalNetClassInWhitelist 本机分桶枚举只可能落在三个白名单取值内。
//
// 负对照:分桶函数返回自由文本(比如把地址直接塞进去)⇒ 该用例立刻变红。
func TestLocalNetClassInWhitelist(t *testing.T) {
	got := localNetClass()
	switch got {
	case netPublic, netNAT, netUnknown:
	default:
		t.Fatalf("本机分桶 = %q,不在白名单内", got)
	}
}

// ---- ② 上报载荷:分桶 + 脱敏 + 耗时 ----

// waitBodies 等异步遥测上报落地(上报是异步的)。
func waitBodies(t *testing.T, mu *sync.Mutex, bodies *[]map[string]any, want int) []map[string]any {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(*bodies)
		mu.Unlock()
		if n >= want {
			mu.Lock()
			out := append([]map[string]any(nil), (*bodies)...)
			mu.Unlock()
			return out
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("等待 %d 条遥测上报超时", want)
	return nil
}

// TestReportSessionCarriesBucketAndDuration 上报必须带上网络分桶与耗时,
// 且分桶落在白名单内(直连成功率按网络类型分桶的数据来源)。
//
// 负对照:把 net 传成空串(或传自由文本)⇒ 分桶维度消失/基数失控。
func TestReportSessionCarriesBucketAndDuration(t *testing.T) {
	var mu sync.Mutex
	var bodies []map[string]any
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		mu.Lock()
		bodies = append(bodies, m)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	c, err := New(Options{Registry: ts.URL, NodeKeyPath: t.TempDir() + "/k", Quiet: true})
	if err != nil {
		t.Fatal(err)
	}
	rep := newSessionReporter(ts.URL)
	c.reportSession(rep, registry.TelemetryRelayFallback, "", "direct_failed", 1500*time.Millisecond)

	got := waitBodies(t, &mu, &bodies, 1)[0]
	if got["kind"] != registry.TelemetryRelayFallback {
		t.Fatalf("kind = %v", got["kind"])
	}
	if got["reason"] != "direct_failed" {
		t.Fatalf("reason = %v", got["reason"])
	}
	if got["dur_ms"] != float64(1500) {
		t.Fatalf("dur_ms = %v, want 1500", got["dur_ms"])
	}
	netv, _ := got["net"].(string)
	switch netv {
	case netPublic, netNAT, netUnknown:
	default:
		t.Fatalf("net 分桶 = %q,不在白名单内", netv)
	}
}

// TestReportSessionDesensitized 上报载荷不得含任何地址(IP/前缀/端口)。
//
// 负对照:把本机地址或对端地址塞进 path/reason/net ⇒ 本用例变红。
func TestReportSessionDesensitized(t *testing.T) {
	var mu sync.Mutex
	var raw string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		raw = string(b)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	c, err := New(Options{Registry: ts.URL, NodeKeyPath: t.TempDir() + "/k", Quiet: true})
	if err != nil {
		t.Fatal(err)
	}
	rep := newSessionReporter(ts.URL)
	c.reportSession(rep, registry.TelemetryEstablished, "punch", "", 0)

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		got := raw
		mu.Unlock()
		if got != "" {
			raw = got
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if raw == "" {
		t.Fatal("遥测未落地")
	}
	// 载荷里不得有点分十进制地址
	if re := regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`); re.MatchString(raw) {
		t.Fatalf("载荷含 IPv4 地址: %s", raw)
	}
	// 载荷里不得出现本机任何网卡地址
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, ifi := range ifaces {
		list, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range list {
			if strings.Contains(raw, a.String()) {
				t.Fatalf("载荷含本机地址 %q: %s", a.String(), raw)
			}
		}
	}
	// 只允许白名单键(没有自由文本字段)
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatalf("载荷非法: %v", err)
	}
	allowed := map[string]bool{
		"node_id": true, "kind": true, "path": true, "reason": true,
		"net": true, "dur_ms": true, "ts": true, "sig": true,
	}
	for k := range m {
		if !allowed[k] {
			t.Fatalf("载荷含非白名单字段 %q: %s", k, raw)
		}
	}
}

// TestReportSessionSkipsEmptyBase regBase 为空(单测/未知基址)时不上报——
// 不发请求、不 panic。
func TestReportSessionSkipsEmptyBase(t *testing.T) {
	var mu sync.Mutex
	hits := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	c, err := New(Options{Registry: ts.URL, NodeKeyPath: t.TempDir() + "/k", Quiet: true})
	if err != nil {
		t.Fatal(err)
	}
	rep := newSessionReporter("")
	c.reportSession(rep, registry.TelemetryEstablished, "relay", "", 0)
	c.reportSession(rep, registry.TelemetryFailed, "", "relay_failed", 0)
	time.Sleep(100 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if hits != 0 {
		t.Fatalf("空基址仍上报了 %d 次", hits)
	}
}

// TestReportSessionBucketsSuccessFallbackFailure 成功/回退/失败三类事件
// 各落各桶:kind/path/reason 各自归位,同一会话的网络分桶一致。
//
// 负对照:把三类事件错标(比如回退事件报成 established)⇒ 直连成功率口径
// 整体失真,而「有上报」类断言不会发现 ⇒ 必须逐类断言。
func TestReportSessionBucketsSuccessFallbackFailure(t *testing.T) {
	var mu sync.Mutex
	var bodies []map[string]any
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		mu.Lock()
		bodies = append(bodies, m)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	c, err := New(Options{Registry: ts.URL, NodeKeyPath: t.TempDir() + "/k", Quiet: true})
	if err != nil {
		t.Fatal(err)
	}
	rep := newSessionReporter(ts.URL)
	c.reportSession(rep, registry.TelemetryEstablished, "punch", "", 0)
	c.reportSession(rep, registry.TelemetryRelayFallback, "", "direct_failed", 1200*time.Millisecond)
	c.reportSession(rep, registry.TelemetryFailed, "", "punch_failed", 0)

	got := waitBodies(t, &mu, &bodies, 3)
	byKind := map[string]map[string]any{}
	for _, b := range got {
		kind, _ := b["kind"].(string)
		if _, dup := byKind[kind]; dup {
			t.Fatalf("kind %q 重复上报", kind)
		}
		byKind[kind] = b
	}
	// 成功:established/punch
	ok, present := byKind[registry.TelemetryEstablished]
	if !present {
		t.Fatal("缺 established 上报")
	}
	if ok["path"] != "punch" {
		t.Fatalf("established path = %v, want punch", ok["path"])
	}
	if ok["reason"] != "" {
		t.Fatalf("established 不应带 reason: %v", ok["reason"])
	}
	// 回退:relay_fallback/direct_failed + 回退触发耗时
	fb, present := byKind[registry.TelemetryRelayFallback]
	if !present {
		t.Fatal("缺 relay_fallback 上报")
	}
	if fb["reason"] != "direct_failed" {
		t.Fatalf("relay_fallback reason = %v, want direct_failed", fb["reason"])
	}
	if fb["dur_ms"] != float64(1200) {
		t.Fatalf("relay_fallback dur_ms = %v, want 1200", fb["dur_ms"])
	}
	// 失败:failed/punch_failed
	fl, present := byKind[registry.TelemetryFailed]
	if !present {
		t.Fatal("缺 failed 上报")
	}
	if fl["reason"] != "punch_failed" {
		t.Fatalf("failed reason = %v, want punch_failed", fl["reason"])
	}
	// 三类事件落在**同一个会话分桶**里,且分桶取值合法
	var netv string
	for _, b := range got {
		v, _ := b["net"].(string)
		switch v {
		case netPublic, netNAT, netUnknown:
		default:
			t.Fatalf("net 分桶 = %q,不在白名单内", v)
		}
		if netv == "" {
			netv = v
		} else if netv != v {
			t.Fatalf("同一会话分桶不一致: %q vs %q", netv, v)
		}
	}
}

// ---- ③ 回退原因分类 ----

// TestFallbackReasonClassification 回退原因必须逐值正确(打洞失败 vs 直连失败)。
//
// 负对照:两个分支写反 ⇒ 分布整体对调,而「有上报」类断言不会发现。
func TestFallbackReasonClassification(t *testing.T) {
	if got := fallbackReason(false); got != "punch_failed" {
		t.Fatalf("打洞失败分类 = %q, want punch_failed", got)
	}
	if got := fallbackReason(true); got != "direct_failed" {
		t.Fatalf("直连失败分类 = %q, want direct_failed", got)
	}
}

// ---- ④ 直传策略:缺省=今日行为 ----

// directPolicyEnvKeys 直传策略的环境变量键(测试里逐个清空以保证缺省口径)。
var directPolicyEnvKeys = []string{
	"PB_P2P_DIRECT_FAST_PUNCH_BUDGET",
	"PB_P2P_DIRECT_PUNCH_BUDGET",
	"PB_P2P_DIRECT_RELAY_PROBE_TIMEOUT",
	"PB_P2P_DIRECT_RELAY_FALLBACK_ENABLED",
}

// clearDirectPolicyEnv 清空策略环境变量(空值按未设置处理)。
func clearDirectPolicyEnv(t *testing.T) {
	t.Helper()
	for _, k := range directPolicyEnvKeys {
		t.Setenv(k, "")
	}
}

// TestDirectPolicyDefaultsUnchanged 缺省取值必须逐字等于 2026-11-15 前的
// 硬编码行为(1.5s 快打洞 / 4s 长打洞 / 2s 中继探测 / 允许回退中继)。
//
// 负对照:任一缺省被改动 ⇒ 本用例变红(这就是「不配置时行为与今天完全一致」
// 的证明)。
func TestDirectPolicyDefaultsUnchanged(t *testing.T) {
	clearDirectPolicyEnv(t)
	d, warns := directpolicy.Load()
	if len(warns) != 0 {
		t.Fatalf("缺省不应告警: %v", warns)
	}
	if d.FastPunchBudget != 1500*time.Millisecond {
		t.Fatalf("快打洞预算缺省 = %s, want 1.5s", d.FastPunchBudget)
	}
	if d.PunchBudget != 4*time.Second {
		t.Fatalf("长打洞预算缺省 = %s, want 4s", d.PunchBudget)
	}
	if d.RelayProbeTimeout != 2*time.Second {
		t.Fatalf("中继探测超时缺省 = %s, want 2s", d.RelayProbeTimeout)
	}
	if !d.RelayFallbackEnabled {
		t.Fatal("中继回退缺省应为启用")
	}
}

// TestDirectPolicyEnvOverrideAndClamp 环境变量可覆盖;非法取值钳回缺省并告警。
//
// 负对照:布尔项手误("flase")若被当成 false ⇒ 中继回退被静默关掉 ⇒ 本用例
// 变红。
func TestDirectPolicyEnvOverrideAndClamp(t *testing.T) {
	clearDirectPolicyEnv(t)
	t.Setenv("PB_P2P_DIRECT_FAST_PUNCH_BUDGET", "800ms")
	t.Setenv("PB_P2P_DIRECT_RELAY_FALLBACK_ENABLED", "false")
	d, warns := directpolicy.Load()
	if len(warns) != 0 {
		t.Fatalf("合法取值不应告警: %v", warns)
	}
	if d.FastPunchBudget != 800*time.Millisecond {
		t.Fatalf("快打洞预算 = %s, want 800ms", d.FastPunchBudget)
	}
	if d.RelayFallbackEnabled {
		t.Fatal("中继回退应被显式关闭")
	}

	// 非法取值 ⇒ 钳回缺省 + 告警
	t.Setenv("PB_P2P_DIRECT_FAST_PUNCH_BUDGET", "not-a-duration")
	d, warns = directpolicy.Load()
	if len(warns) == 0 {
		t.Fatal("非法取值应告警")
	}
	if d.FastPunchBudget != 1500*time.Millisecond {
		t.Fatalf("非法快打洞预算未回退缺省: %s", d.FastPunchBudget)
	}

	// 布尔项手误("flase")⇒ 折回缺省(true)**且必须告警**:
	// 静默关掉中继回退会让「打不通就换中继」的兜底消失,传输直接失败。
	t.Setenv("PB_P2P_DIRECT_FAST_PUNCH_BUDGET", "800ms")
	t.Setenv("PB_P2P_DIRECT_RELAY_FALLBACK_ENABLED", "flase")
	d, warns = directpolicy.Load()
	if len(warns) == 0 {
		t.Fatal("非法布尔取值应告警")
	}
	if !d.RelayFallbackEnabled {
		t.Fatal("非法布尔取值不得关掉中继回退")
	}
}

// TestClientAppliesPolicy 客户端实际吃到的策略 = 环境变量/显式指定。
//
// 负对照:New 里忘读策略(策略改了行为不变)⇒ 本用例变红。
func TestClientAppliesPolicy(t *testing.T) {
	clearDirectPolicyEnv(t)
	t.Setenv("PB_P2P_DIRECT_FAST_PUNCH_BUDGET", "900ms")
	t.Setenv("PB_P2P_DIRECT_RELAY_PROBE_TIMEOUT", "3s")

	c, err := New(Options{Registry: "http://127.0.0.1:1", NodeKeyPath: t.TempDir() + "/k", Quiet: true})
	if err != nil {
		t.Fatal(err)
	}
	if c.opt.Direct.FastPunchBudget != 900*time.Millisecond {
		t.Fatalf("客户端快打洞预算 = %s, want 900ms", c.opt.Direct.FastPunchBudget)
	}
	if c.opt.Direct.RelayProbeTimeout != 3*time.Second {
		t.Fatalf("客户端中继探测 = %s, want 3s", c.opt.Direct.RelayProbeTimeout)
	}
	// 打洞预算:未显式指定 ⇒ 取策略缺省 4s
	if c.opt.PunchBudget != 4*time.Second {
		t.Fatalf("客户端打洞预算 = %s, want 4s", c.opt.PunchBudget)
	}

	// 显式指定的打洞预算优先于策略值(测试/诊断场景)
	c2, err := New(Options{Registry: "http://127.0.0.1:1", NodeKeyPath: t.TempDir() + "/k", Quiet: true, PunchBudget: 45 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if c2.opt.PunchBudget != 45*time.Second {
		t.Fatalf("显式打洞预算被覆盖: %s", c2.opt.PunchBudget)
	}
}

// TestClientDefaultBehaviorUnchanged 不配置任何策略时,客户端行为参数与
// 2026-11-15 前的硬编码逐字一致。
func TestClientDefaultBehaviorUnchanged(t *testing.T) {
	clearDirectPolicyEnv(t)
	c, err := New(Options{Registry: "http://127.0.0.1:1", NodeKeyPath: t.TempDir() + "/k", Quiet: true})
	if err != nil {
		t.Fatal(err)
	}
	if c.opt.Direct.FastPunchBudget != 1500*time.Millisecond {
		t.Fatalf("快打洞预算 = %s, want 1.5s", c.opt.Direct.FastPunchBudget)
	}
	if c.opt.Direct.RelayProbeTimeout != 2*time.Second {
		t.Fatalf("中继探测 = %s, want 2s", c.opt.Direct.RelayProbeTimeout)
	}
	if c.opt.PunchBudget != 4*time.Second {
		t.Fatalf("打洞预算 = %s, want 4s", c.opt.PunchBudget)
	}
	if !c.opt.Direct.RelayFallbackEnabled {
		t.Fatal("中继回退应默认启用")
	}
}

// ---- ⑤ 契约:上报报文能被服务端契约接受(含旧客户端兼容) ----

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
	if err := reg.telemetry(t.Context(), id, registry.TelemetryEstablished, "punch", "", netNAT, 0); err != nil {
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
	if got.Net != netNAT {
		t.Fatalf("net = %q, want %q", got.Net, netNAT)
	}
}

// TestLegacyTelemetryStillAccepted 旧客户端(v1 签名负载、不带 net/dur_ms)
// 的上报仍被服务端契约接受——混合版本车队里旧 p2pc 的遥测不能丢。
//
// 负对照:删掉 registry 侧的 v1 回落分支 ⇒ 本用例变红。
func TestLegacyTelemetryStillAccepted(t *testing.T) {
	id, err := newNodeIdentity(t.TempDir() + "/node.key")
	if err != nil {
		t.Fatal(err)
	}
	ts := time.Now().Unix()
	in := registry.TelemetryInput{
		NodeID: id.id,
		Kind:   registry.TelemetryEstablished,
		Path:   "punch",
		TS:     ts,
		Sig:    id.sign(registry.BuildLegacyTelemetryPayload(id.id, registry.TelemetryEstablished, "punch", "", ts)),
	}
	if err := in.Validate(); err != nil {
		t.Fatalf("旧报文契约拒绝: %v", err)
	}
	if err := in.TelemetrySign(time.Now()); err != nil {
		t.Fatalf("旧报文验签拒绝: %v", err)
	}
	// 带维度的事件不得用旧负载签名(否则同一事件两套可接受签名)。
	in2 := in
	in2.Net = netPublic
	if err := in2.TelemetrySign(time.Now()); err == nil {
		t.Fatal("带 net 的事件不应接受 v1 签名")
	}
}
