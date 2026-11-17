package server

import (
	"fmt"
	"strings"
	"testing"

	"github.com/pigeonbox/p2p/internal/registry"
)

// seriesCount 统计某指标族的序列数(不含直方图子指标)。
func seriesCount(t *testing.T, m *Metrics, name string) int {
	t.Helper()
	mfs, err := m.reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, mf := range mfs {
		if mf.GetName() == name {
			n += len(mf.GetMetric())
		}
	}
	return n
}

// labelValues 收集某指标族全部序列的标签取值(用于脱敏/基数断言)。
func labelValues(t *testing.T, m *Metrics, name string) []string {
	t.Helper()
	mfs, err := m.reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		for _, met := range mf.GetMetric() {
			for _, lp := range met.GetLabel() {
				out = append(out, lp.GetValue())
			}
		}
	}
	return out
}

// TestMetricsByNetRecords 分桶指标按 (路径|原因|结果) × 网络分桶落点。
//
// 负对照:分桶维度写死成单一取值(或 net 未透传)⇒ 直连成功率按网络类型
// 分桶的口径消失,本用例变红。
func TestMetricsByNetRecords(t *testing.T) {
	m := NewMetrics()
	m.SessionEstablishedByNet("punch", registry.NetNAT)
	m.SessionEstablishedByNet("punch", registry.NetNAT)
	m.SessionEstablishedByNet("relay", registry.NetPublic)
	m.SessionFailedByNet("punch_failed", registry.NetNAT)
	m.RelayFallbackByNet("direct_failed", registry.NetPublic)
	m.DirectUpgrade(registry.UpgradeUpgraded, registry.NetNAT)

	if got := testCounter(t, m, "p2p_session_established_by_net_total", map[string]string{"path": "punch", "net": registry.NetNAT}); got != 2 {
		t.Fatalf("punch/nat 读数 = %v, want 2", got)
	}
	if got := testCounter(t, m, "p2p_session_established_by_net_total", map[string]string{"path": "relay", "net": registry.NetPublic}); got != 1 {
		t.Fatalf("relay/public 读数 = %v, want 1", got)
	}
	if got := testCounter(t, m, "p2p_session_failed_by_net_total", map[string]string{"reason": "punch_failed", "net": registry.NetNAT}); got != 1 {
		t.Fatalf("failed/nat 读数 = %v, want 1", got)
	}
	if got := testCounter(t, m, "p2p_relay_fallback_by_net_total", map[string]string{"reason": "direct_failed", "net": registry.NetPublic}); got != 1 {
		t.Fatalf("fallback/public 读数 = %v, want 1", got)
	}
	if got := testCounter(t, m, "p2p_direct_upgrade_total", map[string]string{"result": registry.UpgradeUpgraded, "net": registry.NetNAT}); got != 1 {
		t.Fatalf("upgrade/nat 读数 = %v, want 1", got)
	}
}

// TestMetricsCardinalityCap 灌入大量不同维度后,序列数不得增长(基数封顶)。
//
// 封顶策略:标签取值在**指标层**归一(registry.NormalizeTelemetry*):
// net 只有 public|nat|unknown 三选一,path/reason 白名单外一律折进 other
// ⇒ 每个指标族的序列数上界 = 白名单大小 × 3。
//
// 负对照:去掉指标层归一(直接 WithLabelValues(原始值))⇒ 本用例变红
// (序列数随灌入维度线性增长 ⇒ Prometheus 标签爆炸)。
func TestMetricsCardinalityCap(t *testing.T) {
	m := NewMetrics()
	for i := 0; i < 1000; i++ {
		m.SessionEstablishedByNet(fmt.Sprintf("punch-%d", i), fmt.Sprintf("10.0.0.%d", i%256))
		m.SessionFailedByNet(fmt.Sprintf("err-%d", i), fmt.Sprintf("evil-%d", i))
		m.RelayFallbackByNet(fmt.Sprintf("fb-%d", i), fmt.Sprintf("x%d", i))
		m.RelayFallbackDuration(fmt.Sprintf("fb-%d", i), fmt.Sprintf("x%d", i), int64(i))
		m.DirectUpgrade(fmt.Sprintf("up-%d", i), fmt.Sprintf("x%d", i))
		m.DirectUpgradeDuration(fmt.Sprintf("up-%d", i), fmt.Sprintf("x%d", i), int64(i))
	}

	// 上界:path/reason 白名单 3 项 + other = 4;net 恒 3 项。
	if got := seriesCount(t, m, "p2p_session_established_by_net_total"); got > 4*3 {
		t.Fatalf("established 分桶序列数 = %d,超过上界 %d", got, 4*3)
	}
	if got := seriesCount(t, m, "p2p_session_failed_by_net_total"); got > 4*3 {
		t.Fatalf("failed 分桶序列数 = %d,超过上界 %d", got, 4*3)
	}
	if got := seriesCount(t, m, "p2p_relay_fallback_by_net_total"); got > 3*3 {
		t.Fatalf("fallback 分桶序列数 = %d,超过上界 %d", got, 3*3)
	}
	if got := seriesCount(t, m, "p2p_direct_upgrade_total"); got > 4*3 {
		t.Fatalf("upgrade 分桶序列数 = %d,超过上界 %d", got, 4*3)
	}

	// 标签取值必须只落在白名单内(不得出现注入串/地址)。
	allowedNet := map[string]bool{registry.NetPublic: true, registry.NetNAT: true, registry.NetUnknown: true}
	for _, v := range labelValues(t, m, "p2p_session_established_by_net_total") {
		if strings.HasPrefix(v, "punch-") || strings.HasPrefix(v, "10.0.0.") {
			t.Fatalf("标签泄漏注入值: %q", v)
		}
		if v == registry.NetPublic || v == registry.NetNAT || v == registry.NetUnknown ||
			v == "punch" || v == "relay" || v == "fallback" || v == registry.TelemetryOtherLabel {
			continue
		}
		t.Fatalf("标签取值越界: %q", v)
	}
	for _, v := range labelValues(t, m, "p2p_relay_fallback_by_net_total") {
		if !allowedNet[v] && v != "punch_failed" && v != "direct_failed" && v != registry.TelemetryOtherLabel {
			t.Fatalf("标签取值越界: %q", v)
		}
	}
}

// TestMetricsDurationClamp 耗时入参越界/负值被钳制(不进异常桶)。
func TestMetricsDurationClamp(t *testing.T) {
	m := NewMetrics()
	m.RelayFallbackDuration("punch_failed", registry.NetNAT, -5)
	m.RelayFallbackDuration("punch_failed", registry.NetNAT, registry.MaxTelemetryDurationMS*10)
	m.DirectUpgradeDuration(registry.UpgradeUpgraded, registry.NetNAT, -1)

	mfs, err := m.reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, mf := range mfs {
		if mf.GetName() != "p2p_relay_fallback_duration_seconds" {
			continue
		}
		for _, met := range mf.GetMetric() {
			found = true
			if got := met.GetHistogram().GetSampleSum(); got < 0 {
				t.Fatalf("耗时和为负: %v", got)
			}
			if got := met.GetHistogram().GetSampleSum(); got > float64(registry.MaxTelemetryDurationMS)*2/1000 {
				t.Fatalf("耗时和未钳制: %v", got)
			}
		}
	}
	if !found {
		t.Fatal("回退耗时指标未落点")
	}
}
