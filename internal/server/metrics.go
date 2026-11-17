package server

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/pigeonbox/p2p/internal/registry"
)

// Metrics p2pd 指标集。独立 Registry,避免测试间全局污染。
type Metrics struct {
	reg *prometheus.Registry

	httpRequests       *prometheus.CounterVec // method, route, code
	resolveTotal       *prometheus.CounterVec // result: hit|miss
	rateLimited        prometheus.Counter
	nodesActive        prometheus.Gauge
	announcesGauge     prometheus.Gauge
	signalingSessions  prometheus.Gauge
	signalingJoins     *prometheus.CounterVec // result: waiting|paired|busy|rejected
	sessionEstablished *prometheus.CounterVec // path: punch|relay|fallback
	sessionFailed      *prometheus.CounterVec // reason: 白名单枚举(脱敏)
	relayFallback      *prometheus.CounterVec // reason: punch_failed|direct_failed

	// p2p#51 直连观测面:按**网络环境分桶**的直连成功率 + 中继回退/直连升级
	// 的耗时与结果(此前回退是黑盒)。
	//
	// 分桶取值只有 public|nat|unknown 三个 ⇒ 基数封顶;标签归一在**本层**
	// 兜底(registry.NormalizeTelemetry*):即便调用方绕过服务端白名单校验,
	// label 取值也只会落在白名单或 other ⇒ 灌入任意多不同维度都不增序列。
	sessionEstablishedByNet *prometheus.CounterVec   // path, net
	sessionFailedByNet      *prometheus.CounterVec   // reason, net
	relayFallbackByNet      *prometheus.CounterVec   // reason, net
	relayFallbackDuration   *prometheus.HistogramVec // reason, net
	directUpgrade           *prometheus.CounterVec   // result, net
	directUpgradeDuration   *prometheus.HistogramVec // result, net
}

// 直连观测面的耗时桶(秒)。回退触发耗时与升级耗时的量级都在亚秒~分钟级,
// Prometheus 默认桶(5ms~10s)对长尾太粗 ⇒ 自定桶。
var directDurationBuckets = []float64{0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 30, 60, 300}

// NewMetrics 构造指标集。
func NewMetrics() *Metrics {
	reg := prometheus.NewRegistry()
	m := &Metrics{reg: reg}
	f := promauto.With(reg)
	m.httpRequests = f.NewCounterVec(prometheus.CounterOpts{
		Name: "p2p_http_requests_total", Help: "HTTP 请求计数(按路由静态名)",
	}, []string{"method", "route", "code"})
	m.resolveTotal = f.NewCounterVec(prometheus.CounterOpts{
		Name: "p2p_resolve_total", Help: "口令解析计数",
	}, []string{"result"})
	m.rateLimited = f.NewCounter(prometheus.CounterOpts{
		Name: "p2p_rate_limited_total", Help: "限流拦截计数",
	})
	m.nodesActive = f.NewGauge(prometheus.GaugeOpts{
		Name: "p2p_nodes_active", Help: "当前有效节点租约数",
	})
	m.announcesGauge = f.NewGauge(prometheus.GaugeOpts{
		Name: "p2p_announces_active", Help: "当前有效公告数",
	})
	m.signalingSessions = f.NewGauge(prometheus.GaugeOpts{
		Name: "p2p_signaling_sessions_active", Help: "当前活跃信令会话数(含等待配对)",
	})
	m.signalingJoins = f.NewCounterVec(prometheus.CounterOpts{
		Name: "p2p_signaling_joins_total", Help: "信令信道接入计数",
	}, []string{"result"})
	// p2p#51 直连率遥测:客户端在打洞/会话建立结果路径经 /v1/telemetry/session 上报。
	// label 一律服务端白名单校验,只记枚举不记对端地址(脱敏)。
	m.sessionEstablished = f.NewCounterVec(prometheus.CounterOpts{
		Name: "p2p_session_established_total", Help: "传输会话建立成功计数(按最终路径)",
	}, []string{"path"})
	m.sessionFailed = f.NewCounterVec(prometheus.CounterOpts{
		Name: "p2p_session_failed_total", Help: "传输会话建立失败计数(按原因枚举,脱敏)",
	}, []string{"reason"})
	m.relayFallback = f.NewCounterVec(prometheus.CounterOpts{
		Name: "p2p_relay_fallback_total", Help: "会话回退中继计数(按触发原因)",
	}, []string{"reason"})
	// p2p#51:同批事件的**分桶视角**(net=public|nat|unknown)与回退/升级耗时。
	// 与上面三个指标同源同事件(服务端一次上报落两处),按 net 切片即可算
	// 「某类网络环境下的直连成功率」。
	m.sessionEstablishedByNet = f.NewCounterVec(prometheus.CounterOpts{
		Name: "p2p_session_established_by_net_total", Help: "传输会话建立成功计数(按最终路径 × 网络环境分桶)",
	}, []string{"path", "net"})
	m.sessionFailedByNet = f.NewCounterVec(prometheus.CounterOpts{
		Name: "p2p_session_failed_by_net_total", Help: "传输会话建立失败计数(按原因枚举 × 网络环境分桶,脱敏)",
	}, []string{"reason", "net"})
	m.relayFallbackByNet = f.NewCounterVec(prometheus.CounterOpts{
		Name: "p2p_relay_fallback_by_net_total", Help: "会话回退中继计数(按触发原因 × 网络环境分桶)",
	}, []string{"reason", "net"})
	m.relayFallbackDuration = f.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "p2p_relay_fallback_duration_seconds",
		Help:    "中继回退触发耗时(秒,自直连尝试开始到回退决策)",
		Buckets: directDurationBuckets,
	}, []string{"reason", "net"})
	m.directUpgrade = f.NewCounterVec(prometheus.CounterOpts{
		Name: "p2p_direct_upgrade_total", Help: "直连升级结果计数(中继兜底后后台打洞升级直连)",
	}, []string{"result", "net"})
	m.directUpgradeDuration = f.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "p2p_direct_upgrade_duration_seconds",
		Help:    "直连升级耗时(秒,自中继就绪到升级成功/超时)",
		Buckets: directDurationBuckets,
	}, []string{"result", "net"})
	return m
}

// SignalingSessions 实现 signaling.Metrics（会话仪表增减）。
func (m *Metrics) SignalingSessions(delta int) { m.signalingSessions.Add(float64(delta)) }

// SignalingJoin 实现 signaling.Metrics（接入计数）。
func (m *Metrics) SignalingJoin(result string) { m.signalingJoins.WithLabelValues(result).Inc() }

// SessionEstablished 会话建立成功(path 由 handler 白名单校验)。
func (m *Metrics) SessionEstablished(path string) {
	m.sessionEstablished.WithLabelValues(path).Inc()
}

// SessionFailed 会话建立失败(reason 由 handler 白名单校验,脱敏枚举)。
func (m *Metrics) SessionFailed(reason string) { m.sessionFailed.WithLabelValues(reason).Inc() }

// RelayFallback 会话回退中继(punch_failed=快打洞失败;direct_failed=快打洞成功但直连失败)。
func (m *Metrics) RelayFallback(reason string) { m.relayFallback.WithLabelValues(reason).Inc() }

// SessionEstablishedByNet 会话建立成功(路径 × 网络环境分桶,p2p#51)。
//
// 标签在**本层**归一(白名单外折进 other/net 的 unknown)⇒ 基数封顶的最后
// 一道闸:即便调用方绕过 registry 侧校验,label 取值也只会是白名单内的。
func (m *Metrics) SessionEstablishedByNet(path, net string) {
	m.sessionEstablishedByNet.WithLabelValues(
		registry.NormalizeTelemetryPath(path),
		registry.NormalizeTelemetryNet(net),
	).Inc()
}

// SessionFailedByNet 会话建立失败(原因 × 网络环境分桶,p2p#51)。
func (m *Metrics) SessionFailedByNet(reason, net string) {
	m.sessionFailedByNet.WithLabelValues(
		registry.NormalizeTelemetryReason(registry.TelemetryFailed, reason),
		registry.NormalizeTelemetryNet(net),
	).Inc()
}

// RelayFallbackByNet 会话回退中继(原因 × 网络环境分桶,p2p#51)。
func (m *Metrics) RelayFallbackByNet(reason, net string) {
	m.relayFallbackByNet.WithLabelValues(
		registry.NormalizeTelemetryReason(registry.TelemetryRelayFallback, reason),
		registry.NormalizeTelemetryNet(net),
	).Inc()
}

// RelayFallbackDuration 回退触发耗时(毫秒入参,秒出指标)。
//
// 负值/超大值在 registry.ClampTelemetryDurationMS 里钳制(不进指标桶的
// 异常值会让直方图分桶失真)。
func (m *Metrics) RelayFallbackDuration(reason, net string, durMS int64) {
	m.relayFallbackDuration.WithLabelValues(
		registry.NormalizeTelemetryReason(registry.TelemetryRelayFallback, reason),
		registry.NormalizeTelemetryNet(net),
	).Observe(float64(registry.ClampTelemetryDurationMS(durMS)) / 1000)
}

// DirectUpgrade 直连升级结果(upgraded|upgrade_timeout|upgrade_failed,p2p#51)。
func (m *Metrics) DirectUpgrade(result, net string) {
	m.directUpgrade.WithLabelValues(
		registry.NormalizeTelemetryReason(registry.TelemetryDirectUpgrade, result),
		registry.NormalizeTelemetryNet(net),
	).Inc()
}

// DirectUpgradeDuration 直连升级耗时(毫秒入参,秒出指标,p2p#51)。
func (m *Metrics) DirectUpgradeDuration(result, net string, durMS int64) {
	m.directUpgradeDuration.WithLabelValues(
		registry.NormalizeTelemetryReason(registry.TelemetryDirectUpgrade, result),
		registry.NormalizeTelemetryNet(net),
	).Observe(float64(registry.ClampTelemetryDurationMS(durMS)) / 1000)
}

// SetGauges 由清扫循环周期刷新活跃量仪表。
func (m *Metrics) SetGauges(nodes, announces int) {
	m.nodesActive.Set(float64(nodes))
	m.announcesGauge.Set(float64(announces))
}

func promHandler(reg *prometheus.Registry) http.Handler {
	return promhttp.HandlerFor(reg, promhttp.HandlerOpts{})
}
