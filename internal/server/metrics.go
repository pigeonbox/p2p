package server

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
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
}

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

// SetGauges 由清扫循环周期刷新活跃量仪表。
func (m *Metrics) SetGauges(nodes, announces int) {
	m.nodesActive.Set(float64(nodes))
	m.announcesGauge.Set(float64(announces))
}

func promHandler(reg *prometheus.Registry) http.Handler {
	return promhttp.HandlerFor(reg, promhttp.HandlerOpts{})
}
