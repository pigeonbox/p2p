// Package server 装配 p2pd 的 HTTP 面:路由、中间件、限流、指标。
// 响应约定:成功 200 + JSON;失败为对应 HTTP 状态码 + {"error": "消息"}。
package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/pigeonbox/kit/ratelimit"
	"github.com/pigeonbox/p2p/internal/config"
	"github.com/pigeonbox/p2p/internal/registry"
	"github.com/pigeonbox/p2p/internal/signaling"
	"golang.org/x/time/rate"
)

const maxBodyBytes = 64 << 10 // 64KB,所有请求体上限

// limiterIdleTTL 按键限流条目的空闲回收阈值(闲置超此值的 key 被清理)。
const limiterIdleTTL = 30 * time.Minute

// newKeyedLimiter 构造按键令牌桶(kit/ratelimit,空闲键自动回收)。
// 生命周期跟随 ctx:ctx 结束时停掉清理协程——与信令/清扫协程同寿命。
func newKeyedLimiter(ctx context.Context, r rate.Limit, burst int) *ratelimit.KeyedLimiter {
	kl := ratelimit.NewKeyedLimiter(func() ratelimit.Limiter {
		return ratelimit.NewTokenBucket(r, burst)
	}, limiterIdleTTL)
	go func() {
		<-ctx.Done()
		kl.Close()
	}()
	return kl
}

// Params 装配参数。
type Params struct {
	Service *registry.Service
	Config  config.Config
	Logger  *slog.Logger
	Metrics *Metrics
	Version string
}

// Server HTTP 服务。
type Server struct {
	svc     *registry.Service
	cfg     config.Config
	log     *slog.Logger
	metrics *Metrics
	version string
	hub     *signaling.Hub // M3 信令（signaling.enabled=false 时为 nil）

	resolveLim *ratelimit.KeyedLimiter // 读路径(resolve/node 查询)
	writeLim   *ratelimit.KeyedLimiter // 写路径(register/announce/信道接入)
	adminLim   *ratelimit.KeyedLimiter // 管理端
	// resolveHashLim per-hash 维度限流:per-IP 限不住 IP 池对热点 code_hash
	// 的选择明文枚举/定向阻断观测,双键叠加(IP 10x, hash 1x)。
	resolveHashLim *ratelimit.KeyedLimiter
}

// New 构造 Server。ctx 用于限流器/信令清扫协程的生命周期。
func New(ctx context.Context, p Params) *Server {
	log := p.Logger
	if log == nil {
		log = slog.Default()
	}
	m := p.Metrics
	if m == nil {
		m = NewMetrics()
	}
	var hub *signaling.Hub
	if p.Config.Signaling.Enabled {
		hub = signaling.NewHub(ctx, signaling.Config{
			SessionTTL:         p.Config.Signaling.SessionTTL,
			IdleTimeout:        p.Config.Signaling.IdleTimeout,
			HelloTimeout:       p.Config.Signaling.HelloTimeout,
			PingPeriod:         20 * time.Second,
			WriteWait:          10 * time.Second,
			MaxFrameBytes:      p.Config.Signaling.MaxFrameBytes,
			MaxSessionsPerNode: p.Config.Signaling.MaxSessionsPerNode,
			MaxTotalSessions:   p.Config.Signaling.MaxTotalSessions,
		}, p.Service, m)
	}
	return &Server{
		svc:            p.Service,
		cfg:            p.Config,
		log:            log,
		metrics:        m,
		version:        p.Version,
		hub:            hub,
		resolveLim:     newKeyedLimiter(ctx, 1, 120), // resolve: 平均 1/s 突发 120
		writeLim:       newKeyedLimiter(ctx, 2, 120), // 写路径: 平均 2/s 突发 120
		adminLim:       newKeyedLimiter(ctx, 10, 60), // 管理端宽松
		resolveHashLim: newKeyedLimiter(ctx, 10, 60), // 单 hash: 平均 10/s(正常取件重试 2/s×多接收方余量)
	}
}

// Handler 构建完整 HTTP 处理链。
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /health", s.handleHealth)
	// /metrics 门禁(2026-10-05 审计 P3):配置了管理口令时同 adminGate 校验
	// (Prometheus 抓取侧配 Authorization: Bearer <PB_P2P_ADMIN_PASSWORD>);
	// 未配置口令时默认开放(部署兼容,文档声明),metrics.strict=true 的
	// 公共部署则干脆 404 不暴露——宁缺勿泄。
	if s.cfg.Admin.Password != "" {
		mux.Handle("GET /metrics", s.adminGate(promHandler(s.metrics.reg).ServeHTTP))
	} else if s.cfg.Metrics.Strict {
		mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) {
			http.NotFound(w, nil)
		})
	} else {
		mux.Handle("GET /metrics", promHandler(s.metrics.reg))
	}

	s.route(mux, "POST /v1/nodes/register", "register", s.writeLim, s.handleRegister)
	s.route(mux, "POST /v1/nodes/heartbeat", "heartbeat", s.writeLim, s.handleRegister) // 与 register 同语义(幂等 upsert)
	s.route(mux, "GET /v1/nodes/{id}", "node_get", s.resolveLim, s.handleGetNode)
	s.route(mux, "DELETE /v1/nodes/{id}", "node_delete", s.writeLim, s.handleDeregister)

	s.route(mux, "POST /v1/announces", "announce", s.writeLim, s.handleAnnounce)
	s.route(mux, "DELETE /v1/announces/{hash}", "announce_delete", s.writeLim, s.handleRevoke)
	s.route(mux, "GET /v1/resolve/{hash}", "resolve", s.resolveLim, s.handleResolve)

	s.route(mux, "GET /v1/admin/stats", "admin_stats", s.adminLim, s.adminGate(s.handleAdminStats))
	s.route(mux, "GET /v1/admin/nodes", "admin_nodes", s.adminLim, s.adminGate(s.handleAdminNodes))
	s.route(mux, "GET /v1/admin/announces", "admin_announces", s.adminLim, s.adminGate(s.handleAdminAnnounces))
	s.route(mux, "DELETE /v1/admin/nodes/{id}", "admin_node_delete", s.adminLim, s.adminGate(s.handleAdminDeleteNode))

	// M3 信令信道（signaling.enabled=false 时不注册）
	if s.hub != nil {
		s.route(mux, "GET /v1/channel/{hash}", "channel", s.writeLim, s.hub.Handler())
	}

	return recoverMW(s.log, requestLogMW(s.log, mux))
}

// route 注册路由:指标(外层,含 429)→ 限流(内层)→ 业务 handler。
func (s *Server) route(mux *http.ServeMux, pattern, name string, l *ratelimit.KeyedLimiter, h http.HandlerFunc) {
	mux.HandleFunc(pattern, s.withMetrics(name, s.withLimit(l, h)))
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	// relay_port 自报中继端口:客户端据此发现中继(不再依赖写死的 12347),
	// 老服务器缺该字段时客户端回退历史默认 registry host:12347。
	writeJSON(w, http.StatusOK, map[string]any{
		"status":     "ok",
		"version":    s.version,
		"relay_port": s.cfg.Relay.Port,
	})
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var in registry.RegisterInput
	if !s.decode(w, r, &in) {
		return
	}
	node, err := s.svc.RegisterNode(r.Context(), in, s.clientIP(r))
	if err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"node_id":    node.ID,
		"url":        node.URL,
		"expires_at": node.ExpiresAt.Unix(),
	})
}

func (s *Server) handleGetNode(w http.ResponseWriter, r *http.Request) {
	node, err := s.svc.GetNode(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"node_id": node.ID, "url": node.URL, "name": node.Name,
		"version": node.Version, "caps": node.Caps, "expires_at": node.ExpiresAt.Unix(),
	})
}

func (s *Server) handleDeregister(w http.ResponseWriter, r *http.Request) {
	var in registry.RevokeInput
	if !s.decode(w, r, &in) {
		return
	}
	if err := s.svc.DeregisterNode(r.Context(), in); err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleAnnounce(w http.ResponseWriter, r *http.Request) {
	var in registry.AnnounceInput
	if !s.decode(w, r, &in) {
		return
	}
	a, err := s.svc.Announce(r.Context(), in)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"code_hash": a.CodeHash, "node_id": a.NodeID, "expires_at": a.ExpiresAt.Unix(),
	})
}

func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	var in registry.RevokeInput
	if !s.decode(w, r, &in) {
		return
	}
	in.CodeHash = r.PathValue("hash")
	if err := s.svc.RevokeAnnounce(r.Context(), in); err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleResolve(w http.ResponseWriter, r *http.Request) {
	// per-hash 维度限流:同一 code_hash 的解析频率封顶(IP 池绕不过),
	// 防对热点口令的选择明文枚举与定向阻断观测。正常取件(含 500ms 重试)
	// 远低于该阈值。
	if !s.resolveHashLim.Allow(strings.ToLower(r.PathValue("hash"))) {
		s.metrics.rateLimited.Inc()
		writeErr(w, http.StatusTooManyRequests, errRateLimited)
		return
	}
	a, node, err := s.svc.Resolve(r.Context(), r.PathValue("hash"))
	if err != nil {
		s.metrics.resolveTotal.WithLabelValues("miss").Inc()
		s.writeErr(w, err)
		return
	}
	s.metrics.resolveTotal.WithLabelValues("hit").Inc()
	writeJSON(w, http.StatusOK, map[string]any{
		"node_id": node.ID, "url": node.URL, "name": node.Name,
		"expires_at": a.ExpiresAt.Unix(), "size_hint": a.SizeHint,
	})
}

// adminGate 管理端口令门:未配置口令时整体禁用。
func (s *Server) adminGate(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		pw := s.cfg.Admin.Password
		if pw == "" {
			writeErr(w, http.StatusForbidden, errors.New("admin 未启用(未配置 PB_P2P_ADMIN_PASSWORD)"))
			return
		}
		auth := r.Header.Get("Authorization")
		const prefix = "Bearer "
		if !strings.HasPrefix(auth, prefix) || !secureEqual(strings.TrimPrefix(auth, prefix), pw) {
			writeErr(w, http.StatusUnauthorized, errors.New("admin 口令错误"))
			return
		}
		h(w, r)
	}
}

func (s *Server) handleAdminStats(w http.ResponseWriter, r *http.Request) {
	nodes, announces, err := s.svc.Stats(r.Context())
	if err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"nodes": nodes, "announces": announces, "version": s.version,
	})
}

func (s *Server) handleAdminNodes(w http.ResponseWriter, r *http.Request) {
	nodes, err := s.svc.ListNodes(r.Context())
	if err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"nodes": nodes})
}

func (s *Server) handleAdminAnnounces(w http.ResponseWriter, r *http.Request) {
	announces, err := s.svc.ListAnnounces(r.Context())
	if err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"announces": announces})
}

func (s *Server) handleAdminDeleteNode(w http.ResponseWriter, r *http.Request) {
	if err := s.svc.AdminDeleteNode(r.Context(), r.PathValue("id")); err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ---- 公共小件 ----

// decode 读取并反序列化 JSON 请求体(限制大小)。
func (s *Server) decode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("请求体非法: %v", err))
		return false
	}
	return true
}

// writeErr 按哨兵错误映射 HTTP 状态码。
func (s *Server) writeErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, registry.ErrInvalidRequest), errors.Is(err, registry.ErrStaleTimestamp):
		writeErr(w, http.StatusBadRequest, err)
	case errors.Is(err, registry.ErrUnauthorized), errors.Is(err, registry.ErrBadSignature):
		writeErr(w, http.StatusUnauthorized, err)
	case errors.Is(err, registry.ErrNotFound):
		writeErr(w, http.StatusNotFound, err)
	case errors.Is(err, registry.ErrConflict):
		writeErr(w, http.StatusConflict, err)
	case errors.Is(err, registry.ErrQuotaExceeded):
		writeErr(w, http.StatusTooManyRequests, err)
	default:
		s.log.Error("内部错误", "err", err)
		writeErr(w, http.StatusInternalServerError, errors.New("内部错误"))
	}
}

// clientIP 取客户端 IP。
// BehindProxy=true 时解析 X-Forwarded-For——从最右段向左走,跳过可信代理跳
// (TrustedProxies 网段),第一个不可信地址即客户端真实来源。此前取首段的实现
// 可被客户端伪造(每个请求换一个假首段=每个假 IP 一个新限流桶,keyed 限流
// 整体失效)。直连对端不在可信网段时忽略 XFF 回退 RemoteAddr。
func (s *Server) clientIP(r *http.Request) string {
	remote := remoteIP(r)
	if s.cfg.Server.BehindProxy && s.trustedProxy(remote) {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			for i := len(parts) - 1; i > 0; i-- {
				if ip := strings.TrimSpace(parts[i]); !trustedIP(s.cfg.Server.TrustedProxies, ip) {
					return ip
				}
			}
			// 全部为可信跳:客户端直连可信代理,取最左段
			return strings.TrimSpace(parts[0])
		}
	}
	return remote
}

// trustedProxy 直连对端是否可作为反代采信其 XFF。未配置网段时信任直连对端
// (单层反代的常见形态;多层代理链须显式列出内层代理网段)。
func (s *Server) trustedProxy(remote string) bool {
	return len(s.cfg.Server.TrustedProxies) == 0 || trustedIP(s.cfg.Server.TrustedProxies, remote)
}

// trustedIP ip 是否落在任一 CIDR 网段内。
func trustedIP(cidrs []string, ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, c := range cidrs {
		if _, ipnet, err := net.ParseCIDR(strings.TrimSpace(c)); err == nil && ipnet.Contains(ip) {
			return true
		}
	}
	return false
}

// remoteIP 去端口的直连对端地址。
func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}
