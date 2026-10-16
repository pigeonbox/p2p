package server

import (
	"bufio"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/oekit/concurrency/ratelimit"
)

var (
	errInternal    = errors.New("内部错误")
	errRateLimited = errors.New("请求过于频繁")
)

// recoverMW panic 兜底:记日志并回 500,防止单请求打挂进程。
func recoverMW(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				log.Error("panic 已拦截", "method", r.Method, "path", r.URL.Path, "panic", rec)
				writeErr(w, http.StatusInternalServerError, errInternal)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// requestLogMW 请求访问日志(方法/路径/状态/耗时)。
// 路径含 code_hash 的路由(announces/resolve/channel)脱敏为路由名+前 8 位
// (2026-10-05 审计 P3:明文记录口令哈希让"注册中心零知识"承诺在日志层打折,
// 泄露的日志可被用于定向阻断配对/离线枚举)。
func requestLogMW(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		start := time.Now()
		next.ServeHTTP(rec, r)
		log.Info("http", "method", r.Method, "path", redactPath(r.URL.Path),
			"status", rec.status, "dur_ms", time.Since(start).Milliseconds())
	})
}

// redactPath 对携带 64 位 hex 段的路径脱敏(保留段前 8 位)。
func redactPath(p string) string {
	seg := strings.LastIndexByte(p, '/')
	if seg < 0 {
		return p
	}
	last := p[seg+1:]
	if len(last) == 64 && isAllHex(last) {
		return p[:seg+1] + last[:8] + "…"
	}
	return p
}

func isAllHex(s string) bool {
	for _, c := range s {
		isDigit := c >= '0' && c <= '9'
		isLower := c >= 'a' && c <= 'f'
		isUpper := c >= 'A' && c <= 'F'
		if !isDigit && !isLower && !isUpper {
			return false
		}
	}
	return true
}

// statusRecorder 捕获响应状态码。
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// Hijack 透传底层连接接管(WS 升级必需)。嵌入接口只提升该接口自身的方法,
// Hijacker 不在其中——不透传的话 gorilla 升级直接失败(bad handshake)。
func (s *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := s.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("底层 ResponseWriter 未实现 http.Hijacker")
	}
	return h.Hijack()
}

// statusLabel 归一化状态码标签(2xx/4xx/5xx 细分到百位,控基数)。
func (s *statusRecorder) statusLabel() string {
	switch {
	case s.status < 300:
		return "2xx"
	case s.status < 400:
		return "3xx"
	case s.status < 500:
		return "4xx"
	default:
		return "5xx"
	}
}

// withLimit 令牌桶限流包装;超限回 429。
func (s *Server) withLimit(l *ratelimit.KeyedLimiter, h http.HandlerFunc) http.HandlerFunc {
	if l == nil {
		return h
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if !l.Allow(s.clientIP(r)) {
			s.metrics.rateLimited.Inc()
			writeErr(w, http.StatusTooManyRequests, errRateLimited)
			return
		}
		h(w, r)
	}
}

// withMetrics 路由粒度请求计数(route 用静态名,避免路径参数基数爆炸)。
func (s *Server) withMetrics(route string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		h(rec, r)
		s.metrics.httpRequests.WithLabelValues(r.Method, route, rec.statusLabel()).Inc()
	}
}

// secureEqual 恒时比较。先对双侧做 SHA-256 再比——ConstantTimeCompare 对
// 不等长输入会以比较耗时泄露长度,哈希定长化后彻底抹掉该侧信道。
func secureEqual(a, b string) bool {
	ha := sha256.Sum256([]byte(a))
	hb := sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(ha[:], hb[:]) == 1
}
