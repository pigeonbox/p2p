// 配对码端点（2026-10-18，spec 见 hub docs/specs/2026-10-18-p2p-pairing-code-design.md）。
//
// create/approve/requests 为节点签名写语义，走全局写桶；claim 另叠加独立
// per-IP 限流——错码无法归因到具体会话，per-IP 是枚举尝试的主防线（配合
// 拒绝即烧码与一次性发放，见 spec §3）。
package server

import (
	"net/http"
	"time"

	"github.com/pigeonbox/p2p/internal/registry"
)

// handlePairCreate 亮码方建会话：{node_id, secret, ts, sig} → {code, ttl}。
func (s *Server) handlePairCreate(w http.ResponseWriter, r *http.Request) {
	var in registry.PairCreateInput
	if !s.decode(w, r, &in) {
		return
	}
	code, ttl, err := s.pairing.Create(r.Context(), in)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"code": code,
		"ttl":  int64(ttl / time.Second),
	})
}

// handlePairClaim 敲门方凭码换会话：首调占 pending 位；同 claim_id 轮询，
// 批准后一次性兑换 {status:"granted", secret, creator}。
func (s *Server) handlePairClaim(w http.ResponseWriter, r *http.Request) {
	if !s.pairClaimLim.Allow(s.clientIP(r)) {
		s.metrics.rateLimited.Inc()
		writeErr(w, http.StatusTooManyRequests, errRateLimited)
		return
	}
	var in registry.PairClaimInput
	if !s.decode(w, r, &in) {
		return
	}
	res, err := s.pairing.Claim(r.Context(), in)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// handlePairApprove 亮码方裁决 pending 请求：{node_id, code, decision, claimer, ts, sig}。
func (s *Server) handlePairApprove(w http.ResponseWriter, r *http.Request) {
	var in registry.PairApproveInput
	if !s.decode(w, r, &in) {
		return
	}
	if err := s.pairing.Approve(r.Context(), in); err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handlePairRequests 亮码方拉取活跃会话与待确认请求（POST：签名走请求体，
// 与 register/announce 的 body-sig 约定一致）。
func (s *Server) handlePairRequests(w http.ResponseWriter, r *http.Request) {
	var in registry.PairRequestsInput
	if !s.decode(w, r, &in) {
		return
	}
	views, err := s.pairing.Requests(r.Context(), in)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	if views == nil {
		views = []registry.PairSessionView{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": views})
}
