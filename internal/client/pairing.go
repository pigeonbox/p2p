// 配对码客户端（2026-10-18，hub docs/specs/2026-10-18-p2p-pairing-code-design.md）。
//
// 编排三形态：
//
//	SendPaired            发送方亮码 → 敲门→接受门 → 兑换 → sendChannel
//	ReceivePaired         接收方敲码（claim 轮询兑换）→ receiveFrom
//	ReceivePairedAsCreator 接收方亮码（反向）→ 接受门 → receiveFrom
//
// 配对只解决「双方如何就同一高熵 secret 达成一致」；secret 既定后走完全既有
// 的信道/PAKE/传输链路（sendChannel/receiveFrom 复用，零协议分支）。
package client

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/pigeonbox/p2p/internal/registry"
)

// 配对哨兵错误：CLI/网页层按 errors.Is 分流（ErrPairUnknown 触发口令回退）。
var (
	ErrPairUnknown = errors.New("配对码不存在或已失效")
	ErrPairBusy    = errors.New("配对码已被其他设备待确认")
)

// IsPairingCode 4-8 位纯数字形态识别。legacy 口令为 12 位分组建制，无形状
// 冲突；`--code 1234` 自定义短口令的兼容由调用方 claim-404-回退兜住。
func IsPairingCode(s string) bool {
	if len(s) < 4 || len(s) > 8 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// PairRequestView 待确认请求视图（接受门展示用）。
type PairRequestView struct {
	NodeID string
	Name   string
}

// PairCallbacks 配对编排回调（全可空；OnRequest 缺省视为自动接受）。
type PairCallbacks struct {
	// OnCode 每次铸码回调（含过期重铸）：展示配对码与有效期。
	OnCode func(code string, ttl time.Duration)
	// OnRequest 接受门：返回 true 接受；false 拒绝即烧码并重铸新码。
	OnRequest func(req PairRequestView) bool
	// OnDenied 拒绝后回调（提示/事件；可空）。
	OnDenied func(req PairRequestView)
	// OnExpired 码过期重铸前回调（可空）。
	OnExpired func()
	// OnPending 敲码侧收到 pending 态回调（「等待对方确认」提示；可空）。
	OnPending func()
}

// ---- registryAPI 扩展（/v1/pair/*，签名负载与 spec §2.2 逐字对齐） ----

type pairCreateResp struct {
	Code string `json:"code"`
	TTL  int64  `json:"ttl"`
}

func (r *registryAPI) pairCreate(ctx context.Context, n *nodeIdentity, secret string) (string, time.Duration, error) {
	ts := time.Now().Unix()
	body := map[string]any{"node_id": n.id, "secret": secret, "ts": ts}
	body["sig"] = n.sign(registry.BuildPayload("pair-create", n.id, secret, fmt.Sprint(ts)))
	status, respBody, err := r.doRaw(ctx, http.MethodPost, "/v1/pair", body)
	if err != nil {
		return "", 0, err
	}
	if status != http.StatusOK {
		return "", 0, pairHTTPError(status, respBody)
	}
	var out pairCreateResp
	if err := json.Unmarshal(respBody, &out); err != nil {
		return "", 0, fmt.Errorf("create 响应: %w", err)
	}
	return out.Code, time.Duration(out.TTL) * time.Second, nil
}

type pairClaimResp struct {
	Status    string `json:"status"`
	Secret    string `json:"secret"`
	Creator   string `json:"creator"`
	ExpiresIn int64  `json:"expires_in"`
}

func (r *registryAPI) pairClaim(ctx context.Context, n *nodeIdentity, code, claimID string) (pairClaimResp, time.Duration, error) {
	ts := time.Now().Unix()
	body := map[string]any{"node_id": n.id, "code": code, "claim_id": claimID, "ts": ts}
	body["sig"] = n.sign(registry.BuildPayload("pair-claim", n.id, code, claimID, fmt.Sprint(ts)))
	status, respBody, err := r.doRaw(ctx, http.MethodPost, "/v1/pair/claim", body)
	if err != nil {
		return pairClaimResp{}, 0, err
	}
	if status != http.StatusOK {
		return pairClaimResp{}, 0, pairHTTPError(status, respBody)
	}
	var out pairClaimResp
	if err := json.Unmarshal(respBody, &out); err != nil {
		return pairClaimResp{}, 0, fmt.Errorf("claim 响应: %w", err)
	}
	return out, time.Duration(out.ExpiresIn) * time.Second, nil
}

func (r *registryAPI) pairApprove(ctx context.Context, n *nodeIdentity, code, decision, claimer string) error {
	ts := time.Now().Unix()
	body := map[string]any{"node_id": n.id, "code": code, "decision": decision, "claimer": claimer, "ts": ts}
	body["sig"] = n.sign(registry.BuildPayload("pair-approve", n.id, code, decision, claimer, fmt.Sprint(ts)))
	status, respBody, err := r.doRaw(ctx, http.MethodPost, "/v1/pair/approve", body)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return pairHTTPError(status, respBody)
	}
	return nil
}

type pairReqView struct {
	NodeID string `json:"node_id"`
	Name   string `json:"name"`
}

type pairSessionView struct {
	Code      string        `json:"code"`
	ExpiresIn int64         `json:"expires_in"`
	Requests  []pairReqView `json:"requests"`
}

func (r *registryAPI) pairRequests(ctx context.Context, n *nodeIdentity) ([]pairSessionView, time.Duration, error) {
	ts := time.Now().Unix()
	body := map[string]any{"node_id": n.id, "ts": ts}
	body["sig"] = n.sign(registry.BuildPayload("pair-requests", n.id, fmt.Sprint(ts)))
	status, respBody, err := r.doRaw(ctx, http.MethodPost, "/v1/pair/requests", body)
	if err != nil {
		return nil, 0, err
	}
	if status != http.StatusOK {
		return nil, 0, pairHTTPError(status, respBody)
	}
	var out struct {
		Sessions []pairSessionView `json:"sessions"`
	}
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, 0, fmt.Errorf("requests 响应: %w", err)
	}
	return out.Sessions, 0, nil
}

// doRaw 带状态码的请求：非 2xx 返回 (status, body, nil) 由调用方映射语义。
func (r *registryAPI) doRaw(ctx context.Context, method, path string, body any) (int, []byte, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return 0, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, method, r.base+path, bytes.NewReader(b))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := r.http.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
	if err != nil {
		return resp.StatusCode, nil, err
	}
	return resp.StatusCode, raw, nil
}

// pairHTTPError 服务端错误码 → 客户端哨兵（404=未知/失效触发口令回退，
// 409=他人占用，其余原样带报文）。
func pairHTTPError(status int, body []byte) error {
	switch status {
	case http.StatusNotFound:
		return ErrPairUnknown
	case http.StatusConflict:
		return ErrPairBusy
	}
	return fmt.Errorf("注册中心 %d: %s", status, string(body))
}

// ---- 编排 ----

const pairPollInterval = 2 * time.Second

// pairClaimToken claim_id：随机 16 hex，绑定 pending 位与轮询归属。
func pairClaimToken() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("claim-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

// waitPairRequest 亮码方等待敲门：轮询 /requests 直到有人请求（走接受门）
// 或码过期（返回 "", false，调用方重铸）。返回被接受的 claimer node_id。
func (c *Client) waitPairRequest(code string, cb PairCallbacks) (string, bool) {
	ctx := context.Background()
	deadline := time.Now().Add(10 * time.Minute) // 兜底上限（服务端码 TTL ≤ 该值）
	for {
		sessions, _, err := c.reg.pairRequests(ctx, c.id)
		if err != nil {
			c.log.Warn("配对轮询失败,重试", "err", err)
			time.Sleep(pairPollInterval)
			continue
		}
		var cur *pairSessionView
		for i := range sessions {
			if sessions[i].Code == code {
				cur = &sessions[i]
				break
			}
		}
		if cur == nil {
			// 码已出表（过期/GC）：重铸
			if cb.OnExpired != nil {
				cb.OnExpired()
			}
			return "", false
		}
		if len(cur.Requests) > 0 {
			req := PairRequestView{NodeID: cur.Requests[0].NodeID, Name: cur.Requests[0].Name}
			accept := true
			if cb.OnRequest != nil {
				accept = cb.OnRequest(req)
			}
			decision := "accept"
			if !accept {
				decision = "deny"
			}
			if err := c.reg.pairApprove(ctx, c.id, code, decision, req.NodeID); err != nil {
				c.log.Warn("裁决失败,重试", "err", err)
				time.Sleep(pairPollInterval)
				continue
			}
			if !accept {
				if cb.OnDenied != nil {
					cb.OnDenied(req)
				}
				return "", false // 拒绝即烧码：重铸
			}
			return req.NodeID, true
		}
		if time.Now().After(deadline) {
			if cb.OnExpired != nil {
				cb.OnExpired()
			}
			return "", false
		}
		time.Sleep(pairPollInterval)
	}
}

// mintPairing 铸码（secret 本地生成，announce 不涉及——配对模式不走联邦公告）。
func (c *Client) mintPairing() (secret, code string, ttl time.Duration, err error) {
	if secret, err = GenerateCode(); err != nil {
		return "", "", 0, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if code, ttl, err = c.reg.pairCreate(ctx, c.id, secret); err != nil {
		return "", "", 0, fmt.Errorf("创建配对会话: %w", err)
	}
	return secret, code, ttl, nil
}

// SendPaired 发送方亮码模式：铸码 → 等敲门+接受门（拒绝/过期自动重铸）→
// 批准后以兑换 secret 进入既有发送链路。
func (c *Client) SendPaired(paths []string, cb PairCallbacks) (string, error) {
	d := c.setupNode(c.reg)
	defer d()
	for {
		secret, code, ttl, err := c.mintPairing()
		if err != nil {
			return "", err
		}
		if cb.OnCode != nil {
			cb.OnCode(code, ttl)
		}
		if _, ok := c.waitPairRequest(code, cb); !ok {
			continue // 拒绝/过期 → 新码新一轮
		}
		c.log.Info("配对成功,开始传输")
		return c.sendChannel(paths, secret)
	}
}

// claimPair claim 轮询兑换（pending→granted）。租约由调用方持有（须覆盖
// 后续信道接入——claim 兑换返回即注销会令 joinChannel 被 4003 拒之门外）。
// ErrPairUnknown/ErrPairBusy 原样上抛（CLI 据此回退口令解析）。
func (c *Client) claimPair(code string, cb PairCallbacks) (pairClaimResp, error) {
	claimID := pairClaimToken()
	ctx := context.Background()
	deadline := time.Now().Add(10 * time.Minute)
	for {
		res, expiresIn, err := c.reg.pairClaim(ctx, c.id, code, claimID)
		if err != nil {
			return pairClaimResp{}, err
		}
		if res.Status == "granted" {
			return res, nil
		}
		if res.Status != "pending" {
			return pairClaimResp{}, fmt.Errorf("配对状态异常: %q", res.Status)
		}
		if cb.OnPending != nil {
			cb.OnPending()
		}
		if expiresIn > 0 {
			if srvDeadline := time.Now().Add(expiresIn + time.Second); srvDeadline.Before(deadline) {
				deadline = srvDeadline
			}
		}
		if time.Now().After(deadline) {
			return pairClaimResp{}, ErrPairUnknown
		}
		time.Sleep(pairPollInterval)
	}
}

// ReceivePaired 敲码接收：claim 兑换 secret → 以 creator 钉定进入既有接收链路。
// 租约自 claim 前注册起、贯穿整个接收（claimPair 与 receiveFrom 双段共用）。
func (c *Client) ReceivePaired(code, dir string, cb PairCallbacks) ([]string, error) {
	d := c.setupNode(c.reg)
	defer d()
	res, err := c.claimPair(code, cb)
	if err != nil {
		return nil, err
	}
	c.log.Info("配对成功,开始接收")
	return c.receiveFrom(c.reg.base, res.Secret, dir, res.Creator)
}

// SendByClaim 敲码发送（反向配对的发送侧）：接收方亮码，发送方输码 claim
// 兑换 secret 后推送文件。PAKE 发起方恒为文件发送方，与谁铸码无关。
func (c *Client) SendByClaim(code string, paths []string, cb PairCallbacks) (string, error) {
	d := c.setupNode(c.reg)
	defer d()
	res, err := c.claimPair(code, cb)
	if err != nil {
		return "", err
	}
	c.log.Info("配对成功,开始传输")
	return c.sendChannel(paths, res.Secret)
}

// ReceivePairedAsCreator 反向模式：接收方亮码（等对方敲码推送），批准后以
// secret 收件，claimant 钉定信道对端。
func (c *Client) ReceivePairedAsCreator(dir string, cb PairCallbacks) ([]string, error) {
	d := c.setupNode(c.reg)
	defer d()
	for {
		secret, code, ttl, err := c.mintPairing()
		if err != nil {
			return nil, err
		}
		if cb.OnCode != nil {
			cb.OnCode(code, ttl)
		}
		claimer, ok := c.waitPairRequest(code, cb)
		if !ok {
			continue
		}
		c.log.Info("配对成功,开始接收")
		return c.receiveFrom(c.reg.base, secret, dir, claimer)
	}
}
