package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/oekit/core/version"
	"github.com/pigeonbox/p2p/internal/registry"
)

// registryAPI 节点身份生命周期：注册→公告→解析→注销。
// p2pc 是完整节点客户端的参考实现——与 core federation 域服务同一套契约。
type registryAPI struct {
	base string
	http *http.Client
}

func newRegistryAPI(base string) *registryAPI {
	return &registryAPI{base: trimRight(base), http: &http.Client{Timeout: 10 * time.Second}}
}

func trimRight(s string) string {
	for len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	return s
}

type nodeIdentity struct {
	id   string
	priv ed25519.PrivateKey
}

func newNodeIdentity(keyPath string) (*nodeIdentity, error) {
	priv, err := loadOrCreateNodeKey(keyPath)
	if err != nil {
		return nil, err
	}
	return &nodeIdentity{id: hex.EncodeToString(priv.Public().(ed25519.PublicKey)), priv: priv}, nil
}

func (n *nodeIdentity) sign(payload []byte) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(n.priv, payload))
}

// register 注册节点租约（url 为占位——直传不经 url 字段，取件方走打洞/中继）。
func (r *registryAPI) register(ctx context.Context, n *nodeIdentity, name string, ttl time.Duration) error {
	// version 参与签名 payload——body 与 BuildPayload 必须同源(不同源即 401)
	ver := "p2pc/" + version.Version // kit/version,-ldflags 注入(镜像构建);裸 go build 为 dev
	body := map[string]any{
		"node_id": n.id, "url": "http://direct.invalid", "name": name, "version": ver,
		"caps": []string{"direct"}, "ttl_seconds": int64(ttl / time.Second),
		"nonce": "p2pc-" + strconv.FormatInt(time.Now().UnixNano(), 36), "ts": time.Now().Unix(),
	}
	body["ts"] = time.Now().Unix()
	payload := registry.BuildPayload(n.id, "http://direct.invalid", name, ver,
		"direct", fmt.Sprint(int64(ttl/time.Second)), body["nonce"].(string), fmt.Sprint(body["ts"].(int64)))
	body["sig"] = n.sign(payload)
	return r.do(ctx, http.MethodPost, "/v1/nodes/register", body, http.StatusOK, nil)
}

// announce 宣告口令路由（code 原样含连字符；哈希在服务端约定一侧计算）。
func (r *registryAPI) announce(ctx context.Context, n *nodeIdentity, code string, expires time.Time) error {
	hash := registry.CodeHash(code)
	ts := time.Now().Unix()
	body := map[string]any{
		"node_id": n.id, "code_hash": hash, "expires_at": expires.Unix(),
		"size_hint": 0, "ts": ts,
	}
	body["sig"] = n.sign(registry.BuildPayload(n.id, hash, fmt.Sprint(expires.Unix()), "0", fmt.Sprint(ts)))
	return r.do(ctx, http.MethodPost, "/v1/announces", body, http.StatusOK, nil)
}

// resolve 解析口令→源节点（接收方用于身份钉定）。
func (r *registryAPI) resolve(ctx context.Context, code string) (nodeID string, err error) {
	hash := registry.CodeHash(code)
	var out struct {
		NodeID string `json:"node_id"`
		URL    string `json:"url"`
	}
	if err := r.do(ctx, http.MethodGet, "/v1/resolve/"+hash, nil, http.StatusOK, &out); err != nil {
		return "", err
	}
	return out.NodeID, nil
}

// deregister 注销（best-effort）。
func (r *registryAPI) deregister(ctx context.Context, n *nodeIdentity) {
	body := map[string]any{"node_id": n.id, "ts": time.Now().Unix()}
	body["sig"] = n.sign(registry.BuildPayload(n.id, fmt.Sprint(body["ts"].(int64))))
	_ = r.do(ctx, http.MethodDelete, "/v1/nodes/"+n.id, body, http.StatusOK, nil)
}

func (r *registryAPI) do(ctx context.Context, method, path string, body any, wantStatus int, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, r.base+path, rd)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := r.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != wantStatus {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return fmt.Errorf("%s %s: 期望 %d 实际 %d: %s", method, path, wantStatus, resp.StatusCode, b)
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}
