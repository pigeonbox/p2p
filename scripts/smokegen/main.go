// smokegen 是冒烟辅助 CLI:以真实客户端身份对运行中的 p2pd 跑一遍
// 节点生命周期(注册→公告→解析→撤销→注销)与信令信道(双节点配对→双向转发),
// 全部断言通过才退出 0。仅用于 scripts/smoke.sh,不属于服务本体。
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/oekit/concurrency/async"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gorilla/websocket"

	"github.com/pigeonbox/p2p/internal/client"
	"github.com/pigeonbox/p2p/internal/registry"
	"github.com/pigeonbox/p2p/internal/signaling"
)

func main() {
	base := flag.String("base", "http://127.0.0.1:12399", "p2pd 基址")
	code := flag.String("code", "smoke-code-0123456789", "冒烟口令(≥40bit 熵)")
	flag.Parse()
	if err := run(*base, *code); err != nil {
		fmt.Fprintln(os.Stderr, "✗ smoke flow:", err)
		os.Exit(1)
	}
	if err := runChannel(*base); err != nil {
		fmt.Fprintln(os.Stderr, "✗ smoke channel:", err)
		os.Exit(1)
	}
	fmt.Println("✓ 生命周期 + 信令信道 flow OK")
	if err := runTransfer(*base); err != nil {
		fmt.Fprintln(os.Stderr, "✗ smoke transfer:", err)
		os.Exit(1)
	}
}

// runTransfer 设备直传回环: 同进程起发送/接收两个客户端,1MB 随机文件走
// 打洞(回环)或中继路径完整传输并校验。
func runTransfer(base string) error {
	dir, err := os.MkdirTemp("", "p2p-transfer-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	src := filepath.Join(dir, "transfer-smoke.bin")
	data := make([]byte, 1<<20)
	if _, err := rand.Read(data); err != nil {
		return err
	}
	if err := os.WriteFile(src, data, 0o644); err != nil {
		return err
	}

	code, err := client.GenerateCode()
	if err != nil {
		return err
	}
	recvDir := filepath.Join(dir, "out")
	if err := os.MkdirAll(recvDir, 0o755); err != nil {
		return err
	}
	errCh := make(chan error, 1)
	async.GoSafeLabeled("smokegen-send", func() {
		c, err := client.New(client.Options{Registry: base, NodeKeyPath: filepath.Join(dir, "s.key"), RelayAddr: relayAddrOf(base), Quiet: true})
		if err != nil {
			errCh <- err
			return
		}
		_, err = c.Send([]string{src}, code)
		errCh <- err
	})
	// 等公告就绪
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(base + "/v1/resolve/" + registry.CodeHash(code))
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	c, err := client.New(client.Options{Registry: base, NodeKeyPath: filepath.Join(dir, "r.key"), RelayAddr: relayAddrOf(base), Quiet: true})
	if err != nil {
		return err
	}
	outFiles, err := c.Receive(code, recvDir)
	if err != nil {
		return fmt.Errorf("接收: %w", err)
	}
	if err := <-errCh; err != nil {
		return fmt.Errorf("发送: %w", err)
	}
	got, err := os.ReadFile(outFiles[0])
	if err != nil {
		return err
	}
	if sha256.Sum256(got) != sha256.Sum256(data) {
		return fmt.Errorf("传输内容不一致")
	}
	fmt.Println("  ✓ 设备直传回环(1MB)")
	return nil
}

func relayAddrOf(base string) string {
	host := strings.TrimPrefix(strings.TrimSuffix(base, "/"), "http://")
	host = strings.TrimPrefix(host, "https://")
	if i := strings.Index(host, "/"); i >= 0 {
		host = host[:i]
	}
	return host + ":12347"
}

// ---- 通用:节点注册/注销 ----

func signPayload(priv ed25519.PrivateKey, payload []byte) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(priv, payload))
}

func registerNode(base, url, name string) (string, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", nil, err
	}
	nodeID := hex.EncodeToString(pub)
	ts := time.Now().Unix()
	body := map[string]any{
		"node_id": nodeID, "url": url, "name": name, "version": "dev",
		"caps": []string{"download"}, "ttl_seconds": 3600,
		"nonce": "smoke-nonce", "ts": ts,
		"sig": signPayload(priv, registry.BuildPayload(nodeID, url, name, "dev", "download", "3600", "smoke-nonce", fmt.Sprint(ts))),
	}
	if err := post(base, "/v1/nodes/register", body, http.StatusOK); err != nil {
		return "", nil, fmt.Errorf("register %s: %w", name, err)
	}
	return nodeID, priv, nil
}

func deregisterNode(base, nodeID string, priv ed25519.PrivateKey) error {
	ts := time.Now().Unix()
	return doJSON(http.MethodDelete, base, "/v1/nodes/"+nodeID,
		map[string]any{"node_id": nodeID, "ts": ts, "sig": signPayload(priv, registry.BuildPayload(nodeID, fmt.Sprint(ts)))},
		http.StatusOK, nil)
}

// run 生命周期: 注册→公告→解析→撤销→注销。
func run(base, code string) error {
	nodeID, priv, err := registerNode(base, "http://127.0.0.1:1", "smoke-node")
	if err != nil {
		return err
	}
	defer func() { _ = deregisterNode(base, nodeID, priv) }()
	fmt.Println("  ✓ 注册")

	hash := registry.CodeHash(code)
	expires := time.Now().Unix() + 600
	ts := time.Now().Unix()
	annBody := map[string]any{
		"node_id": nodeID, "code_hash": hash, "expires_at": expires,
		"size_hint": 0, "ts": ts,
		"sig": signPayload(priv, registry.BuildPayload(nodeID, hash, fmt.Sprint(expires), "0", fmt.Sprint(ts))),
	}
	if err := post(base, "/v1/announces", annBody, http.StatusOK); err != nil {
		return fmt.Errorf("announce: %w", err)
	}
	fmt.Println("  ✓ 公告")

	var resolved struct {
		NodeID string `json:"node_id"`
		URL    string `json:"url"`
	}
	if err := getJSON(base, "/v1/resolve/"+hash, http.StatusOK, &resolved); err != nil {
		return fmt.Errorf("resolve hit: %w", err)
	}
	if resolved.NodeID != nodeID || resolved.URL != "http://127.0.0.1:1" {
		return fmt.Errorf("resolve 返回不匹配: %+v", resolved)
	}
	fmt.Println("  ✓ 解析命中")

	ts = time.Now().Unix()
	if err := doJSON(http.MethodDelete, base, "/v1/announces/"+hash,
		map[string]any{"node_id": nodeID, "ts": ts, "sig": signPayload(priv, registry.BuildPayload(nodeID, hash, fmt.Sprint(ts)))},
		http.StatusOK, nil); err != nil {
		return fmt.Errorf("revoke: %w", err)
	}
	fmt.Println("  ✓ 撤销")

	if err := getJSON(base, "/v1/resolve/"+hash, http.StatusNotFound, nil); err != nil {
		return fmt.Errorf("resolve miss after revoke: %w", err)
	}
	fmt.Println("  ✓ 撤销后解析 404")
	return nil
}

// runChannel 信令信道: 双节点注册→配对→双向转发→注销。
func runChannel(base string) error {
	hash := registry.CodeHash("smoke-channel-code-0123456789")
	idA, privA, err := registerNode(base, "http://127.0.0.1:1", "smoke-a")
	if err != nil {
		return err
	}
	idB, privB, err := registerNode(base, "http://127.0.0.1:2", "smoke-b")
	if err != nil {
		return err
	}
	defer func() {
		_ = deregisterNode(base, idA, privA)
		_ = deregisterNode(base, idB, privB)
	}()

	wsURL := "ws" + strings.TrimPrefix(base, "http") + "/v1/channel/" + hash
	connA, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		return fmt.Errorf("dial A: %w", err)
	}
	defer func() { _ = connA.Close() }()
	connB, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		return fmt.Errorf("dial B: %w", err)
	}
	defer func() { _ = connB.Close() }()

	hello := func(conn *websocket.Conn, id string, priv ed25519.PrivateKey) error {
		ts := time.Now().Unix()
		return conn.WriteJSON(map[string]any{
			"type": "hello", "node_id": id, "ts": ts,
			"sig": signPayload(priv, signaling.BuildJoinPayload(id, hash, ts)),
		})
	}
	read := func(conn *websocket.Conn) (frame, error) {
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, raw, err := conn.ReadMessage()
		if err != nil {
			return frame{}, err
		}
		var f frame
		err = json.Unmarshal(raw, &f)
		return f, err
	}
	if err := hello(connA, idA, privA); err != nil {
		return err
	}
	if f, err := read(connA); err != nil || f.Type != "waiting" {
		return fmt.Errorf("A 期望 waiting: %+v err=%v", f, err)
	}
	if err := hello(connB, idB, privB); err != nil {
		return err
	}
	fa, err := read(connA)
	if err != nil || fa.Type != "paired" || fa.PeerID != idB {
		return fmt.Errorf("A 期望 paired(peer=%s): %+v err=%v", idB, fa, err)
	}
	fb, err := read(connB)
	if err != nil || fb.Type != "paired" || fb.PeerID != idA {
		return fmt.Errorf("B 期望 paired(peer=%s): %+v err=%v", idA, fb, err)
	}
	fmt.Println("  ✓ 信令配对(身份交叉核对)")

	if err := connA.WriteJSON(map[string]any{"type": "data", "payload": []byte("ping")}); err != nil {
		return err
	}
	if f, err := read(connB); err != nil || f.Type != "data" || f.From != idA || string(f.Payload) != "ping" {
		return fmt.Errorf("B 期望 A 的 ping: %+v err=%v", f, err)
	}
	if err := connB.WriteJSON(map[string]any{"type": "data", "payload": []byte("pong")}); err != nil {
		return err
	}
	if f, err := read(connA); err != nil || f.Type != "data" || f.From != idB || string(f.Payload) != "pong" {
		return fmt.Errorf("A 期望 B 的 pong: %+v err=%v", f, err)
	}
	fmt.Println("  ✓ 信令双向转发")
	return nil
}

type frame struct {
	Type    string `json:"type"`
	PeerID  string `json:"peer_id"`
	From    string `json:"from"`
	Payload []byte `json:"payload"`
	Message string `json:"message"`
}

// ---- HTTP 小件 ----

func post(base, path string, body any, wantStatus int) error {
	return doJSON(http.MethodPost, base, path, body, wantStatus, nil)
}

func doJSON(method, base, path string, body any, wantStatus int, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, base+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != wantStatus {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("%s %s: 期望 %d 实际 %d: %s", method, path, wantStatus, resp.StatusCode, b)
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

func getJSON(base, path string, wantStatus int, out any) error {
	return doJSON(http.MethodGet, base, path, nil, wantStatus, out)
}
