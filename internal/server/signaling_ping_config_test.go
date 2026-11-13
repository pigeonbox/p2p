package server

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/pigeonbox/p2p/internal/config"
	"github.com/pigeonbox/p2p/internal/registry"
	"github.com/pigeonbox/p2p/internal/signaling"
)

// TestSignalingPingPeriodFromConfig 是 p2p#38「死配置接入生效路径」的判据:
// signaling.ping_period 此前在 server.New 被字面量 20s 硬编码 ⇒ 配置键改了
// 等于没改。判据走真实链路:配置 100ms ⇒ 客户端 3s 内必收到服务端 ping;
// 若透传被回退成字面量 20s ⇒ 3s 内收不到即转红。
func TestSignalingPingPeriodFromConfig(t *testing.T) {
	ts, _ := newTestServer(t, func(c *config.Config) {
		c.Signaling = config.Signaling{
			Enabled:            true,
			SessionTTL:         10 * time.Minute,
			IdleTimeout:        30 * time.Second,
			HelloTimeout:       10 * time.Second,
			PingPeriod:         100 * time.Millisecond,
			WriteWait:          time.Second,
			MaxFrameBytes:      16 << 10,
			MaxSessionsPerNode: 8,
			MaxTotalSessions:   64,
		}
	})
	tc := testClient{t: t, base: ts}
	k := newNodeKey(t)
	tc.register(k, "https://ping-config.test")

	hash := registry.CodeHash("ping-config-code-12345")
	wsBase := "ws" + strings.TrimPrefix(ts.URL, "http")
	conn, _, err := websocket.DefaultDialer.Dial(wsBase+"/v1/channel/"+hash, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	// hello 准入:签名负载是 signaling.BuildJoinPayload(channel-join),与注册
	// 接口的 registry.BuildPayload 不同族,须直接用节点私钥签。
	tsSec := time.Now().Unix()
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(k.priv,
		signaling.BuildJoinPayload(k.id, hash, tsSec)))
	if err := conn.WriteJSON(map[string]any{
		"type": "hello", "node_id": k.id, "ts": tsSec, "sig": sig,
	}); err != nil {
		t.Fatalf("hello: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, raw, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("读 waiting 帧: %v", err)
	}
	if !strings.Contains(string(raw), "waiting") {
		t.Fatalf("首个服务端帧应 waiting,得到 %s", raw)
	}

	// 观测 ping:控制帧在**阻塞读期间**送达并触发 ping handler。gorilla 的
	// 读错误是永久性的(不可短 deadline 反复读),所以只起一次长读。
	pingCh := make(chan struct{}, 1)
	conn.SetPingHandler(func(appData string) error {
		_ = conn.WriteControl(websocket.PongMessage, []byte(appData), time.Now().Add(time.Second))
		select {
		case pingCh <- struct{}{}:
		default:
		}
		return nil
	})
	readDone := make(chan error, 1)
	go func() {
		_ = conn.SetReadDeadline(time.Now().Add(4 * time.Second))
		_, _, err := conn.ReadMessage() // 无数据帧:阻塞到 ping/截止
		readDone <- err
	}()
	select {
	case <-pingCh:
		return // 配置的 100ms ping 周期已透传到生效路径
	case err := <-readDone:
		t.Fatalf("读在收到 ping 前结束: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("3s 内未收到服务端 ping:ping_period 未从配置透传(server.New 字面量硬编码回退?)")
	}
}
