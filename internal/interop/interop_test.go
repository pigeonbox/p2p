package interop

// 矩阵第一格：当前版 ↔ 当前版，端到端全功能基线（pigeonbox/p2p#50）。
//
// 两端均为本仓当前代码的 client 库实例（in-proc 双端点），但通路全真实：
// 注册中心 httptest HTTP、反射器 UDP、中继 TCP、双端点间 QUIC/中继会话。
// fixture 与 internal/client/client_test.go 的 newFixture 同构（cmd/p2pcweb/
// e2e_test.go 已有同款跨包复制先例）——测试专用复制，勿改语义。
//
// 传输确定性走 fixture 中继（DisablePunch）：CI runner 上 loopback UDP 打洞
// 不可靠，且与 internal/client 的打洞用例并行时互相争抢资源——同
// TestSendRecvForcedRelay 模式。打洞/直连形态归矩阵「中继↔直连切换」格。

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pigeonbox/p2p/internal/client"
	"github.com/pigeonbox/p2p/internal/config"
	reflectPkg "github.com/pigeonbox/p2p/internal/reflect"
	"github.com/pigeonbox/p2p/internal/registry"
	"github.com/pigeonbox/p2p/internal/relay"
	"github.com/pigeonbox/p2p/internal/server"
	"github.com/pigeonbox/p2p/internal/store/memory"
)

// ---- fixture（与 internal/client/client_test.go newFixture 同构，带中继） ----

type fixture struct {
	base   string // httptest 基址
	relay  string // 中继地址
	cancel func()
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())

	cfg := config.Config{
		Server:       config.Server{Port: 0, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second},
		Registration: config.Registration{Mode: "open", MinNodeTTL: time.Minute, MaxNodeTTL: time.Hour},
		Announce:     config.Announce{MaxPerNode: 100, MaxTTL: time.Hour},
		Signaling:    config.Signaling{Enabled: true, SessionTTL: 10 * time.Minute, IdleTimeout: time.Minute, HelloTimeout: 10 * time.Second, PingPeriod: 20 * time.Second, WriteWait: 10 * time.Second, MaxFrameBytes: 16 << 10, MaxSessionsPerNode: 8, MaxTotalSessions: 64},
		Log:          config.Log{Level: "error"},
	}
	svc := registry.New(registry.Params{
		Store: memory.New(), MinNodeTTL: cfg.Registration.MinNodeTTL,
		MaxNodeTTL: cfg.Registration.MaxNodeTTL, MaxAnnounces: cfg.Announce.MaxPerNode,
		MaxAnnounceTTL: cfg.Announce.MaxTTL,
	})
	pairingSvc := registry.NewPairingService(ctx, registry.PairingConfig{}, svc)
	srv := server.New(ctx, server.Params{Service: svc, Pairing: pairingSvc, Config: cfg, Version: "test"})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	// 反射器：与 httptest 同端口的 UDP（与生产同构）
	port := ts.Listener.Addr().(*net.TCPAddr).Port
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{Port: port})
	if err != nil {
		t.Fatalf("反射器绑定: %v", err)
	}
	go reflectPkg.Serve(ctx, udpConn, nil)

	f := &fixture{base: ts.URL, cancel: func() { cancel(); _ = udpConn.Close() }}
	t.Cleanup(f.cancel)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f.relay = ln.Addr().String()
	go func() { _ = relay.Serve(ctx, ln, relay.Params{}) }()
	t.Cleanup(func() { _ = ln.Close() })
	return f
}

func testOpts(f *fixture, nodeTag string) client.Options {
	return client.Options{
		Registry:     f.base,
		NodeKeyPath:  filepath.Join(os.TempDir(), fmt.Sprintf("pb-interop-%s-%d.key", nodeTag, time.Now().UnixNano())),
		RelayAddr:    f.relay,
		PunchBudget:  3 * time.Second,
		DisablePunch: true,
		Quiet:        true,
	}
}

func waitForAnnounce(t *testing.T, base, code string) {
	t.Helper()
	hash := sha256.Sum256([]byte(code))
	url := base + "/v1/resolve/" + hex.EncodeToString(hash[:])
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == 200 {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("公告 10s 内未就绪")
}

func sha256File(t *testing.T, path string) string {
	t.Helper()
	fh, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()
	h := sha256.New()
	if _, err := io.Copy(h, fh); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// TestInteropCurrentCurrent 矩阵第一格「当前版 ↔ 当前版」：注册 → 宣告 →
// 传输一轮 → 数据哈希一致。两端都是当前代码，任何一侧单测绿而此格红即
// 说明端到端装配（而非协商语义）有回归。
func TestInteropCurrentCurrent(t *testing.T) {
	f := newFixture(t)

	code, err := client.GenerateCode()
	if err != nil {
		t.Fatal(err)
	}
	sendDir := t.TempDir()
	recvDir := t.TempDir()

	// 随机载荷 1MB：哈希比对对逐字节翻转敏感，且足以走完分段/进度路径
	src := filepath.Join(sendDir, "interop-当前版.bin")
	payload := make([]byte, 1<<20)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(src, payload, 0o644); err != nil {
		t.Fatal(err)
	}
	wantHash := sha256.Sum256(payload)

	// 发送侧（goroutine：接收方敲门后双方才进传输）
	sendErr := make(chan error, 1)
	go func() {
		c, err := client.New(testOpts(f, "send"))
		if err != nil {
			sendErr <- fmt.Errorf("发送端构造: %w", err)
			return
		}
		_, err = c.Send([]string{src}, code)
		sendErr <- err
	}()

	// 注册/宣告就绪 → 接收侧按口令拉取
	waitForAnnounce(t, f.base, code)
	rc, err := client.New(testOpts(f, "recv"))
	if err != nil {
		t.Fatalf("接收端构造: %v", err)
	}
	outFiles, err := rc.Receive(code, recvDir)
	if err != nil {
		select {
		case e := <-sendErr:
			t.Fatalf("接收: %v（发送侧: %v）", err, e)
		default:
			t.Fatalf("接收: %v（发送侧仍在跑，无错误上报）", err)
		}
	}
	if err := <-sendErr; err != nil {
		t.Fatalf("发送: %v", err)
	}

	if len(outFiles) != 1 {
		t.Fatalf("期望 1 个文件，实际 %d", len(outFiles))
	}
	if filepath.Base(outFiles[0]) != filepath.Base(src) {
		t.Errorf("落盘名 %q ≠ 原名 %q", filepath.Base(outFiles[0]), filepath.Base(src))
	}
	gotHash := sha256File(t, outFiles[0])
	if gotHash != hex.EncodeToString(wantHash[:]) {
		t.Fatalf("数据哈希不一致: got %s want %s", gotHash, hex.EncodeToString(wantHash[:]))
	}
}
