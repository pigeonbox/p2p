package main

// 网页模式全链路 e2e：API 上传 → re-exec 子模式（真实子进程）→ client 发送
// → client 库接收 → 文件一致。fixture 与 internal/client/client_test.go 的
// newFixture 同构（进程内注册/公告/信令/反射器/中继），测试专用复制，勿改语义。

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
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

// TestMain 分发 Manager 拉起的隐藏子模式：go test 时 os.Executable() 即测试
// 二进制，args 均为 --k=v 形式，逐一手解析后进子模式。
func TestMain(m *testing.M) {
	for _, a := range os.Args[1:] {
		if !strings.HasPrefix(a, "--transfer-child=") {
			continue
		}
		o := &options{child: strings.TrimPrefix(a, "--transfer-child=")}
		for _, b := range os.Args[1:] {
			switch {
			case strings.HasPrefix(b, "--registry="):
				o.registry = strings.TrimPrefix(b, "--registry=")
			case strings.HasPrefix(b, "--code="):
				o.code = strings.TrimPrefix(b, "--code=")
			case strings.HasPrefix(b, "--path="):
				o.path = strings.TrimPrefix(b, "--path=")
			case strings.HasPrefix(b, "--out="):
				o.outDir = strings.TrimPrefix(b, "--out=")
			case strings.HasPrefix(b, "--relay="):
				o.relay = strings.TrimPrefix(b, "--relay=")
			case b == "--no-punch":
				o.noPunch = true
			}
		}
		os.Exit(runTransferChild(o))
	}
	os.Exit(m.Run())
}

// ---- fixture（与 internal/client/client_test.go 同构） ----

type p2pFixture struct {
	base  string
	relay string
}

func newP2PFixture(t *testing.T) *p2pFixture {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	cfg := config.Config{
		Server:       config.Server{Port: 0, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second},
		Registration: config.Registration{Mode: "open", MinNodeTTL: time.Minute, MaxNodeTTL: time.Hour},
		Announce:     config.Announce{MaxPerNode: 100, MaxTTL: time.Hour},
		Signaling:    config.Signaling{Enabled: true, SessionTTL: 10 * time.Minute, IdleTimeout: time.Minute, HelloTimeout: 10 * time.Second, MaxFrameBytes: 16 << 10, MaxSessionsPerNode: 8, MaxTotalSessions: 64},
		Log:          config.Log{Level: "error"},
	}
	svc := registry.New(registry.Params{
		Store: memory.New(), MinNodeTTL: cfg.Registration.MinNodeTTL,
		MaxNodeTTL: cfg.Registration.MaxNodeTTL, MaxAnnounces: cfg.Announce.MaxPerNode,
		MaxAnnounceTTL: cfg.Announce.MaxTTL,
	})
	srv := server.New(ctx, server.Params{Service: svc, Config: cfg, Version: "test"})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	// 反射器：与 httptest 同端口的 UDP（与生产同构）
	port := ts.Listener.Addr().(*net.TCPAddr).Port
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{Port: port})
	if err != nil {
		t.Fatalf("反射器绑定: %v", err)
	}
	go reflectPkg.Serve(ctx, udpConn, nil)
	t.Cleanup(func() { _ = udpConn.Close() })

	f := &p2pFixture{base: ts.URL}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f.relay = ln.Addr().String()
	go func() { _ = relay.Serve(ctx, ln, relay.Params{}) }()
	t.Cleanup(func() { _ = ln.Close() })
	return f
}

func waitForAnnounce(t *testing.T, base, code string) {
	t.Helper()
	hash := sha256.Sum256([]byte(code))
	target := base + "/v1/resolve/" + hex.EncodeToString(hash[:])
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(target)
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

// ---- e2e 用例 ----

// TestWebSendToClientRecv 网页上传 → 子模式发送 → client 库按口令接收。
// 载荷 2MB:跨过 1MB 进度粒度,顺带断言子进程进度标记 → 结构化 progress 事件。
func TestWebSendToClientRecv(t *testing.T) {
	f := newP2PFixture(t)

	payload := make([]byte, 2<<20)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	fileName := "e2e 直传样例.bin"

	s := &Server{
		token:     "tk",
		loopback:  true,
		maxUpload: 8 << 20,
		outDir:    t.TempDir(),
		// 确定性走 fixture 中继(禁打洞):CI runner 上 loopback UDP 打洞不可靠,
		// 且与 internal/client 的打洞用例并行时互相争抢资源——同 TestSendRecvForcedRelay 模式
		relay:   f.relay,
		noPunch: true,
		cfg:     newCfgStoreAt(filepath.Join(t.TempDir(), "c.json")),
		mgr:     NewManager(),
	}
	ts := httptest.NewServer(s.routes())
	defer ts.Close()
	// guard 的 Host 校验按请求时读取 s.port，监听后再补即可
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(ts.URL, "http://"))
	s.port = port

	events := s.mgr.Subscribe()

	// 网页上传（multipart 流式）
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile("file", fileName)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST",
		"/api/send?registry="+url.QueryEscape(f.base), &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	w := httptest.NewRecorder()
	s.handleSend(w, req)
	if w.Code != http.StatusAccepted {
		t.Fatalf("上传期望 202, got %d: %s", w.Code, w.Body.String())
	}
	code := decodeField(t, w.Body.String(), "code")
	if code == "" {
		t.Fatal("响应缺少口令")
	}
	waitForAnnounce(t, f.base, code)

	// 接收方：client 库直连
	rc, err := client.New(client.Options{
		Registry:    f.base,
		NodeKeyPath: filepath.Join(t.TempDir(), "recv.key"),
		RelayAddr:   f.relay,
		PunchBudget: 3 * time.Second,
		Quiet:       true,
	})
	if err != nil {
		t.Fatal(err)
	}
	recvDir := t.TempDir()
	files, err := rc.Receive(code, recvDir)
	if err != nil {
		t.Fatalf("接收失败: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("期望 1 个文件,实际 %d", len(files))
	}
	if filepath.Base(files[0]) != fileName {
		t.Errorf("落盘名 %q ≠ 原名 %q", filepath.Base(files[0]), fileName)
	}
	got, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("内容不一致: %d vs %d 字节", len(got), len(payload))
	}

	// 发送侧子进程应正常退出;途中应至少一条结构化进度事件(2MB > 1MB 粒度)
	sawProgress := false
	deadline := time.After(30 * time.Second)
	for {
		select {
		case ev := <-events:
			switch ev.Type {
			case "progress":
				if ev.Total >= int64(len(payload)) && ev.Got > 0 {
					sawProgress = true
				}
			case "exit":
				if ev.Exit != 0 {
					t.Fatalf("发送侧退出码 %d（err=%s）", ev.Exit, ev.Err)
				}
				if !sawProgress {
					t.Fatal("全程未收到结构化进度事件")
				}
				return
			}
		case <-deadline:
			t.Fatal("30s 内未收到发送侧 exit 事件")
		}
	}
}

func decodeField(t *testing.T, body, field string) string {
	t.Helper()
	marker := `"` + field + `":"`
	i := strings.Index(body, marker)
	if i < 0 {
		return ""
	}
	rest := body[i+len(marker):]
	j := strings.Index(rest, `"`)
	if j < 0 {
		return ""
	}
	return rest[:j]
}
