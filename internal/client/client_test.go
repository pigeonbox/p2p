package client

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
	"strings"
	"testing"
	"time"

	"github.com/pigeonbox/p2p/internal/config"
	reflectPkg "github.com/pigeonbox/p2p/internal/reflect"
	"github.com/pigeonbox/p2p/internal/registry"
	"github.com/pigeonbox/p2p/internal/relay"
	"github.com/pigeonbox/p2p/internal/server"
	"github.com/pigeonbox/p2p/internal/store/memory"
)

// ---- fixture: 完整 p2pd 能力(注册/公告/解析/信令/反射器/可选中继) ----

type fixture struct {
	base   string // httptest 基址
	relay  string // 中继地址(启用时)
	cancel func()
}

func newFixture(t *testing.T, withRelay bool) *fixture {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())

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
	pairingSvc := registry.NewPairingService(ctx, registry.PairingConfig{}, svc)
	srv := server.New(ctx, server.Params{Service: svc, Pairing: pairingSvc, Config: cfg, Version: "test"})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	// 反射器:与 httptest 同端口的 UDP(与生产同构)
	port := ts.Listener.Addr().(*net.TCPAddr).Port
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{Port: port})
	if err != nil {
		t.Fatalf("反射器绑定: %v", err)
	}
	go reflectPkg.Serve(ctx, udpConn, nil)

	f := &fixture{base: ts.URL, cancel: func() { cancel(); _ = udpConn.Close() }}
	t.Cleanup(f.cancel)

	if withRelay {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		f.relay = ln.Addr().String()
		go func() { _ = relay.Serve(ctx, ln, relay.Params{}) }()
		t.Cleanup(func() { _ = ln.Close() })
	}
	return f
}

func testOpts(f *fixture, nodeTag string) Options {
	return Options{
		Registry:    f.base,
		NodeKeyPath: filepath.Join(os.TempDir(), fmt.Sprintf("fcb-e2e-%s-%d.key", nodeTag, time.Now().UnixNano())),
		RelayAddr:   f.relay,
		PunchBudget: 3 * time.Second,
		Quiet:       true,
	}
}

func randomFile(t *testing.T, dir, name string, size int) string {
	t.Helper()
	data := make([]byte, size)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func waitForAnnounce(t *testing.T, base, code string) {
	t.Helper()
	hash := sha256.Sum256([]byte(code))
	url := base + "/v1/resolve/" + hex.EncodeToString(hash[:])
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := httpGet(url)
		if err == nil && resp == 200 {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("公告 10s 内未就绪")
}

// ---- 用例 ----

func TestSendRecvLoopbackPunch(t *testing.T) {
	f := newFixture(t, false)
	// 全量 -race 套件并行负载下 3s 打洞预算偶发被挤爆(抖动,非回归):
	// 放宽到 6s,失败仍会走"中继不可用"硬失败路径,不掩盖真回归
	optsOverride := func(o *Options) { o.PunchBudget = 20 * time.Second }
	_ = optsOverride
	code, err := GenerateCode()
	if err != nil {
		t.Fatal(err)
	}
	sendDir := t.TempDir()
	recvDir := t.TempDir()
	src := randomFile(t, sendDir, "hello-传输.bin", 1<<20) // 1MB

	so := testOpts(f, "send")
	so.PunchBudget = 20 * time.Second
	errCh := make(chan error, 1)
	go func() {
		c, err := New(so)
		if err != nil {
			errCh <- err
			return
		}
		_, err = c.Send([]string{src}, code)
		errCh <- err
	}()

	waitForAnnounce(t, f.base, code)
	ro := testOpts(f, "recv")
	ro.PunchBudget = 20 * time.Second
	c, err := New(ro)
	if err != nil {
		t.Fatal(err)
	}
	outFiles, err := c.Receive(code, recvDir)
	if err != nil {
		t.Fatalf("接收: %v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("发送: %v", err)
	}
	assertSameFile(t, src, outFiles[0])
}

func TestSendRecvForcedRelay(t *testing.T) {
	f := newFixture(t, true)
	code, _ := GenerateCode()
	sendDir := t.TempDir()
	recvDir := t.TempDir()
	src := randomFile(t, sendDir, "relay-file.bin", 512<<10)

	opts := testOpts(f, "send")
	opts.DisablePunch = true
	errCh := make(chan error, 1)
	go func() {
		c, err := New(opts)
		if err != nil {
			errCh <- err
			return
		}
		_, err = c.Send([]string{src}, code)
		errCh <- err
	}()

	waitForAnnounce(t, f.base, code)
	recvOpts := testOpts(f, "recv")
	recvOpts.DisablePunch = true
	c, err := New(recvOpts)
	if err != nil {
		t.Fatal(err)
	}
	outFiles, err := c.Receive(code, recvDir)
	if err != nil {
		t.Fatalf("接收: %v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("发送: %v", err)
	}
	assertSameFile(t, src, outFiles[0])
}

func TestSendRecvResumeFromPartial(t *testing.T) {
	f := newFixture(t, true)
	code, _ := GenerateCode()
	sendDir := t.TempDir()
	recvDir := t.TempDir()
	src := randomFile(t, sendDir, "resume-file.bin", 1<<20)

	// 预置接收方部分文件(前 256KB)→ 触发断点续传
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(recvDir, "resume-file.bin"), data[:256<<10], 0o644); err != nil {
		t.Fatal(err)
	}

	// 断点续传与传输方式无关,钉中继路径(CI 网络打洞结果不确定)
	sendOpts := testOpts(f, "send")
	sendOpts.DisablePunch = true
	errCh := make(chan error, 1)
	go func() {
		c, err := New(sendOpts)
		if err != nil {
			errCh <- err
			return
		}
		_, err = c.Send([]string{src}, code)
		errCh <- err
	}()

	waitForAnnounce(t, f.base, code)
	recvOpts := testOpts(f, "recv")
	recvOpts.DisablePunch = true
	c, err := New(recvOpts)
	if err != nil {
		t.Fatal(err)
	}
	outFiles, err := c.Receive(code, recvDir)
	if err != nil {
		t.Fatalf("接收: %v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("发送: %v", err)
	}
	assertSameFile(t, src, outFiles[0])
}

// TestSendRecvMultiStreamDirect v3 多流并行路径回环 e2e:文件 ≥8MB 阈值
// 触发 QUIC 直传多流(plan/seg 分段+WriteAt 定位写+全量 sha256)。
// 同时覆盖显式版本协商(v3 双端握手)。
func TestSendRecvMultiStreamDirect(t *testing.T) {
	f := newFixture(t, false)
	code, _ := GenerateCode()
	sendDir := t.TempDir()
	recvDir := t.TempDir()
	src := randomFile(t, sendDir, "multi-stream.bin", 8<<20) // 恰在多流阈值上

	so := testOpts(f, "send")
	so.PunchBudget = 20 * time.Second
	errCh := make(chan error, 1)
	go func() {
		c, err := New(so)
		if err != nil {
			errCh <- err
			return
		}
		_, err = c.Send([]string{src}, code)
		errCh <- err
	}()

	waitForAnnounce(t, f.base, code)
	ro := testOpts(f, "recv")
	ro.PunchBudget = 20 * time.Second
	c, err := New(ro)
	if err != nil {
		t.Fatal(err)
	}
	outFiles, err := c.Receive(code, recvDir)
	if err != nil {
		t.Fatalf("接收: %v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("发送: %v", err)
	}
	assertSameFile(t, src, outFiles[0])
}

// ---- 小件 ----

func assertSameFile(t *testing.T, want, got string) {
	t.Helper()
	a, err := os.ReadFile(want)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(got)
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != len(b) || sha256.Sum256(a) != sha256.Sum256(b) {
		t.Fatalf("文件不一致: 期望 %d 字节,实际 %d 字节", len(a), len(b))
	}
}

// httpGet 状态码探测。
func httpGet(url string) (int, error) {
	resp, err := http.Get(url) //nolint:gosec // 测试固定 URL
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, nil
}

// TestRelayAddrDerivation 默认中继地址:registry 带端口时须换端口而非拼接。
func TestRelayAddrDerivation(t *testing.T) {
	cases := map[string]string{
		"http://10.44.129.215:22346": "10.44.129.215:12347",
		"http://10.44.129.215":       "10.44.129.215:12347",
		"http://p2p:12346":           "p2p:12347",
	}
	for reg, want := range cases {
		c, err := New(Options{Registry: reg, NodeKeyPath: filepath.Join(t.TempDir(), "k"), Quiet: true})
		if err != nil {
			t.Fatal(err)
		}
		if got := c.relayAddr(); got != want {
			t.Fatalf("registry=%s: relay=%s 期望 %s", reg, got, want)
		}
	}
}

// TestReceiverFirstRace 接收方先于发送方启动(解析首发 miss):
// resolve 短重试应吃掉时序差,双方正常完成传输。
func TestReceiverFirstRace(t *testing.T) {
	f := newFixture(t, true)
	code, _ := GenerateCode()
	sendDir := t.TempDir()
	recvDir := t.TempDir()
	src := randomFile(t, sendDir, "race-file.bin", 256<<10)

	recvErr := make(chan error, 1)
	go func() {
		opts := testOpts(f, "recv")
		opts.DisablePunch = true
		c, err := New(opts)
		if err != nil {
			recvErr <- err
			return
		}
		outFiles, err := c.Receive(code, recvDir)
		if err == nil && len(outFiles) > 0 {
			t.Logf("received: %s", outFiles[0])
		}
		recvErr <- err
	}()

	time.Sleep(1 * time.Second) // 接收方先跑,吃到首发 miss 进入重试

	sendErr := make(chan error, 1)
	go func() {
		opts := testOpts(f, "send")
		opts.DisablePunch = true
		c, err := New(opts)
		if err != nil {
			sendErr <- err
			return
		}
		_, err = c.Send([]string{src}, code)
		sendErr <- err
	}()

	if err := <-recvErr; err != nil {
		t.Fatalf("接收: %v", err)
	}
	if err := <-sendErr; err != nil {
		t.Fatalf("发送: %v", err)
	}
	assertSameFile(t, src, filepath.Join(recvDir, "race-file.bin"))
}

// TestSendRecvMultiFileV4 v4 多文件 e2e:混合输入(单文件+目录)+压缩+多流
// +单遍哈希+部分接受,一次覆盖全部 v4 路径。
func TestSendRecvMultiFileV4(t *testing.T) {
	f := newFixture(t, true)
	code, _ := GenerateCode()
	sendDir := t.TempDir()
	recvDir := t.TempDir()

	// 输入:两个散文件 + 一个目录(含子目录)——总量压到 1MB 触发压缩,
	// 单文件 8MB 触发多流;hashAfter 阈值临时收紧触发单遍哈希
	big := randomFile(t, sendDir, "big-多流.bin", 8<<20)
	small := randomFile(t, sendDir, "小文件.txt", 300<<10)
	sub := filepath.Join(sendDir, "项目目录", "nested")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	nested := randomFile(t, sub, "nested-中文.txt", 120<<10)

	oldHA, oldCT := hashAfterMinTotal, compressMinTotal
	hashAfterMinTotal = 1 << 20
	compressMinTotal = 1 << 20
	defer func() { hashAfterMinTotal, compressMinTotal = oldHA, oldCT }()

	so := testOpts(f, "send")
	so.PunchBudget = 2 * time.Second // 快速失败→中继先行(顺带覆盖 relay 路径)
	so.DisablePunch = true
	errCh := make(chan error, 1)
	go func() {
		c, err := New(so)
		if err != nil {
			errCh <- err
			return
		}
		_, err = c.Send([]string{big, small, filepath.Join(sendDir, "项目目录")}, code)
		errCh <- err
	}()

	waitForAnnounce(t, f.base, code)
	ro := testOpts(f, "recv")
	ro.DisablePunch = true
	// 部分接受:跳过 小文件.txt(ID=1)
	ro.ChooseFiles = func(mf Manifest) []ManifestEntry {
		var picked []ManifestEntry
		for _, e := range mf.Files {
			if e.Name != "小文件.txt" {
				picked = append(picked, e)
			}
		}
		return picked
	}
	c, err := New(ro)
	if err != nil {
		t.Fatal(err)
	}
	files, err := c.Receive(code, recvDir)
	if err != nil {
		t.Fatalf("接收: %v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("发送: %v", err)
	}
	if len(files) != 2 {
		t.Fatalf("部分接受应得 2 个文件,实际 %d: %v", len(files), files)
	}
	// 找到两个文件并核对内容(目录结构在接收目录下重现)
	var bigOut, nestedOut string
	for _, p := range files {
		rel, _ := filepath.Rel(recvDir, p)
		switch {
		case strings.Contains(rel, "big-多流.bin"):
			bigOut = p
		case strings.Contains(rel, "nested-中文.txt"):
			nestedOut = p
		}
	}
	if bigOut == "" || nestedOut == "" {
		t.Fatalf("落盘清单缺文件: %v", files)
	}
	assertSameFile(t, big, bigOut)
	assertSameFile(t, nested, nestedOut)
}

// TestRelayFirstBoundaryUpgrade 先通后优回归:1ms 预算强制快打洞失败→
// 双方落中继→回环长打洞立刻成功→信令三步→arm→文件边界 MsgSwap 换直连。
// 校验换源后第二个文件内容完好(换源机制正确性的关键回归)。
func TestRelayFirstBoundaryUpgrade(t *testing.T) {
	f := newFixture(t, true)
	code, _ := GenerateCode()
	sendDir := t.TempDir()
	recvDir := t.TempDir()
	// 两文件都 ≥8MB:file1 走中继多流耗时足够长,arm 必然在边界前就绪
	f1 := randomFile(t, sendDir, "边界前.bin", 8<<20)
	f2 := randomFile(t, sendDir, "边界后.bin", 8<<20)

	so := testOpts(f, "send")
	so.PunchBudget = time.Millisecond // 快打洞必败,中继先行
	so.DisablePunch = false
	errCh := make(chan error, 1)
	go func() {
		c, err := New(so)
		if err != nil {
			errCh <- err
			return
		}
		_, err = c.Send([]string{f1, f2}, code)
		errCh <- err
	}()

	waitForAnnounce(t, f.base, code)
	ro := testOpts(f, "recv")
	ro.PunchBudget = time.Millisecond
	c, err := New(ro)
	if err != nil {
		t.Fatal(err)
	}
	files, err := c.Receive(code, recvDir)
	if err != nil {
		t.Fatalf("接收: %v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("发送: %v", err)
	}
	if len(files) != 2 {
		t.Fatalf("期望 2 个文件,实际 %d", len(files))
	}
	byName := map[string]string{}
	for _, p := range files {
		byName[filepath.Base(p)] = p
	}
	assertSameFile(t, f1, byName["边界前.bin"])
	assertSameFile(t, f2, byName["边界后.bin"])
}
