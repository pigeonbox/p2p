package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestGuardTokenAndHost(t *testing.T) {
	s := &Server{token: "secret", loopback: true, port: "12348"}
	s.pairs, _ = newPairStore(pairCodeTTL)
	s.sessions = newSessionStore()
	h := s.guard(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

	get := func(host, target string, header string) (int, string) {
		r := httptest.NewRequest("GET", target, nil)
		r.Host = host
		if header != "" {
			r.Header.Set("X-P2PCWEB", header)
		}
		w := httptest.NewRecorder()
		h(w, r)
		return w.Code, w.Body.String()
	}

	if c, _ := get("127.0.0.1:12348", "/api/state", "secret"); c != 200 {
		t.Fatalf("头令牌被拒: %d", c)
	}
	// 首屏文档未认证 → 登录页（200，但不含应用 UI/凭据），而不是把令牌塞回 URL
	if c, body := get("127.0.0.1:12348", "/", ""); c != 200 || !strings.Contains(body, "访问验证") {
		t.Fatalf("未认证首屏应返回登录页, got %d", c)
	}
	// p2p#58：URL query 里的长期令牌一律不再接受（不认证、不放行应用）
	if c, body := get("127.0.0.1:12348", "/?t=secret", ""); c != 200 || strings.Contains(body, "文件柜") {
		t.Fatalf("query 令牌不得认证成功, got %d", c)
	}
	if c, _ := get("127.0.0.1:12348", "/api/state?t=secret", ""); c != http.StatusForbidden {
		t.Fatalf("API query 令牌应被拒, got %d", c)
	}
	if c, _ := get("localhost:12348", "/api/state", "secret"); c != 200 {
		t.Fatalf("localhost 头令牌被拒: %d", c)
	}
	for name, tc := range map[string]struct{ host, target, header string }{
		"缺令牌":     {"127.0.0.1:12348", "/api/state", ""},
		"错令牌":     {"127.0.0.1:12348", "/api/state", "wrong"},
		"rebind":  {"evil.example.com:12348", "/", "secret"},
		"端口不符":    {"127.0.0.1:9999", "/", "secret"},
		"无端口Host": {"127.0.0.1", "/", "secret"},
	} {
		if c, _ := get(tc.host, tc.target, tc.header); c != http.StatusForbidden {
			t.Fatalf("%s 期望 403, got %d", name, c)
		}
	}
}

// TestPairCodeExchangeAndCookie 一次性配对码 → 303 + HttpOnly 会话 Cookie；
// 复用/过期/错误码拒绝；Cookie 可访问 API。
func TestPairCodeExchangeAndCookie(t *testing.T) {
	s := &Server{token: "secret", loopback: true, port: "12348", cfg: &cfgStore{}, mgr: NewManager(), shares: newShareTable()}
	s.pairs, _ = newPairStore(pairCodeTTL)
	s.sessions = newSessionStore()
	ts := httptest.NewServer(s.routes())
	defer ts.Close()
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(ts.URL, "http://"))
	s.port = port

	// 手动跟随跳转，保留 Cookie
	jar := &cookieJar{}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	u := ts.URL + "/?c=" + s.pairs.code
	req, _ := http.NewRequest("GET", u, nil)
	req.Host = "127.0.0.1:" + port
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("配对码兑换期望 303, got %d", resp.StatusCode)
	}
	cookies := resp.Cookies()
	if len(cookies) != 1 || cookies[0].Name != sessionCookie || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatalf("会话 Cookie 形态不对: %+v", cookies)
	}
	if strings.Contains(resp.Header.Get("Location"), "?") {
		t.Fatalf("跳转地址不应带 query: %s", resp.Header.Get("Location"))
	}
	jar.add(cookies[0])

	// 复用同一配对码 → 403（用后即焚）
	req, _ = http.NewRequest("GET", u, nil)
	req.Host = "127.0.0.1:" + port
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("配对码复用应 403, got %d", resp.StatusCode)
	}

	// 会话 Cookie 访问 API
	req, _ = http.NewRequest("GET", ts.URL+"/api/state", nil)
	req.Host = "127.0.0.1:" + port
	req.AddCookie(jar.get(sessionCookie))
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(body), "\"out_dir\"") {
		t.Fatalf("Cookie 会话访问 API 失败: %d %s", resp.StatusCode, body)
	}
}

// TestPairFormLogin 登录表单：错误凭据 401；令牌正确 → 303 + Cookie。
func TestPairFormLogin(t *testing.T) {
	s := &Server{token: "secret", loopback: true, port: "12348"}
	s.pairs, _ = newPairStore(pairCodeTTL)
	s.sessions = newSessionStore()
	ts := httptest.NewServer(s.routes())
	defer ts.Close()
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(ts.URL, "http://"))
	s.port = port

	post := func(form string) *http.Response {
		req, _ := http.NewRequest("POST", ts.URL+"/pair", strings.NewReader(form))
		req.Host = "127.0.0.1:" + port
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		// 不跟随跳转
		c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	resp := post("token=wrong")
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("错误令牌期望 401, got %d", resp.StatusCode)
	}
	resp = post("token=secret")
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || len(resp.Cookies()) == 0 {
		t.Fatalf("正确令牌期望 303 + Cookie, got %d", resp.StatusCode)
	}
}

// cookieJar 最小会话罐（避免为一条测试引入 cookiejar 依赖）。
type cookieJar struct{ c []*http.Cookie }

func (j *cookieJar) add(c *http.Cookie) { j.c = append(j.c, c) }
func (j *cookieJar) get(name string) *http.Cookie {
	for i := len(j.c) - 1; i >= 0; i-- {
		if j.c[i].Name == name {
			return j.c[i]
		}
	}
	return nil
}

// TestStartupURLsOmitLongLivedToken 启动日志/自动打开 URL 不含长期令牌，
// URL 里没有 ?t=；自动打开只带一次性 code（p2p#58 验收）。
func TestStartupURLsOmitLongLivedToken(t *testing.T) {
	token := "deadbeefdeadbeefdeadbeefdeadbeef"
	pairs, err := newPairStore(pairCodeTTL)
	if err != nil {
		t.Fatal(err)
	}
	base := accessURL("127.0.0.1", "12348")
	open := pairAccessURL(base, pairs.code)
	if strings.Contains(base, token) || strings.Contains(open, token) {
		t.Fatalf("URL 泄露长期令牌: base=%q open=%q", base, open)
	}
	if strings.Contains(base, "?t=") || strings.Contains(open, "?t=") || strings.Contains(open, "t="+token) {
		t.Fatalf("URL 出现 ?t= 形态: base=%q open=%q", base, open)
	}
	if !strings.HasSuffix(base, "/") || strings.Contains(base, "?") {
		t.Fatalf("启动日志地址应为不含 query 的 host:port: %q", base)
	}
	if !strings.Contains(open, "?c="+pairs.code) {
		t.Fatalf("自动打开 URL 应只带一次性 code: %q", open)
	}
	// 配对码自身是短票，不是长期令牌
	if pairs.code == token {
		t.Fatal("配对码不得等于长期令牌")
	}
}

func TestNormalizeBaseURL(t *testing.T) {
	cases := [][2]string{
		{"10.0.0.1", "http://10.0.0.1"},
		{"http://a.b/", "http://a.b"},
		{`"https://c.d/"`, "https://c.d"},
		{"  1.2.3.4:8080  ", "http://1.2.3.4:8080"},
		{"", ""},
	}
	for _, c := range cases {
		if got := normalizeBaseURL(c[0]); got != c[1] {
			t.Errorf("normalizeBaseURL(%q) = %q, want %q", c[0], got, c[1])
		}
	}
}

func TestHandleRecvValidation(t *testing.T) {
	s := &Server{token: "t", mgr: NewManager(), cfg: &cfgStore{}}

	r := httptest.NewRequest("POST", "/api/recv", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	s.handleRecv(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("空口令期望 400, got %d", w.Code)
	}

	r = httptest.NewRequest("POST", "/api/recv", strings.NewReader(`{"code":"AAAA-BBBB-CCCC"}`))
	w = httptest.NewRecorder()
	s.handleRecv(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("缺 registry 期望 400, got %d", w.Code)
	}
}

func TestHandleSendValidation(t *testing.T) {
	s := &Server{token: "t", maxUpload: 1 << 20, mgr: NewManager()}

	r := httptest.NewRequest("POST", "/api/send", nil)
	w := httptest.NewRecorder()
	s.handleSend(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("缺 registry 期望 400, got %d", w.Code)
	}

	r = httptest.NewRequest("POST", "/api/send?t=1&registry=http://r", strings.NewReader("x"))
	w = httptest.NewRecorder()
	s.handleSend(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("非 multipart 期望 400, got %d", w.Code)
	}
}

// TestShareDownloadRoundtrip 浏览器直下:上传→列表→令牌下载(单文件+多文件 zip)。
func TestShareDownloadRoundtrip(t *testing.T) {
	s := &Server{token: "tk", maxUpload: 1 << 20, shares: newShareTable(), mgr: NewManager()}
	ts := httptest.NewServer(s.routes())
	defer ts.Close()
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(ts.URL, "http://"))
	s.port = port

	// 上传两个文件(走 zip 分支)
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for _, name := range []string{"甲.txt", "sub/乙.bin"} {
		fw, _ := mw.CreateFormFile("file", name)
		_, _ = fw.Write([]byte("content-of-" + name))
	}
	_ = mw.Close()
	req, _ := http.NewRequest("POST", ts.URL+"/api/share", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("X-P2PCWEB", "tk")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("share: %d %s", resp.StatusCode, body)
	}
	var out struct{ ID, URL, Name string }
	_ = json.Unmarshal(body, &out)

	// 列表必须携带 name/url/expires(share 字段未导出曾致列表输出 [{}])
	lreq, _ := http.NewRequest("GET", ts.URL+"/api/shares", nil)
	lreq.Header.Set("X-P2PCWEB", "tk")
	lr, err := http.DefaultClient.Do(lreq)
	if err != nil {
		t.Fatal(err)
	}
	lb := mustReadAll(lr.Body)
	_ = lr.Body.Close()
	if !strings.Contains(string(lb), `"name":"`) || !strings.Contains(string(lb), `"url":"/d/`) {
		t.Fatalf("分享列表缺 name/url 字段: %s", lb)
	}

	// 下载(令牌在 query)
	dl, err := http.Get(ts.URL + out.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = dl.Body.Close() }()
	if dl.StatusCode != 200 || !strings.Contains(dl.Header.Get("Content-Type"), "zip") {
		t.Fatalf("下载: %d %s", dl.StatusCode, dl.Header.Get("Content-Type"))
	}
	raw := mustReadAll(dl.Body)
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatalf("zip 解析: %v", err)
	}
	if len(zr.File) != 2 {
		t.Fatalf("zip 应含 2 文件,实际 %d", len(zr.File))
	}

	// 错令牌必须 404
	bad, _ := http.Get(ts.URL + "/d/" + out.ID + "?t=wrong")
	_ = bad.Body.Close()
	if bad.StatusCode != 404 {
		t.Fatalf("错令牌应 404,实际 %d", bad.StatusCode)
	}
}

func mustReadAll(rc io.Reader) []byte {
	b, _ := io.ReadAll(rc)
	return b
}

// lockedBuffer 供子进程输出与测试 goroutine 并发读写（-race 下安全）。
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// TestStartupOutputOmitsAccessToken 真进程验收（p2p#58）：默认启动输出里
// 不能出现长期令牌，界面 URL 不能带 ?t=；一次性配对码可打印但必须短票且
// 与长期令牌不同。
func TestStartupOutputOmitsAccessToken(t *testing.T) {
	if testing.Short() {
		t.Skip("需要编译 p2pc-web 二进制")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "p2pcweb")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("构建 p2pc-web 失败: %v\n%s", err, out)
	}
	tokenFile := filepath.Join(dir, "token")
	cmd := exec.Command(bin, "--addr", "127.0.0.1:0", "--no-open", "--token-file", tokenFile)
	out := &lockedBuffer{}
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()

	var token string
	deadline := time.Now().Add(20 * time.Second)
	for {
		b, _ := os.ReadFile(tokenFile)
		if len(b) > 0 && strings.Contains(out.String(), "一次性配对码:") {
			token = strings.TrimSpace(string(b))
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("启动输出超时:\n%s", out.String())
		}
		time.Sleep(50 * time.Millisecond)
	}

	logText := out.String()
	if token == "" {
		t.Fatal("令牌文件为空")
	}
	if strings.Contains(logText, token) {
		t.Fatalf("启动日志泄露长期访问令牌 %q:\n%s", token, logText)
	}
	if strings.Contains(logText, "?t=") {
		t.Fatalf("启动日志出现 ?t= 形态:\n%s", logText)
	}
	// 界面地址行不得含任何凭据（只有 host:port/）
	var uiLine string
	for _, line := range strings.Split(logText, "\n") {
		if strings.Contains(line, "界面:") {
			uiLine = strings.TrimSpace(line)
		}
	}
	if uiLine == "" || !strings.Contains(uiLine, "http://127.0.0.1:") || strings.ContainsAny(uiLine, "?") {
		t.Fatalf("界面地址应为不含 query 的 http://host:port/: %q", uiLine)
	}
	// 一次性配对码：必须存在、与长期令牌不同、且不是从 URL query 形态打印
	const marker = "一次性配对码: "
	i := strings.Index(logText, marker)
	if i < 0 {
		t.Fatalf("缺少一次性配对码提示:\n%s", logText)
	}
	rest := logText[i+len(marker):]
	code := rest
	if j := strings.IndexAny(rest, "（\n"); j >= 0 {
		code = rest[:j]
	}
	code = strings.TrimSpace(code)
	if code == "" || code == token {
		t.Fatalf("一次性配对码异常: %q（token=%q）", code, token)
	}
}
