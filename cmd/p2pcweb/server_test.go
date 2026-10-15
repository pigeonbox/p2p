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
	"strings"
	"testing"
)

func TestGuardTokenAndHost(t *testing.T) {
	s := &Server{token: "secret", loopback: true, port: "12348"}
	h := s.guard(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

	get := func(host, target string, header string) int {
		r := httptest.NewRequest("GET", target, nil)
		r.Host = host
		if header != "" {
			r.Header.Set("X-P2PCWEB", header)
		}
		w := httptest.NewRecorder()
		h(w, r)
		return w.Code
	}

	if c := get("127.0.0.1:12348", "/?t=secret", ""); c != 200 {
		t.Fatalf("首屏文档查询令牌被拒: %d", c)
	}
	if c := get("127.0.0.1:12348", "/", "secret"); c != 200 {
		t.Fatalf("头令牌被拒: %d", c)
	}
	if c := get("localhost:12348", "/?t=secret", ""); c != 200 {
		t.Fatalf("localhost 被拒: %d", c)
	}
	// API 一律头令牌:query 令牌只放行首屏文档,防凭据进每个请求的 URL(日志面)
	if c := get("127.0.0.1:12348", "/api/state?t=secret", ""); c != http.StatusForbidden {
		t.Fatalf("API query 令牌应被拒, got %d", c)
	}
	for name, c := range map[string]int{
		"缺令牌":     get("127.0.0.1:12348", "/", ""),
		"错令牌":     get("127.0.0.1:12348", "/?t=wrong", ""),
		"rebind":  get("evil.example.com:12348", "/?t=secret", ""),
		"端口不符":    get("127.0.0.1:9999", "/?t=secret", ""),
		"无端口Host": get("127.0.0.1", "/?t=secret", ""),
	} {
		if c != http.StatusForbidden {
			t.Fatalf("%s 期望 403, got %d", name, c)
		}
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
