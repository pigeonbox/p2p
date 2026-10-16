package main

// 投递到柜测试：Box 客户端回环（httptest 假柜断言请求契约）+ handler 验证
// （配置缺失/路径越界/全链路）+ DONE 标记多路径解析。

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDeliverToBoxRoundTrip(t *testing.T) {
	var gotKey, gotName string
	gotFields := map[string]string{}
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/share/file/" {
			t.Errorf("路径不符: %s", r.URL.Path)
		}
		gotKey = r.Header.Get("X-API-Key")
		if r.ContentLength <= 0 {
			t.Errorf("请求应为定长, got %d", r.ContentLength)
		}
		mr, err := r.MultipartReader()
		if err != nil {
			t.Fatalf("multipart 解析: %v", err)
		}
		for {
			part, perr := mr.NextPart()
			if perr == io.EOF {
				break
			}
			if perr != nil {
				t.Fatalf("part: %v", perr)
			}
			if part.FormName() == "file" {
				gotName = part.FileName()
				gotBody, _ = io.ReadAll(part)
				continue
			}
			b, _ := io.ReadAll(part)
			gotFields[part.FormName()] = string(b)
		}
		_, _ = w.Write([]byte(`{"code":0,"message":"ok","data":{"code":"ab12cd","url":"http://x/s?code=ab12cd","pickup_code":"123456"}}`))
	}))
	defer srv.Close()

	dir := t.TempDir()
	p := filepath.Join(dir, "报告 final.pdf")
	if err := os.WriteFile(p, []byte("hello-box"), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := deliverToBox(srv.URL, "k-test", p)
	if err != nil {
		t.Fatalf("deliverToBox: %v", err)
	}
	if gotKey != "k-test" {
		t.Errorf("X-API-Key = %q", gotKey)
	}
	if gotName != "报告 final.pdf" {
		t.Errorf("filename = %q", gotName)
	}
	if string(gotBody) != "hello-box" {
		t.Errorf("文件体不符: %q", gotBody)
	}
	for k, want := range map[string]string{"expire_value": "1", "expire_style": "day", "require_auth": "false"} {
		if gotFields[k] != want {
			t.Errorf("字段 %s = %q, want %q", k, gotFields[k], want)
		}
	}
	if res.ShareCode != "ab12cd" || res.PickupCode != "123456" {
		t.Errorf("结果不符: %+v", res)
	}
}

func TestDeliverToBoxErrors(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "a.txt")
	_ = os.WriteFile(p, []byte("x"), 0o600)

	if _, err := deliverToBox("", "k", p); err == nil || !strings.Contains(err.Error(), "文件柜地址") {
		t.Errorf("空地址应报配置缺失, got %v", err)
	}
	if _, err := deliverToBox("http://x", "  ", p); err == nil || !strings.Contains(err.Error(), "API Key") {
		t.Errorf("空密钥应报配置缺失, got %v", err)
	}
	if _, err := deliverToBox("http://x", "k", dir); err == nil || !strings.Contains(err.Error(), "目录") {
		t.Errorf("目录应拒绝, got %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"code":401,"message":"API Key 无效"}`))
	}))
	defer srv.Close()
	_, err := deliverToBox(srv.URL, "bad", p)
	if err == nil || !strings.Contains(err.Error(), "API Key 无效") {
		t.Errorf("业务错误应透出 message, got %v", err)
	}
}

func TestHandleDeliverValidation(t *testing.T) {
	out := t.TempDir()
	inside := filepath.Join(out, "recv.bin")
	_ = os.WriteFile(inside, []byte("z"), 0o600)

	s := &Server{token: "t", mgr: NewManager(), cfg: &cfgStore{}, outDir: out}
	post := func(body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/api/deliver", strings.NewReader(body))
		w := httptest.NewRecorder()
		s.handleDeliver(w, r)
		return w
	}
	if c := post(`{}`).Code; c != http.StatusBadRequest {
		t.Errorf("空路径期望 400, got %d", c)
	}
	if c := post(`{"path":"` + inside + `"}`).Code; c != http.StatusBadRequest {
		t.Errorf("未配置柜应 400, got %d", c)
	}

	s.cfg = &cfgStore{c: Config{ServerURL: "http://box.example", BoxAPIKey: "k"}}
	if c := post(`{"path":"` + filepath.Join(os.TempDir(), "evil.bin") + `"}`).Code; c != http.StatusForbidden {
		t.Errorf("接收目录外应 403, got %d", c)
	}

	box := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-Key") != "k" {
			t.Errorf("API Key 未透传")
		}
		_, _ = w.Write([]byte(`{"code":0,"message":"ok","data":{"code":"xy","pickup_code":"654321","url":"u"}}`))
	}))
	defer box.Close()
	s.cfg = &cfgStore{c: Config{ServerURL: box.URL, BoxAPIKey: "k"}}
	w := post(`{"path":"` + inside + `"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("全链路期望 200, got %d: %s", w.Code, w.Body.String())
	}
	var res boxDeliverResult
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil || res.PickupCode != "654321" {
		t.Errorf("结果不符: %s", w.Body.String())
	}
}

func TestParseDonePaths(t *testing.T) {
	if got := parseDonePaths(doneMarker + " /tmp/a b.txt\x1f/tmp/c.txt"); len(got) != 2 || got[0] != "/tmp/a b.txt" || got[1] != "/tmp/c.txt" {
		t.Errorf("多路径解析: %q", got)
	}
	if got := parseDonePaths(doneMarker + " /only.txt"); len(got) != 1 || got[0] != "/only.txt" {
		t.Errorf("单路径解析(旧形态): %q", got)
	}
	if got := parseDonePaths(doneMarker); got != nil {
		t.Errorf("空标记应 nil: %q", got)
	}
}

func TestResolveToken(t *testing.T) {
	// 显式 --token 优先
	if got, _ := resolveToken(&options{token: " t1 "}); got != "t1" {
		t.Errorf("显式令牌未去空格: %q", got)
	}
	// 令牌文件:无则生成写入 0600,再读复用(跨重启稳定)
	dir := t.TempDir()
	p := filepath.Join(dir, "sub", "token")
	got1, err := resolveToken(&options{tokenFile: p})
	if err != nil || got1 == "" {
		t.Fatalf("首启生成失败: %v", err)
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatalf("令牌文件未落盘: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("令牌文件权限: %v", fi.Mode().Perm())
	}
	got2, _ := resolveToken(&options{tokenFile: p})
	if got2 != got1 {
		t.Errorf("重启后令牌漂移: %q != %q", got2, got1)
	}
	// 两者都空 = 随机(非空即可)
	got3, err := resolveToken(&options{})
	if err != nil || got3 == "" {
		t.Fatalf("随机令牌: %v", err)
	}
}

// 回归:handleConfig 的 snake_case 键必须真正落盘(曾因匿名结构体缺 tag 整体解码为零值,
// 「自动保存」静默失效——真机 fnOS 实测抓到)。走 handler 全链路断言 store 内容。
func TestHandleConfigRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s := &Server{token: "t", mgr: NewManager(), cfg: newCfgStoreAt(filepath.Join(dir, "cfg.json"))}
	body := `{"server_url":"http://box.example","registry":"http://reg.example","box_api_key":"k-123"}`
	r := httptest.NewRequest("POST", "/api/config", strings.NewReader(body))
	w := httptest.NewRecorder()
	s.handleConfig(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("保存期望 200, got %d", w.Code)
	}
	cfg := s.cfg.get()
	if cfg.ServerURL != "http://box.example" || cfg.Registry != "http://reg.example" || cfg.BoxAPIKey != "k-123" {
		t.Fatalf("配置未落盘: %+v", cfg)
	}
	if fi, err := os.Stat(filepath.Join(dir, "cfg.json")); err != nil || fi.Size() == 0 {
		t.Fatalf("配置文件未写: %v", err)
	}
}
