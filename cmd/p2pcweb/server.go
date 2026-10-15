package main

// 本地服务：回环 HTTP + 内嵌网页 UI + SSE 日志流 + 传输编排 API。
// 安全面：默认仅绑 127.0.0.1；全路由要求启动时生成的随机令牌（恒时比较），
// 回环部署下校验 Host 头防 DNS rebinding；无 CORS 头（同源才可读）。

import (
	"archive/zip"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/pigeonbox/kit/version"
	"github.com/pigeonbox/p2p/internal/client"
)

//go:embed web/index.html
var webFS embed.FS

// Server 网页模式服务。
type Server struct {
	token     string
	loopback  bool
	port      string
	maxUpload int64
	outDir    string
	relay     string // 透传子模式的中继地址（空=按注册中心 host 推导；测试注入用）
	noPunch   bool   // 透传子模式禁用打洞（默认 false；测试确定性用）
	cfg       *cfgStore
	mgr       *Manager
	shares    *shareTable
}

// shareTable 浏览器直下分享:一次性令牌链接,15 分钟过期,上限 4 个在席。
// 独立于主令牌门禁(对端浏览器拿不到 p2pcweb 令牌);链接即凭据,仅限
// 可信网络分享。多文件/目录以 zip 流式响应(边打边发,不落盘)。
type shareTable struct {
	mu    sync.Mutex
	items map[string]*share // id → share
}

type share struct {
	id      string
	token   string
	name    string
	path    string // 单文件路径或组目录
	isDir   bool
	expires time.Time
}

const (
	shareTTL       = 15 * time.Minute
	shareMaxActive = 4
)

func newShareTable() *shareTable { return &shareTable{items: map[string]*share{}} }

func (t *shareTable) add(name, path string, isDir bool) (*share, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	// 过期清扫
	now := time.Now()
	for id, sh := range t.items {
		if now.After(sh.expires) {
			delete(t.items, id)
		}
	}
	if len(t.items) >= shareMaxActive {
		return nil, errors.New("在席分享已达上限(4),请先取消旧的")
	}
	id, err := newToken()
	if err != nil {
		return nil, err
	}
	tok, err := newToken()
	if err != nil {
		return nil, err
	}
	sh := &share{id: id, token: tok, name: name, path: path, isDir: isDir, expires: now.Add(shareTTL)}
	t.items[id] = sh
	return sh, nil
}

func (t *shareTable) get(id, token string) *share {
	t.mu.Lock()
	defer t.mu.Unlock()
	sh := t.items[id]
	if sh == nil || !secureEqual(token, sh.token) || time.Now().After(sh.expires) {
		return nil
	}
	return sh
}

func (t *shareTable) drop(id string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.items[id]; !ok {
		return false
	}
	delete(t.items, id)
	return true
}

func (t *shareTable) list() []share {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]share, 0, len(t.items))
	now := time.Now()
	for id, sh := range t.items {
		if now.After(sh.expires) {
			delete(t.items, id)
			continue
		}
		out = append(out, *sh)
	}
	return out
}

// shareJSON 列表输出形态。share 字段未导出(不直接序列化,曾致列表输出 [{}]
// 界面整行空白);url 在此拼好(含一次性令牌),仅供持主令牌的本机界面消费。
type shareJSON struct {
	ID      string    `json:"id"`
	URL     string    `json:"url"`
	Name    string    `json:"name"`
	IsDir   bool      `json:"is_dir"`
	Expires time.Time `json:"expires"`
}

func toShareJSON(s share) shareJSON {
	return shareJSON{
		ID:      s.id,
		URL:     "/d/" + s.id + "?t=" + s.token,
		Name:    s.name,
		IsDir:   s.isDir,
		Expires: s.expires,
	}
}

func newToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// secureEqual 恒时比较(先双侧 SHA-256 定长化,消除长度侧信道;与
// internal/server 同款)。
func secureEqual(a, b string) bool {
	ha := sha256.Sum256([]byte(a))
	hb := sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(ha[:], hb[:]) == 1
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// guard 令牌 + Host 校验。
// 令牌优先取 X-P2PCWEB 头;query 令牌仅对首屏文档请求(/)放行——API 若也
// 收 query 令牌,每个请求的 URL 都带凭据,会进反代/浏览器历史等日志面。
// 页面加载后由前端把令牌挪入 sessionStorage 并以头方式携带,URL 里的
// ?t= 只在入口那一次出现。
func (s *Server) guard(fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := r.Header.Get("X-P2PCWEB")
		if tok == "" && r.URL.Path == "/" {
			tok = r.URL.Query().Get("t")
		}
		if !secureEqual(tok, s.token) {
			http.Error(w, "403：令牌无效，请从启动时打印的完整地址进入", http.StatusForbidden)
			return
		}
		if s.loopback && !s.sameLoopbackHost(r.Host) {
			// 防 DNS rebinding：回环部署下 Host 必须是本机回环名 + 本服务端口
			http.Error(w, "403：Host 校验失败", http.StatusForbidden)
			return
		}
		fn(w, r)
	}
}

// sameLoopbackHost Host 头须为回环主机名 + 本服务端口。
func (s *Server) sameLoopbackHost(hostPort string) bool {
	host, port, err := net.SplitHostPort(hostPort)
	if err != nil {
		return false
	}
	if port != s.port {
		return false
	}
	switch strings.ToLower(host) {
	case "127.0.0.1", "::1", "localhost":
		return true
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return true
	}
	return false
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.guard(s.handleIndex))
	mux.HandleFunc("/api/state", s.guard(s.handleState))
	mux.HandleFunc("/api/config", s.guard(s.handleConfig))
	mux.HandleFunc("/api/send", s.guard(s.handleSend))
	mux.HandleFunc("/api/recv", s.guard(s.handleRecv))
	mux.HandleFunc("/api/cancel", s.guard(s.handleCancel))
	mux.HandleFunc("/api/events", s.guard(s.handleEvents))
	mux.HandleFunc("POST /api/share", s.guard(s.handleShare))
	mux.HandleFunc("GET /api/shares", s.guard(s.handleShareList))
	mux.HandleFunc("POST /api/share/cancel", s.guard(s.handleShareCancel))
	mux.HandleFunc("GET /d/{id}", s.handleDownload) // 独立令牌门禁(对端浏览器无主令牌)
	return mux
}

func (s *Server) handleIndex(w http.ResponseWriter, _ *http.Request) {
	b, err := webFS.ReadFile("web/index.html")
	if err != nil {
		http.Error(w, "内置页面缺失", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(b)
}

func (s *Server) handleState(w http.ResponseWriter, _ *http.Request) {
	cfg := s.cfg.get()
	writeJSON(w, http.StatusOK, map[string]any{
		"busy":       s.mgr.Busy(),
		"role":       s.mgr.Role(),
		"code":       s.mgr.Code(),
		"server_url": cfg.ServerURL,
		"registry":   cfg.Registry,
		"out_dir":    s.outDir,
		"version":    version.Version,
		"max_upload": s.maxUpload,
	})
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	var in struct{ ServerURL, Registry string }
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "请求体非法")
		return
	}
	cfg := s.cfg.get()
	if in.ServerURL != "" {
		cfg.ServerURL = normalizeBaseURL(in.ServerURL)
	}
	if in.Registry != "" {
		cfg.Registry = normalizeBaseURL(in.Registry)
	}
	if err := s.cfg.set(cfg); err != nil {
		writeErr(w, http.StatusInternalServerError, "保存失败: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"ok": "1"})
}

// normalizeBaseURL 宽容归一：补 http://、去尾斜杠（与桌面端设置页一致）。
func normalizeBaseURL(raw string) string {
	t := strings.TrimSpace(raw)
	t = strings.Trim(t, `"'`)
	t = strings.TrimRight(t, "/")
	if t == "" {
		return ""
	}
	if strings.HasPrefix(t, "http://") || strings.HasPrefix(t, "https://") {
		return t
	}
	return "http://" + t
}

// handleSend 流式收上传 → 临时目录（保留原始文件名）→ 拉起发送。
func (s *Server) handleSend(w http.ResponseWriter, r *http.Request) {
	registry := normalizeBaseURL(r.URL.Query().Get("registry"))
	if registry == "" {
		writeErr(w, http.StatusBadRequest, "请填写直传注册中心地址")
		return
	}
	if s.mgr.Busy() {
		writeErr(w, http.StatusConflict, ErrBusy.Error())
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, s.maxUpload+(1<<20))
	mr, err := r.MultipartReader()
	if err != nil {
		writeErr(w, http.StatusBadRequest, "需要 multipart 文件表单")
		return
	}
	tmpDir, err := os.MkdirTemp("", "p2pcweb-upload-")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "临时目录创建失败: "+err.Error())
		return
	}
	cleanup := func() { _ = os.RemoveAll(tmpDir) }

	// 多文件:收齐全部 file part;单文件直发(原名),多文件归组到
	// 「PigeonBox 共享 <时间>」目录(对端 manifest 呈现组名/相对路径)。
	var saved int
	var single string
	for {
		part, perr := mr.NextPart()
		if errors.Is(perr, io.EOF) {
			break
		}
		if perr != nil {
			cleanup()
			writeErr(w, http.StatusBadRequest, "表单解析失败")
			return
		}
		if part.FormName() != "file" {
			_ = part.Close()
			continue
		}
		dest := filepath.Join(tmpDir, sanitizeName(part.FileName()))
		f, ferr := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if ferr != nil {
			cleanup()
			writeErr(w, http.StatusInternalServerError, "临时文件创建失败: "+ferr.Error())
			return
		}
		n, cerr := io.Copy(f, part)
		fClose := f.Close()
		_ = part.Close()
		if cerr != nil || fClose != nil {
			cleanup()
			writeErr(w, http.StatusBadRequest, "上传读取失败")
			return
		}
		if n > s.maxUpload {
			cleanup()
			writeErr(w, http.StatusRequestEntityTooLarge,
				fmt.Sprintf("文件超过上限 %d 字节（--max-upload 可调）", s.maxUpload))
			return
		}
		if n == 0 {
			cleanup()
			writeErr(w, http.StatusBadRequest, "空文件: "+part.FileName())
			return
		}
		saved++
		single = dest
	}
	if saved == 0 {
		cleanup()
		writeErr(w, http.StatusBadRequest, "缺少 file 字段")
		return
	}
	dest := single
	if saved > 1 {
		group := filepath.Join(tmpDir, "PigeonBox 共享 "+time.Now().Format("01-02 15:04"))
		if err := os.Mkdir(group, 0o700); err != nil {
			cleanup()
			writeErr(w, http.StatusInternalServerError, "组目录创建失败: "+err.Error())
			return
		}
		entries, _ := os.ReadDir(tmpDir)
		for _, en := range entries {
			if en.IsDir() {
				continue
			}
			if err := os.Rename(filepath.Join(tmpDir, en.Name()), filepath.Join(group, en.Name())); err != nil {
				cleanup()
				writeErr(w, http.StatusInternalServerError, "归组失败: "+err.Error())
				return
			}
		}
		dest = group
	}

	code, err := client.GenerateCode()
	if err != nil {
		cleanup()
		writeErr(w, http.StatusInternalServerError, "口令生成失败: "+err.Error())
		return
	}
	if err := s.mgr.Start("send", registry, code, dest, "", s.relay, s.noPunch, cleanup); err != nil {
		cleanup()
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"code": code})
}

// multipartPart 已移除（直接用 *multipart.Part）。

func (s *Server) handleRecv(w http.ResponseWriter, r *http.Request) {
	var in struct{ Code, Registry string }
	if err := json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "请求体非法")
		return
	}
	code := strings.ToUpper(strings.TrimSpace(in.Code))
	registry := normalizeBaseURL(in.Registry)
	if code == "" {
		writeErr(w, http.StatusBadRequest, "请输入口令")
		return
	}
	if registry == "" {
		writeErr(w, http.StatusBadRequest, "请填写直传注册中心地址")
		return
	}
	_ = s.cfg.set(Config{ServerURL: s.cfg.get().ServerURL, Registry: registry})
	if err := s.mgr.Start("recv", registry, code, "", s.outDir, s.relay, s.noPunch, nil); err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"ok": "1"})
}

// handleShare 创建浏览器直下分享(multipart 与 handleSend 同构,无需注册中心)。
func (s *Server) handleShare(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, s.maxUpload*4+(1<<20))
	mr, err := r.MultipartReader()
	if err != nil {
		writeErr(w, http.StatusBadRequest, "需要 multipart 文件表单")
		return
	}
	tmpDir, err := os.MkdirTemp("", "p2pcweb-share-")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "临时目录创建失败: "+err.Error())
		return
	}
	cleanup := func() { _ = os.RemoveAll(tmpDir) }
	var saved int
	var single string
	singleName := ""
	for {
		part, perr := mr.NextPart()
		if errors.Is(perr, io.EOF) {
			break
		}
		if perr != nil {
			cleanup()
			writeErr(w, http.StatusBadRequest, "表单解析失败")
			return
		}
		if part.FormName() != "file" {
			_ = part.Close()
			continue
		}
		dest := filepath.Join(tmpDir, sanitizeName(part.FileName()))
		f, ferr := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if ferr != nil {
			cleanup()
			writeErr(w, http.StatusInternalServerError, "临时文件创建失败: "+ferr.Error())
			return
		}
		n, cerr := io.Copy(f, part)
		fClose := f.Close()
		_ = part.Close()
		if cerr != nil || fClose != nil {
			cleanup()
			writeErr(w, http.StatusBadRequest, "上传读取失败")
			return
		}
		if n > s.maxUpload {
			cleanup()
			writeErr(w, http.StatusRequestEntityTooLarge,
				fmt.Sprintf("文件超过上限 %d 字节（--max-upload 可调）", s.maxUpload))
			return
		}
		if n == 0 {
			cleanup()
			writeErr(w, http.StatusBadRequest, "空文件: "+part.FileName())
			return
		}
		saved++
		single, singleName = dest, part.FileName()
	}
	if saved == 0 {
		cleanup()
		writeErr(w, http.StatusBadRequest, "缺少 file 字段")
		return
	}
	name := singleName
	path := single
	isDir := false
	if saved > 1 {
		name = "PigeonBox 共享 " + time.Now().Format("01-02 15:04") + ".zip"
		path = tmpDir
		isDir = true
	}
	sh, err := s.shares.add(name, path, isDir)
	if err != nil {
		cleanup()
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	go func() {
		// 过期后清理临时目录(shares 表过期惰性清扫;临时目录按 TTL+1min 兜底)
		time.Sleep(shareTTL + time.Minute)
		_ = os.RemoveAll(tmpDir)
	}()
	writeJSON(w, http.StatusOK, map[string]string{
		"id": sh.id, "url": "/d/" + sh.id + "?t=" + sh.token,
		"name": name, "expires": sh.expires.Format(time.RFC3339),
	})
}

func (s *Server) handleShareList(w http.ResponseWriter, _ *http.Request) {
	items := s.shares.list()
	out := make([]shareJSON, 0, len(items))
	for _, sh := range items {
		out = append(out, toShareJSON(sh))
	}
	writeJSON(w, http.StatusOK, map[string]any{"shares": out})
}

func (s *Server) handleShareCancel(w http.ResponseWriter, r *http.Request) {
	var in struct{ ID string }
	if err := json.NewDecoder(io.LimitReader(r.Body, 4<<10)).Decode(&in); err != nil || in.ID == "" {
		writeErr(w, http.StatusBadRequest, "请求体非法")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": s.shares.drop(in.ID)})
}

// handleDownload 浏览器直下端点:share 令牌门禁(恒时比较),单文件
// ServeContent(天然支持 Range 断点),目录 zip 流式(边压边发)。
func (s *Server) handleDownload(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	sh := s.shares.get(id, r.URL.Query().Get("t"))
	if sh == nil {
		http.Error(w, "404：链接无效或已过期", http.StatusNotFound)
		return
	}
	if !sh.isDir {
		f, err := os.Open(sh.path)
		if err != nil {
			http.Error(w, "文件已不可用", http.StatusGone)
			return
		}
		defer func() { _ = f.Close() }()
		w.Header().Set("Content-Disposition",
			`attachment; filename*=UTF-8''`+mimeEscape(sh.name))
		http.ServeContent(w, r, sh.name, time.Now(), f)
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition",
		`attachment; filename*=UTF-8''`+mimeEscape(sh.name))
	zw := zip.NewWriter(w)
	defer func() { _ = zw.Close() }()
	_ = filepath.WalkDir(sh.path, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		rel, rerr := filepath.Rel(sh.path, p)
		if rerr != nil {
			return nil
		}
		f, oerr := os.Open(p)
		if oerr != nil {
			return nil
		}
		defer func() { _ = f.Close() }()
		hdr := &zip.FileHeader{Name: filepath.ToSlash(rel), Method: zip.Deflate, Modified: time.Now()}
		fw, zerr := zw.CreateHeader(hdr)
		if zerr != nil {
			return zerr
		}
		_, _ = io.Copy(fw, f)
		return nil
	})
}

// mimeEscape RFC 5987 filename* 转义(UTF-8 百分号编码)。
func mimeEscape(name string) string {
	const hexdig = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			strings.IndexByte("-_.!~*'()", c) >= 0:
			b.WriteByte(c)
		default:
			b.WriteByte('%')
			b.WriteByte(hexdig[c>>4])
			b.WriteByte(hexdig[c&0xf])
		}
	}
	return "UTF-8''" + b.String()
}

func (s *Server) handleCancel(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]bool{"cancelled": s.mgr.Cancel()})
}

// handleEvents SSE：日志/口令/退出事件实时推送，15s 心跳保活。
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "不支持流式响应", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")

	ch := s.mgr.Subscribe()
	defer s.mgr.Unsubscribe(ch)
	tick := time.NewTicker(15 * time.Second)
	defer tick.Stop()

	// 快照：订阅后若传输已结束不再有事件，补一条状态让页面收敛
	writeSSE(w, fl, Event{Type: "state", Code: s.mgr.Code(), Busy: s.mgr.Busy(), Role: s.mgr.Role()})
	for {
		select {
		case ev, ok := <-ch:
			if !ok {
				return
			}
			writeSSE(w, fl, ev)
		case <-tick.C:
			if _, err := fmt.Fprint(w, ": ping\n\n"); err != nil {
				return
			}
			fl.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

func writeSSE(w http.ResponseWriter, fl http.Flusher, ev Event) {
	b, err := json.Marshal(ev)
	if err != nil {
		return
	}
	if _, err := fmt.Fprintf(w, "data: %s\n\n", b); err != nil {
		return
	}
	fl.Flush()
}

func boolStr(b bool) string {
	if b {
		return "1"
	}
	return ""
}
