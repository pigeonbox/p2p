package main

// 本地配置与目录解析：网页模式的两个记忆项（文件柜地址、直传注册中心）+
// 接收目录的国产桌面适配（统信/麒麟中文桌面下载目录多为 ~/下载，走 XDG）。

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Config 持久化配置。
type Config struct {
	ServerURL string `json:"server_url"`  // 文件柜地址（浏览器打开用；投递到柜的目标）
	Registry  string `json:"registry"`    // 直传注册中心地址
	BoxAPIKey string `json:"box_api_key"` // 文件柜 API Key（投递到柜；经 X-API-Key 调 /share/file/）
}

func configPath() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "pigeonbox", "p2pcweb.json"), nil
}

// cfgStore 带锁的配置存取（HTTP 并发写安全）。
type cfgStore struct {
	mu sync.Mutex
	p  string
	c  Config
}

func newCfgStore() *cfgStore {
	p, _ := configPath()
	return newCfgStoreAt(p)
}

func newCfgStoreAt(p string) *cfgStore {
	var c Config
	if p != "" {
		if b, err := os.ReadFile(p); err == nil {
			_ = json.Unmarshal(b, &c)
		}
	}
	return &cfgStore{p: p, c: c}
}

func (s *cfgStore) get() Config {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.c
}

func (s *cfgStore) set(c Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.p == "" {
		return errors.New("配置路径不可用")
	}
	if err := os.MkdirAll(filepath.Dir(s.p), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(s.p, b, 0o600); err != nil {
		return err
	}
	s.c = c
	return nil
}

// resolveDownloadDir 接收目录优先级：--out > XDG_DOWNLOAD_DIR > ~/Downloads|~/下载 > 当前目录。
func resolveDownloadDir(flagOut string) string {
	if flagOut != "" {
		return flagOut
	}
	if x := xdgDownloadDir(); x != "" {
		return x
	}
	if home, err := os.UserHomeDir(); err == nil {
		for _, name := range []string{"Downloads", "下载"} {
			p := filepath.Join(home, name)
			if fi, err := os.Stat(p); err == nil && fi.IsDir() {
				return p
			}
		}
	}
	return "."
}

// xdgDownloadDir 解析 ~/.config/user-dirs.dirs 的 XDG_DOWNLOAD_DIR
// （统信/麒麟等中文桌面由 xdg-user-dirs 生成为 ~/下载）。
func xdgDownloadDir() string {
	base, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	b, err := os.ReadFile(filepath.Join(base, "user-dirs.dirs"))
	if err != nil {
		return ""
	}
	return parseXDGDownload(string(b), homeOrEmpty())
}

func homeOrEmpty() string {
	h, _ := os.UserHomeDir()
	return h
}

// parseXDGDownload 纯函数（可测）：从 user-dirs.dirs 内容取下载目录。
func parseXDGDownload(content, home string) string {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "XDG_DOWNLOAD_DIR") {
			continue
		}
		eq := strings.Index(line, "=")
		if eq < 0 {
			return ""
		}
		v := strings.Trim(strings.TrimSpace(line[eq+1:]), `"`)
		v = strings.ReplaceAll(v, "$HOME", home)
		if v == "" {
			return ""
		}
		if fi, err := os.Stat(v); err == nil && fi.IsDir() {
			return v
		}
		return ""
	}
	return ""
}

// sanitizeName 浏览器上传文件名 → 安全落盘名：仅取 base，去分隔符/控制字符，
// 限长（保后缀）。对端收到的文件名 = 该文件的 base（client SendFile 用
// filepath.Base(path) 作 meta.Name），故必须落成原始文件名。
func sanitizeName(name string) string {
	name = filepath.Base(strings.ReplaceAll(name, `\`, `/`))
	var sb strings.Builder
	for _, r := range name {
		if r < 32 || r == 127 || strings.ContainsRune(`/:*?"<>|`, r) {
			r = '_'
		}
		sb.WriteRune(r)
	}
	out := strings.Trim(strings.TrimSpace(sb.String()), ".")
	runes := []rune(out)
	if len(runes) > 100 {
		out = string(runes[len(runes)-100:])
	}
	if out == "" {
		out = "file"
	}
	return out
}
