// p2pc-web — PigeonBox 设备直传·网页模式客户端。
//
// 面向无 webkit2gtk-4.1 的老底座桌面（统信 UOS V20 全系/银河麒麟 V10 SP1 等，
// glibc 2.28 一档）：单个静态二进制（零 GUI/零系统 webview 依赖），本机起
// 回环 HTTP 服务，浏览器即界面——文件柜快捷入口 + 内置 p2p 收发直传。
//
// 架构：父进程 = 本地服务（随机令牌门禁/内嵌 UI/SSE/上传）；每次传输 re-exec
// 自身的 --transfer-child 隐藏子模式跑 internal/client 阻塞 API，kill 子进程
// 即取消（与桌面端 p2pc sidecar 语义一致），客户端核心零改动。
package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/oekit/concurrency/async"
	"github.com/oekit/core/version"
)

// options 全部旗标（服务模式与传输子模式共用一套）。
type options struct {
	addr      string
	outDir    string
	maxUpload int64
	noOpen    bool
	relay     string
	noPunch   bool
	token     string // 显式访问令牌（无头部署/测试；空=随机或令牌文件）
	tokenFile string // 持久化令牌路径：有则读、无则生成写入（NAS 跨重启稳定）
	// 传输子模式专用
	child    string
	registry string
	path     string
	code     string
}

func main() {
	// kit/async.GoSafe 的 panic 收编日志接线:走本入口 logf(零时间前缀,
	// 与启动横幅/事件行同款式);服务模式与传输子模式共用此 main,一并覆盖。
	async.SetPanicHandler(func(msg string, stack []byte) {
		logf("⚠ goroutine panic recovered: %s\n%s", msg, string(stack))
	})
	for _, a := range os.Args[1:] {
		if a == "-v" || a == "--version" || a == "version" {
			fmt.Printf("p2pc-web %s (commit %s, built %s)\n",
				version.Version, version.BuildCommit, version.BuildTime)
			return
		}
	}

	o := &options{}
	fs := flag.NewFlagSet("p2pc-web", flag.ContinueOnError)
	fs.StringVar(&o.addr, "addr", "127.0.0.1:12348", "监听地址（默认仅回环）")
	fs.StringVar(&o.outDir, "out", "", "接收目录（缺省: XDG 下载目录 > ~/Downloads > 当前目录）")
	fs.Int64Var(&o.maxUpload, "max-upload", 4<<30, "网页上传单文件上限（字节）")
	fs.BoolVar(&o.noOpen, "no-open", false, "不自动打开浏览器")
	fs.StringVar(&o.relay, "relay", "", "中继地址（缺省按注册中心 host 推导 :12347）")
	fs.BoolVar(&o.noPunch, "no-punch", false, "跳过 UDP 打洞直接走中继")
	fs.StringVar(&o.token, "token", "", "访问令牌（缺省随机生成；无头部署/测试固定值用）")
	fs.StringVar(&o.tokenFile, "token-file", "", "持久化令牌文件（有则读、无则生成写入 0600；NAS 等无头部署跨重启稳定）")
	fs.StringVar(&o.child, "transfer-child", "", "内部用:传输子模式(send|recv)，勿手动调用")
	fs.StringVar(&o.registry, "registry", "", "传输子模式:p2pd 基址")
	fs.StringVar(&o.path, "path", "", "传输子模式:发送文件路径")
	fs.StringVar(&o.code, "code", "", "传输子模式:直传口令")
	fs.Usage = usage
	if err := fs.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "未知参数: %s\n\n", fs.Arg(0))
		usage()
	}
	if o.child != "" {
		os.Exit(runTransferChild(o))
	}
	if err := runServer(o); err != nil {
		fmt.Fprintf(os.Stderr, "✗ %v\n", err)
		os.Exit(1)
	}
}

func runServer(o *options) error {
	token, err := resolveToken(o)
	if err != nil {
		return err
	}
	lw, err := net.Listen("tcp", o.addr)
	if err != nil {
		return fmt.Errorf("监听 %s: %w", o.addr, err)
	}
	laddr := lw.Addr().String()
	host, port, _ := net.SplitHostPort(laddr)
	loopback := host == "127.0.0.1" || host == "::1" || host == "localhost"
	if !loopback {
		logf("⚠ 非回环监听 %s：随机令牌成为唯一门禁，注意暴露面", laddr)
	}

	s := &Server{
		token:     token,
		loopback:  loopback,
		port:      port,
		maxUpload: o.maxUpload,
		outDir:    resolveDownloadDir(o.outDir),
		relay:     o.relay,
		noPunch:   o.noPunch,
		cfg:       newCfgStore(),
		mgr:       NewManager(),
		shares:    newShareTable(),
	}
	if err := os.MkdirAll(s.outDir, 0o755); err != nil {
		logf("⚠ 接收目录不可创建 %s: %v（传输时会再报错）", s.outDir, err)
	}

	url := fmt.Sprintf("http://%s/?t=%s", net.JoinHostPort(displayHost(host), port), token)
	logf("PigeonBeam 信鸽直传·网页模式 %s\n  界面:     %s\n  接收目录: %s\n  退出:     Ctrl+C（或关闭终端）",
		version.Version, url, s.outDir)
	if !o.noOpen {
		go openBrowser(url)
	}

	httpSrv := &http.Server{Handler: s.routes(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		<-sig
		s.mgr.Cancel()
		_ = httpSrv.Close()
	}()
	if err := httpSrv.Serve(lw); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// resolveToken 令牌来源优先级：--token 显式 > --token-file 持久化（有则读、
// 无则生成并写 0600——NAS 等无头部署跨重启稳定，服务脚本无需自己造随机数）
// > 随机生成（桌面缺省）。
func resolveToken(o *options) (string, error) {
	if t := strings.TrimSpace(o.token); t != "" {
		return t, nil
	}
	if p := strings.TrimSpace(o.tokenFile); p != "" {
		if b, err := os.ReadFile(p); err == nil {
			if t := strings.TrimSpace(string(b)); t != "" {
				return t, nil
			}
		} else if !os.IsNotExist(err) {
			return "", fmt.Errorf("读令牌文件 %s: %w", p, err)
		}
		t, err := newToken()
		if err != nil {
			return "", err
		}
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			return "", fmt.Errorf("创建令牌目录: %w", err)
		}
		if err := os.WriteFile(p, []byte(t+"\n"), 0o600); err != nil {
			return "", fmt.Errorf("写令牌文件 %s: %w", p, err)
		}
		return t, nil
	}
	return newToken()
}

// displayHost 横幅展示用的主机名（通配监听时提示回环地址）。
func displayHost(host string) string {
	switch host {
	case "", "0.0.0.0", "::":
		return "127.0.0.1"
	}
	return host
}

func openBrowser(rawURL string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", rawURL)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", rawURL)
	default:
		cmd = exec.Command("xdg-open", rawURL)
	}
	if err := cmd.Run(); err != nil {
		logf("未自动打开浏览器（%v），请手动访问上面地址", err)
	}
}

func logf(format string, a ...any) {
	log.SetFlags(0)
	log.Printf(format, a...)
}

func usage() {
	fmt.Print(`p2pc-web — PigeonBox 设备直传·网页模式客户端

用法:
  p2pc-web [--addr 127.0.0.1:12348] [--out 目录] [--max-upload 字节] [--no-open]

说明:
  本机起回环 HTTP 服务，浏览器打开启动时打印的带令牌地址即界面:
  文件柜快捷入口 + 设备直传（内置 p2p 口令收发，文件不落服务器）。
  需要可达的 p2pd 注册中心（默认 http://127.0.0.1:12346）。
  纯静态 Go 二进制——无 webkit2gtk-4.1 的老底座桌面（统信 UOS V20/
  麒麟 V10 SP1 等）同样可运行。
`)
}
