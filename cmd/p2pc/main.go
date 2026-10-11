// p2pc — PigeonBox P2P 设备直传参考客户端（M3）。
//
//	p2pc send 文件 --registry http://r:12346   → 输出口令,等待对端取走
//	p2pc recv <口令> --registry http://r:12346 → 接收到当前目录
//
// 流程: 注册节点+公告/解析 → WS 信令配对(身份钉定) → PAKE → 加密候选交换
// → UDP 同时开洞(失败走中继) → AEAD 消息传输(断点续传+sha256 校验)。
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/pigeonbox/kit/version"
	"github.com/pigeonbox/p2p/internal/client"
)

// flagSet 薄包装:统一错误输出行为。
type flagSet struct {
	*flag.FlagSet
}

func newFlagSet(name string) *flagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	return &flagSet{FlagSet: fs}
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	cmd := os.Args[1]
	switch cmd {
	case "send":
		send(os.Args[2:])
	case "recv":
		receive(os.Args[2:])
	case "-h", "--help", "help":
		usage()
	case "-v", "--version", "version":
		fmt.Printf("p2pc %s (commit %s, built %s)\n", version.Version, version.BuildCommit, version.BuildTime)
	default:
		fmt.Fprintf(os.Stderr, "未知子命令: %s\n\n", cmd)
		usage()
	}
}

func usage() {
	fmt.Print(`p2pc — PigeonBox P2P 设备直传客户端

用法:
  p2pc send <文件|目录>... [--registry URL] [--code 口令] [--relay HOST:PORT]
                  [--key PATH] [--no-punch] [--quiet]
  p2pc recv <口令> [--registry URL] [--out DIR] [--yes]
                  [--relay HOST:PORT] [--key PATH] [--no-punch] [--quiet]

说明:
  --registry   p2pd 注册中心基址(默认 http://127.0.0.1:12346)
  口令格式     XXXX-XXXX-XXXX(send 自动生成;recv 原样输入,含连字符)
  传输优先 UDP 打洞直连,失败自动回落中继(先通后优:中继上起传,后台打洞
  成功后文件边界自动升级直连;中继需服务端 relay.enabled=true,现默认开)
  目录会整棵递归;接收方可逐文件授权(--yes 跳过交互全部接受)
`)
	os.Exit(2)
}

func commonFlags(fs *flagSet) *client.Options {
	opt := &client.Options{Registry: "http://127.0.0.1:12346"}
	fs.StringVar(&opt.Registry, "registry", opt.Registry, "p2pd 基址(裸域名触发 DNS SRV 发现)")
	fs.StringVar(&opt.RegistriesJoined, "registries", "", "额外注册中心(逗号分隔,多源 failover;亦可用 PB_P2P_REGISTRIES)")
	fs.StringVar(&opt.RelayAddr, "relay", "", "中继地址(缺省经注册中心 /health 的 relay_port 自动发现;老服务器回退 registry host:12347)")
	fs.StringVar(&opt.NodeKeyPath, "key", client.DefaultNodeKeyPath(), "节点身份密钥路径")
	fs.BoolVar(&opt.DisablePunch, "no-punch", false, "跳过打洞直接走中继")
	fs.BoolVar(&opt.NoRelay, "no-relay", false, "仅直连:跳过中继兜底,打洞失败即报错")
	fs.BoolVar(&opt.Quiet, "quiet", false, "静默模式")
	return opt
}

func send(args []string) {
	fs := newFlagSet("p2pc send")
	opt := commonFlags(fs)
	var code string
	fs.StringVar(&code, "code", "", "指定口令(缺省自动生成)")
	if err := parseArgs(fs.FlagSet, args); err != nil {
		os.Exit(2)
	}
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "✗ 缺少文件/目录参数")
		os.Exit(2)
	}
	paths := fs.Args()
	for _, p := range paths {
		if _, err := os.Stat(p); err != nil {
			fmt.Fprintf(os.Stderr, "✗ 路径不可用: %s\n", p)
			os.Exit(1)
		}
	}

	c, err := client.New(*opt)
	if err != nil {
		fail(err)
	}
	// 口令先亮后等:Send 内部自动口令只在其返回后才可读,等待期接收方无从得知
	code = strings.ToUpper(code)
	if code == "" {
		if code, err = client.GenerateCode(); err != nil {
			fail(err)
		}
	}
	fmt.Printf("口令: %s\n接收方执行: p2pc recv %s\n等待对端接入...\n", code, code)
	if _, err := c.Send(paths, code); err != nil {
		fail(err)
	}
	fmt.Println("\n✓ 发送完成")
}

func receive(args []string) {
	fs := newFlagSet("p2pc recv")
	opt := commonFlags(fs)
	out, _ := os.Getwd()
	fs.StringVar(&out, "out", out, "接收目录")
	yes := fs.Bool("yes", false, "全部接受(跳过逐文件交互授权)")
	if err := parseArgs(fs.FlagSet, args); err != nil {
		os.Exit(2)
	}
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "✗ 缺少口令参数")
		os.Exit(2)
	}
	code := strings.ToUpper(strings.TrimSpace(fs.Arg(0)))
	if !*yes {
		opt.ChooseFiles = chooseInteractively
	}

	c, err := client.New(*opt)
	if err != nil {
		fail(err)
	}
	files, err := c.Receive(code, out)
	if err != nil {
		if len(files) > 0 {
			fmt.Fprintf(os.Stderr, "✗ 部分失败(已收 %d 个): %v\n", len(files), err)
		}
		fail(err)
	}
	fmt.Printf("\n✓ 接收完成(%d 个文件):\n", len(files))
	for _, f := range files {
		if abs, aerr := filepath.Abs(f); aerr == nil {
			fmt.Println("  " + abs)
		} else {
			fmt.Println("  " + f)
		}
	}
}

// chooseInteractively 逐文件授权:回车=全部;输入序号(如 1,3-4)=部分。
func chooseInteractively(mf client.Manifest) []client.ManifestEntry {
	fmt.Printf("对方要发送 %d 个文件(共 %d 字节):\n", len(mf.Files), func() int64 {
		var t int64
		for _, e := range mf.Files {
			t += e.Size
		}
		return t
	}())
	for _, e := range mf.Files {
		fmt.Printf("  [%d] %s (%d 字节)\n", e.ID+1, e.Name, e.Size)
	}
	fmt.Print("回车全部接受,或输入要接受的序号(如 1,3-4)> ")
	var line string
	_, _ = fmt.Scanln(&line)
	line = strings.TrimSpace(line)
	if line == "" {
		return mf.Files
	}
	var picked []client.ManifestEntry
	for _, part := range strings.Split(line, ",") {
		part = strings.TrimSpace(part)
		if i := strings.Index(part, "-"); i > 0 {
			lo, e1 := strconv.Atoi(strings.TrimSpace(part[:i]))
			hi, e2 := strconv.Atoi(strings.TrimSpace(part[i+1:]))
			if e1 != nil || e2 != nil || lo < 1 || hi < lo || hi > len(mf.Files) {
				continue
			}
			for n := lo; n <= hi; n++ {
				picked = append(picked, mf.Files[n-1])
			}
			continue
		}
		if n, e := strconv.Atoi(part); e == nil && n >= 1 && n <= len(mf.Files) {
			picked = append(picked, mf.Files[n-1])
		}
	}
	if len(picked) == 0 {
		fmt.Println("未选中任何文件,全部接受。")
		return mf.Files
	}
	return picked
}

// parseArgs 位置无关的 flag 解析:Go flag 包遇首个非 flag 参数即停,
// 导致 "p2pc send 文件 --code X" 里文件后的旗标全被忽略(215 实测踩坑)。
// 循环 Parse:每轮摘出一个位置参数继续解析;结束后以纯位置参数收尾,
// 已设旗标值保持不变,fs.Args() 即全部位置参数。
func parseArgs(fs *flag.FlagSet, args []string) error {
	var positional []string
	rest := args
	for {
		if err := fs.Parse(rest); err != nil {
			return err
		}
		remaining := fs.Args()
		if len(remaining) == 0 {
			break
		}
		positional = append(positional, remaining[0])
		rest = remaining[1:]
	}
	_ = fs.Parse(positional)
	return nil
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "✗ %v\n", err)
	os.Exit(1)
}
