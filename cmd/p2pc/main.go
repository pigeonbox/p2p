// p2pc — PigeonBeam（信鸽直传）设备直传客户端。
//
//	p2pc send 文件 --registry http://r:12346   → 输出口令,等待对端取走
//	p2pc recv <口令> --registry http://r:12346 → 接收到当前目录
//
// 流程: 注册节点+公告/解析 → WS 信令配对(身份钉定) → PAKE → 加密候选交换
// → UDP 同时开洞(失败走中继) → AEAD 消息传输(断点续传+sha256 校验)。
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/oekit/concurrency/async"
	"github.com/oekit/core/version"
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
	// kit/async.GoSafe 的 panic 收编日志接线。运行时解析 slog.Default()——
	// p2pc 按子命令/TTY/JSON 换装 handler(uiHandler/缺省),固定捕获会接到
	// 换装前的旧 handler 上。
	async.SetPanicHandler(func(msg string, stack []byte) {
		slog.Error("goroutine panic recovered", "msg", msg, "stack", string(stack))
	})
	if len(os.Args) < 2 {
		usage()
	}
	cmd := os.Args[1]
	switch cmd {
	case "send":
		send(os.Args[2:])
	case "recv":
		receive(os.Args[2:])
	case "directory":
		directoryCmd(os.Args[2:])
	case "mailbox":
		mailboxCmd(os.Args[2:])
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
	fmt.Print(`p2pc — PigeonBeam（信鸽直传）设备直传客户端

用法:
  p2pc send <文件|目录>... [--registry URL] [--code 口令] [--relay HOST:PORT]
                  [--key PATH] [--no-punch] [--quiet] [--json]
                  [--invite-to NODE_ID] [--invite-note 附言] [--invite-name 显示名]
  p2pc recv <口令> [--registry URL] [--out DIR] [--yes] [--json]
                  [--relay HOST:PORT] [--key PATH] [--no-punch] [--quiet]
                  （口令传 "-" 时从 PB_P2P_CODE 环境变量读取——argv 不留码,
                    服务进程调用方(server supervisor)的硬化通道）
  p2pc directory [--registry URL]                  列在线名录(JSON)
  p2pc mailbox [--registry URL] [--key PATH] [--watch] [--interval 5s]
                  [--discoverable] [--name 显示名]  弹出/轮询密封邀请(NDJSON)

说明:
  --registry   p2pd 注册中心基址(默认 http://127.0.0.1:12346)
  口令格式     XXXX-XXXX-XXXX(send 自动生成;recv 原样输入,含连字符)
  传输优先 UDP 打洞直连,失败自动回落中继(先通后优:中继上起传,后台打洞
  成功后文件边界自动升级直连;中继需服务端 relay.enabled=true,现默认开)
  目录会整棵递归;接收方可逐文件授权(--yes 跳过交互全部接受)
  --json       NDJSON 事件流(code/done/error),供程序调用方解析;缺省纯文本
  --invite-to  发送后向名录对端信箱投递密封邀请(收端 NAT 后可达;
               发邀请=自愿入名录;失败仅告警不影响发送)
  mailbox      邀请 = 口令 bearer;开箱以名录 box_pub 验真,失败即跳过;
               --discoverable 注册进名录(接收邀请的前提;core supervisor
               以 --watch --discoverable 长驻,stdout 恒 NDJSON)
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
	jsonFlag := fs.Bool("json", false, "NDJSON 事件流输出(机器可读:code/done/error)")
	inviteTo := fs.String("invite-to", "", "发送后向该名录对端投递密封邀请(node_id)")
	inviteNote := fs.String("invite-note", "", "邀请附言")
	inviteName := fs.String("invite-name", "", "邀请显示名(缺省主机名)")
	if err := parseArgs(fs.FlagSet, args); err != nil {
		os.Exit(2)
	}
	jsonOut = *jsonFlag
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

	// 终端人性化输出（TTY 限定;--json/管道不受影响,2026-10-16 易用性）。
	// 必须先于 client.New:client 构造时捕获 slog.Default(),装晚了旧默认
	// handler 经 log→slog 桥接双烤出一层「· INFO …」怪行。
	if !jsonOut {
		if h, _ := newUIHandler(os.Stderr); h != nil {
			h.(*uiHandler).setDirection("send")
			slog.SetDefault(slog.New(h))
		}
	}
	c, err := client.New(*opt)
	if err != nil {
		failJSON(err)
	}
	// 口令先亮后等:Send 内部自动口令只在其返回后才可读,等待期接收方无从得知
	code = strings.ToUpper(code)
	if code == "" {
		if code, err = client.GenerateCode(); err != nil {
			failJSON(err)
		}
	}
	if jsonOut {
		emitEvent("code", map[string]any{"code": code})
	} else {
		printCode(code)
	}
	// 密封邀请(便利非通路):公告由 Send 内部落,邀请先行投递——收端取件
	// 后自行 resolve(带重试),公告竞态由收端重试吸收。失败仅告警。
	if strings.TrimSpace(*inviteTo) != "" {
		if err := client.SendInvite(*opt, code, strings.ToLower(strings.TrimSpace(*inviteTo)), inviteDisplayName(*inviteName), *inviteNote); err != nil {
			if jsonOut {
				emitEvent("invite_error", map[string]any{"msg": err.Error()})
			} else {
				fmt.Fprintf(os.Stderr, "⚠ 邀请投递失败(不影响发送): %v\n", err)
			}
		} else if jsonOut {
			emitEvent("invite_sent", map[string]any{"to": *inviteTo})
		}
	}
	if _, err := c.Send(paths, code); err != nil {
		failJSON(err)
	}
	clearUIProgress()
	if jsonOut {
		emitEvent("done", map[string]any{"kind": "send"})
	} else {
		fmt.Println("\n✓ 发送完成")
	}
}

// clearUIProgress 收掉在屏进度行（✓/✗ 终态行要干净落行;非 TTY 无进度行,空操作）。
func clearUIProgress() {
	if h, ok := slog.Default().Handler().(*uiHandler); ok {
		h.clear()
	}
}

// inviteDisplayName 邀请显示名:旗标 > 主机名 > "p2pc"。
func inviteDisplayName(flag string) string {
	if s := strings.TrimSpace(flag); s != "" {
		return s
	}
	if h, err := os.Hostname(); err == nil && strings.TrimSpace(h) != "" {
		return h
	}
	return "p2pc"
}

// printCode 口令行格式契约：server supervisor（p2px.scanLines）与 desktop
// sidecar 都按 "口令: XXXX-XXXX-XXXX" 解析 stdout——本函数是格式单源，
// 变更必须同步下游解析器并 bump 说明（main_test.go 锁定）。
func printCode(code string) {
	fmt.Printf("口令: %s\n接收方执行: p2pc recv %s\n等待对端接入...\n", code, code)
}

// ---- --json NDJSON 事件流(2026-10-14 留位增量,spec §14) ----
// stdout 单流:{"event":"code"|"done"|"error", ...};缺省纯文本不变
// (desktop sidecar 解析纯文本零影响)。--json 下强制非交互(recv 自动 --yes)。

var jsonOut bool

// emitEvent JSON 模式发一行 NDJSON 事件(非 JSON 模式静默)。
func emitEvent(kind string, fields map[string]any) {
	if !jsonOut {
		return
	}
	m := map[string]any{"event": kind}
	for k, v := range fields {
		m[k] = v
	}
	b, _ := json.Marshal(m)
	fmt.Println(string(b))
}

// failJSON 错误路径(JSON 模式发 error 事件后按 fail 语义退出)。
func failJSON(err error) {
	if jsonOut {
		emitEvent("error", map[string]any{"msg": err.Error()})
		os.Exit(1)
	}
	fail(err)
}

// resolveRecvCode 口令来源：位置参数直传；"-" = 从 PB_P2P_CODE env 读
// （argv 不留码，同机 ps 不可见——server supervisor 硬化通道，2026-10-14）。
func resolveRecvCode(args []string) (string, error) {
	if len(args) == 0 || args[0] == "-" {
		code := strings.ToUpper(strings.TrimSpace(os.Getenv("PB_P2P_CODE")))
		if code == "" {
			return "", fmt.Errorf("口令缺失：位置参数或 PB_P2P_CODE env 二选一（recv - 走 env）")
		}
		return code, nil
	}
	return strings.ToUpper(strings.TrimSpace(args[0])), nil
}

func receive(args []string) {
	fs := newFlagSet("p2pc recv")
	opt := commonFlags(fs)
	out, _ := os.Getwd()
	fs.StringVar(&out, "out", out, "接收目录")
	yes := fs.Bool("yes", false, "全部接受(跳过逐文件交互授权)")
	jsonFlag := fs.Bool("json", false, "NDJSON 事件流输出(机器可读:done/error;强制非交互)")
	if err := parseArgs(fs.FlagSet, args); err != nil {
		os.Exit(2)
	}
	jsonOut = *jsonFlag
	if jsonOut {
		*yes = true // JSON 流不可被交互提示污染
	}
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "✗ 缺少口令参数")
		os.Exit(2)
	}
	code, err := resolveRecvCode(fs.Args())
	if err != nil {
		fmt.Fprintf(os.Stderr, "✗ %v\n", err)
		os.Exit(2)
	}
	if !*yes {
		opt.ChooseFiles = chooseInteractively
	}

	// 终端人性化输出（TTY 限定;--json/管道不受影响;先于 client.New,理由同 send）
	if !jsonOut {
		if h, _ := newUIHandler(os.Stderr); h != nil {
			h.(*uiHandler).setDirection("recv")
			slog.SetDefault(slog.New(h))
		}
	}
	c, err := client.New(*opt)
	if err != nil {
		fail(err)
	}
	files, err := c.Receive(code, out)
	if err != nil {
		clearUIProgress()
		if len(files) > 0 {
			fmt.Fprintf(os.Stderr, "✗ 部分失败(已收 %d 个): %v\n", len(files), err)
		}
		if jsonOut {
			emitEvent("error", map[string]any{"msg": err.Error(), "files": len(files)})
			os.Exit(1)
		}
		fail(err)
	}
	clearUIProgress()
	if jsonOut {
		abs := make([]string, 0, len(files))
		for _, f := range files {
			if a, aerr := filepath.Abs(f); aerr == nil {
				abs = append(abs, a)
			} else {
				abs = append(abs, f)
			}
		}
		emitEvent("done", map[string]any{"kind": "recv", "files": len(files), "paths": abs})
		return
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

// directoryCmd 在线名录:JSON 输出 discoverable 节点列表。
func directoryCmd(args []string) {
	fs := newFlagSet("p2pc directory")
	opt := commonFlags(fs)
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	peers, err := client.DirectoryPeers(*opt)
	if err != nil {
		fail(err)
	}
	b, _ := json.MarshalIndent(map[string]any{"nodes": peers}, "", "  ")
	fmt.Println(string(b))
}

// mailboxCmd 信箱取件:弹出(或 --watch 长驻轮询)密封邀请,开箱验真后
// NDJSON 输出 {"event":"invite",...}——core supervisor 与脚本同面。
func mailboxCmd(args []string) {
	fs := newFlagSet("p2pc mailbox")
	opt := commonFlags(fs)
	watch := fs.Bool("watch", false, "长驻轮询(core supervisor 形态;退出由父进程管理)")
	interval := fs.Duration("interval", 5*time.Second, "轮询间隔(--watch)")
	discoverable := fs.Bool("discoverable", false, "注册进在线名录(接收邀请的前提)")
	name := fs.String("name", "", "名录显示名(缺省 p2pc)")
	if err := parseArgs(fs.FlagSet, args); err != nil {
		os.Exit(2)
	}
	err := client.RunMailbox(client.MailboxOptions{
		Options:      *opt,
		Watch:        *watch,
		Interval:     *interval,
		Discoverable: *discoverable,
		DisplayName:  *name,
	}, printInviteEvent)
	if err != nil {
		fail(err)
	}
}

// printInviteEvent 邀请 NDJSON 单行(stdout 契约:p2px 信箱 watcher 解析)。
func printInviteEvent(inv client.InvitePayload) {
	b, _ := json.Marshal(map[string]any{
		"event": "invite",
		"code":  inv.Code,
		"from":  inv.NodeID,
		"name":  inv.Name,
		"note":  inv.Note,
	})
	fmt.Println(string(b))
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
