// p2pc — PigeonBeam（信鸽直传）设备直传客户端。
//
//	p2pc send 文件 --registry http://r:12346   → 输出口令,等待对端取走
//	p2pc recv <口令> --registry http://r:12346 → 接收到当前目录
//
// 流程: 注册节点+公告/解析 → WS 信令配对(身份钉定) → PAKE → 加密候选交换
// → UDP 同时开洞(失败走中继) → AEAD 消息传输(断点续传+sha256 校验)。
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
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
                  [--pair] [--yes]                        配对码模式(亮四位定时码)
  p2pc recv <口令|配对码> [--registry URL] [--out DIR] [--yes] [--json]
                  [--relay HOST:PORT] [--key PATH] [--no-punch] [--quiet]
                  [--pair]                                --pair 且无码=反向亮码
                  （口令传 "-" 时从 PB_P2P_CODE 环境变量读取——argv 不留码,
                    服务进程调用方(server supervisor)的硬化通道）
  p2pc directory [--registry URL]                  列在线名录(JSON)
  p2pc mailbox [--registry URL] [--key PATH] [--watch] [--interval 5s]
                  [--discoverable] [--name 显示名]  弹出/轮询密封邀请(NDJSON)

说明:
  --registry   p2pd 注册中心基址(默认 http://127.0.0.1:12346)
  口令格式     XXXX-XXXX-XXXX(send 自动生成;recv 原样输入,含连字符)
  配对码模式   --pair 亮 4 位数字定时码(5 分钟失效,对方输入即连,免抄 12 位
               口令);recv/send 侧 4-8 位纯数字自动按配对码认领(反向配对的
               对端),查无此码回退口令解析,--pair 强制只走配对;接受门缺省
               人工确认,--yes/--json 自动;--pair-stdin 走 stdin 单行裁决
               (y/n,EOF=拒绝;desktop/p2px 等程序调用方转发裁决)
  传输优先 UDP 打洞直连,失败自动回落中继(先通后优:中继上起传,后台打洞
  成功后文件边界自动升级直连;中继需服务端 relay.enabled=true,现默认开)
  目录会整棵递归;接收方可逐文件授权(--yes 跳过交互全部接受)
  --json       NDJSON 事件流(code/pair_code/pair_request/done/error),供程序
               调用方解析;缺省纯文本
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
	jsonFlag := fs.Bool("json", false, "NDJSON 事件流输出(机器可读:code/pair_code/pair_request/done/error)")
	pairMode := fs.Bool("pair", false, "配对码模式:亮 4 位定时码,对方输入码即连(免抄口令)")
	yes := fs.Bool("yes", false, "自动接受敲门请求(跳过接受门问询)")
	pairStdin := fs.Bool("pair-stdin", false, "接受门改走 stdin 单行协议(y/n,EOF=拒绝;供 desktop/p2px 转发裁决,优先于 --yes/--json 自动语义)")
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
	// 配对码模式与密封邀请语义互斥:邀请依附口令路径,配对模式由对方输码
	// 连接——静默忽略会让用户误以为邀请已投递(2026-10-19 易用性走查)
	if *pairMode && strings.TrimSpace(*inviteTo) != "" {
		fmt.Fprintln(os.Stderr, "✗ --pair 与 --invite-to 不兼容:配对码模式由对方输码连接,不走密封邀请;请去掉其一")
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

	// 配对码模式:亮码→接受门→兑换→传输,全部在 SendPaired 内编排
	if *pairMode {
		if _, err := c.SendPaired(paths, pairCallbacks(*yes, *pairStdin)); err != nil {
			failJSON(err)
		}
		clearUIProgress()
		if jsonOut {
			emitEvent("done", map[string]any{"kind": "send"})
		} else {
			fmt.Println("\n✓ 发送完成")
		}
		return
	}

	// 口令先亮后等:Send 内部自动口令只在其返回后才可读,等待期接收方无从得知
	code = strings.ToUpper(code)
	if code == "" {
		if code, err = client.GenerateCode(); err != nil {
			failJSON(err)
		}
	}
	// 敲码发送(反向配对的发送侧):4-8 位纯数字先按配对码认领;查无此码回退
	// 口令直传(自定义短口令兼容,与 recv 侧对称)。回退时告知真实原因——
	// 被拒/过期的码只报「无该口令」是灾难级误导(2026-10-19 易用性走查)
	pairTried := false
	if client.IsPairingCode(code) {
		pairTried = true
		if _, perr := c.SendByClaim(code, paths, pairCallbacks(false, false)); perr == nil {
			clearUIProgress()
			if jsonOut {
				emitEvent("done", map[string]any{"kind": "send"})
			} else {
				fmt.Println("\n✓ 发送完成")
			}
			return
		} else if !errors.Is(perr, client.ErrPairUnknown) {
			failJSON(perr)
		}
		fmt.Fprintln(os.Stderr, "⚠ 配对码 "+code+" 不存在或已失效(可能已被拒绝、过期或已使用)——按口令直传解析…")
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
		if pairTried {
			err = fmt.Errorf("%w(提示: 配对码 %s 已失效——对方拒绝/过期/已使用;口令解析亦未命中,请让对方重新亮码或核对口令)", err, code)
		}
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
//
// 提示行**不含口令**：口令是唯一 bearer 凭据，抄进命令行会留在 shell 历史
// 与进程表里（2026-10-26 审计 P1）。口令走 PB_P2P_CODE env（argv 不留码）。
func printCode(code string) {
	fmt.Printf("口令: %s\n接收方执行: p2pc recv -（口令经 PB_P2P_CODE 环境变量传入，勿写进命令行）\n等待对端接入...\n", code)
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
	pairForce := fs.Bool("pair", false, "配对码语义:无位置参数=反向亮码等待对方推送;带 4-8 位数字=只按配对码处理(不做口令回退)")
	pairStdin := fs.Bool("pair-stdin", false, "接受门改走 stdin 单行协议(y/n,EOF=拒绝;供 desktop/p2px 转发裁决,优先于 --yes/--json 自动语义)")
	if err := parseArgs(fs.FlagSet, args); err != nil {
		os.Exit(2)
	}
	jsonOut = *jsonFlag
	if jsonOut {
		*yes = true // JSON 流不可被交互提示污染
	}

	// 终端人性化输出（TTY 限定;--json/管道不受影响;先于 client.New,理由同 send）
	if !jsonOut {
		if h, _ := newUIHandler(os.Stderr); h != nil {
			h.(*uiHandler).setDirection("recv")
			slog.SetDefault(slog.New(h))
		}
	}
	if !*yes {
		opt.ChooseFiles = chooseInteractively
	}
	c, err := client.New(*opt)
	if err != nil {
		fail(err)
	}

	// 反向配对:接收方亮码,对方敲码后推送文件过来
	if *pairForce && fs.NArg() == 0 {
		files, perr := c.ReceivePairedAsCreator(out, pairCallbacks(*yes, *pairStdin))
		finishRecv(files, perr)
		return
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
	// 配对码:4-8 位纯数字先按配对码认领;查无此码(非 --pair 强制)回退口令解析。
	// 回退时告知真实原因——被拒/过期的码只报「无该口令」是灾难级误导
	// (2026-10-19 易用性走查实测撞到)
	pairTried := false
	if client.IsPairingCode(code) || *pairForce {
		pairTried = true
		files, perr := c.ReceivePaired(code, out, pairCallbacks(*yes, *pairStdin))
		if perr == nil {
			finishRecv(files, nil)
			return
		}
		if !errors.Is(perr, client.ErrPairUnknown) || *pairForce {
			clearUIProgress()
			if *pairForce && errors.Is(perr, client.ErrPairUnknown) {
				failJSON(fmt.Errorf("配对码 %s 不存在或已失效(可能已被对方拒绝、过期或已使用)——请让对方重新亮码", code))
			}
			failJSON(perr)
		}
		fmt.Fprintln(os.Stderr, "⚠ 配对码 "+code+" 不存在或已失效(可能已被拒绝、过期或已使用)——按口令直传解析…")
	}
	files, err := c.Receive(code, out)
	if err != nil && pairTried {
		err = fmt.Errorf("%w(提示: 配对码 %s 已失效——对方拒绝/过期/已使用;口令解析亦未命中,请让对方重新亮码或核对口令。口令形态: 12 位 XXXX-XXXX-XXXX)", err, code)
	}
	finishRecv(files, err)
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
	picked := parseSelection(line, mf.Files)
	if len(picked) == 0 {
		fmt.Println("未选中任何文件,全部接受。")
		return mf.Files
	}
	return picked
}

// parseSelection 解析交互式选文件输入("1,3-4")→ 选中的清单条目。//
// 返回按 **ID 升序**（= 发送侧 manifest 序）——2026-10-26 审计 P1：
// 接收侧必须与发送方同序处理文件（发送侧恒按 manifest 序发送，接收侧按
// accepted 列表顺序取条目并回执该条目的 ID）。此前按**用户输入顺序**追加，
// 降序输入（很自然，如先选大的 "3,1"）会让首个回执带上非首个文件的 ID ⇒
// 发送侧判「fileAck id 不符」⇒ 整场传输失败（文件其实已落盘并通过校验）。
//
// 序号是 1-based 展示序号（对应清单 ID+1）；越界/非法项忽略；重复项去重。
func parseSelection(line string, files []client.ManifestEntry) []client.ManifestEntry {
	var picked []client.ManifestEntry
	seen := map[int]bool{}
	add := func(e client.ManifestEntry) {
		if seen[e.ID] {
			return
		}
		seen[e.ID] = true
		picked = append(picked, e)
	}
	for _, part := range strings.Split(line, ",") {
		part = strings.TrimSpace(part)
		if i := strings.Index(part, "-"); i > 0 {
			lo, e1 := strconv.Atoi(strings.TrimSpace(part[:i]))
			hi, e2 := strconv.Atoi(strings.TrimSpace(part[i+1:]))
			if e1 != nil || e2 != nil || lo < 1 || hi < lo || hi > len(files) {
				continue
			}
			for n := lo; n <= hi; n++ {
				add(files[n-1])
			}
			continue
		}
		if n, e := strconv.Atoi(part); e == nil && n >= 1 && n <= len(files) {
			add(files[n-1])
		}
	}
	sort.Slice(picked, func(i, j int) bool { return picked[i].ID < picked[j].ID })
	return picked
}

// pairCallbacks 配对编排回调（send 亮码/recv 敲码/recv 反向亮码三形态共用）。
// 接受门三形态：stdinGate=true 走 stdin 单行协议(y/n,EOF=拒绝——desktop/p2px
// 等程序调用方转发裁决)；否则 jsonOut 恒自动接受（语义经 pair_request 事件
// 上抛）；再否则 autoAccept 自动、无旗标走 TTY 问询。
func pairCallbacks(autoAccept, stdinGate bool) client.PairCallbacks {
	return client.PairCallbacks{
		OnCode: func(code string, ttl time.Duration) {
			if jsonOut {
				emitEvent("pair_code", map[string]any{"code": code, "ttl_seconds": int64(ttl.Seconds())})
				return
			}
			fmt.Printf("配对码: %s（%s内有效）\n请在另一台设备输入该配对码（或执行: p2pc recv %s）...\n",
				code, humanTTL(ttl), code)
		},
		OnRequest: func(req client.PairRequestView) bool {
			if jsonOut {
				emitEvent("pair_request", map[string]any{"from": req.NodeID, "name": req.Name})
			} else {
				fmt.Printf("设备 %s（%s…）请求连接\n", pairPeerName(req), shortNodeID(req.NodeID))
			}
			if stdinGate {
				if !jsonOut {
					fmt.Println("等待裁决（stdin 单行 y/n，EOF=拒绝）…")
				}
				return readGateDecision(os.Stdin)
			}
			if jsonOut {
				return true
			}
			if autoAccept {
				fmt.Printf("已自动接受设备 %s（%s…）的连接\n", pairPeerName(req), shortNodeID(req.NodeID))
				return true
			}
			return askApprove(req)
		},
		OnDenied: func(req client.PairRequestView) {
			if jsonOut {
				emitEvent("pair_denied", map[string]any{"from": req.NodeID})
				return
			}
			fmt.Printf("已拒绝设备 %s，配对码作废，重新生成中…\n", pairPeerName(req))
		},
		OnExpired: func() {
			if jsonOut {
				emitEvent("pair_expired", nil)
				return
			}
			fmt.Println("配对码已过期，重新生成中…")
		},
		OnPending: func() {
			if !jsonOut {
				fmt.Println("等待对方确认…")
			}
		},
	}
}

// readGateDecision stdin 单行裁决：持久行读跨多次裁决复用（拒绝→重铸→新
// 请求各读一行），y/空行=接受，其余/EOF=拒绝（fail closed）。与 p2pcweb
// 子模式 stdin 协议同语义。
func readGateDecision(r io.Reader) bool {
	if gateReader == nil {
		gateReader = bufio.NewReader(r)
	}
	line, err := gateReader.ReadString('\n')
	if err != nil && strings.TrimSpace(line) == "" {
		return false // EOF=拒绝
	}
	return gateDecision(line)
}

var gateReader *bufio.Reader

// gateDecision 单行判定（纯函数，可测）：空/y/yes=接受，其余=拒绝。
func gateDecision(line string) bool {
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "", "y", "yes":
		return true
	}
	return false
}

// askApprove 接受门问询：回车/y 接受，其余拒绝（管道 stdin 无输入=自动接受，
// 与 --yes/--json 的非交互语义一致）。
func askApprove(req client.PairRequestView) bool {
	fmt.Printf("设备 %s（%s…）请求连接，接受? [Y/n] > ", pairPeerName(req), shortNodeID(req.NodeID))
	var line string
	_, _ = fmt.Scanln(&line)
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "", "y", "yes":
		return true
	}
	return false
}

func pairPeerName(req client.PairRequestView) string {
	if name := strings.TrimSpace(req.Name); name != "" {
		return name
	}
	return "未知设备"
}

func shortNodeID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

// humanTTL 时长人话(5m0s → "5 分钟";Go duration 直出对人不友好)。
func humanTTL(d time.Duration) string {
	d = d.Round(time.Second)
	m := int(d / time.Minute)
	sec := int(d/time.Second) % 60
	switch {
	case m > 0 && sec == 0:
		return fmt.Sprintf("%d 分钟", m)
	case m > 0:
		return fmt.Sprintf("%d 分 %d 秒", m, sec)
	default:
		return fmt.Sprintf("%d 秒", sec)
	}
}

// finishRecv 接收收尾统一出口（配对/口令/反向三路径共用）。
func finishRecv(files []string, err error) {
	clearUIProgress()
	if err != nil {
		if len(files) > 0 {
			fmt.Fprintf(os.Stderr, "✗ 部分失败(已收 %d 个): %v\n", len(files), err)
		}
		if jsonOut {
			emitEvent("error", map[string]any{"msg": err.Error(), "files": len(files)})
			os.Exit(1)
		}
		fail(err)
	}
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
