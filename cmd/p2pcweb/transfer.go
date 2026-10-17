package main

// 传输编排：父进程把阻塞式 internal/client 跑在 re-exec 的隐藏子模式里
//（--transfer-child），kill 子进程即取消——与桌面端 p2pc sidecar 语义一致，
// 客户端核心（Send/Receive 无 ctx 取消）零改动。同一时刻至多一个传输。

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"

	"github.com/oekit/concurrency/async"

	"github.com/pigeonbox/p2p/internal/client"
)

// ErrBusy 已有传输进行中。
var ErrBusy = errors.New("已有直传任务进行中，请等待完成或先取消")

// 子进程结果标记行（父进程按行扫描）。
const (
	doneMarker     = "P2PCWEB-DONE"     // 后可跟接收落盘路径
	errorMarker    = "P2PCWEB-ERROR"    // 后为错误信息
	progressMarker = "P2PCWEB-PROGRESS" // 后为 got=/total= 字节进度（不走日志面）
)

// Event SSE 推送事件。
type Event struct {
	Type  string   `json:"type"`            // state | code | progress | log | exit
	Line  string   `json:"line,omitempty"`  // log：日志行
	Code  string   `json:"code,omitempty"`  // code/state：直传口令
	Busy  bool     `json:"busy,omitempty"`  // state：是否有传输进行中
	Role  string   `json:"role,omitempty"`  // state：send | recv
	Exit  int      `json:"exit"`            // exit：子进程退出码（0=成功;勿加 omitempty,否则成功态被省略致前端误判失败）
	Path  string   `json:"path,omitempty"`  // exit：接收落盘路径（首个,兼容旧前端）
	Paths []string `json:"paths,omitempty"` // exit：接收落盘路径清单（多文件）
	Err   string   `json:"err,omitempty"`   // exit：失败原因
	Got   int64    `json:"got"`             // progress：已传字节
	Total int64    `json:"total"`           // progress：总字节（0=未知,界面转圈）
}

// Manager 单会话传输管理器。
type Manager struct {
	mu        sync.Mutex
	cmd       *exec.Cmd
	running   bool
	role      string // send | recv
	code      string
	donePath  string   // 首个落盘路径（兼容字段）
	donePaths []string // 全部落盘路径
	cleanup   func()

	subMu sync.Mutex
	subs  map[chan Event]struct{}
}

func NewManager() *Manager { return &Manager{subs: make(map[chan Event]struct{})} }

func (m *Manager) Busy() bool   { m.mu.Lock(); defer m.mu.Unlock(); return m.running }
func (m *Manager) Role() string { m.mu.Lock(); defer m.mu.Unlock(); return m.role }
func (m *Manager) Code() string { m.mu.Lock(); defer m.mu.Unlock(); return m.code }

// Subscribe 订阅事件流。通道缓冲 64，慢消费者丢行不阻塞传输。
func (m *Manager) Subscribe() chan Event {
	ch := make(chan Event, 64)
	m.subMu.Lock()
	m.subs[ch] = struct{}{}
	m.subMu.Unlock()
	return ch
}

func (m *Manager) Unsubscribe(ch chan Event) {
	m.subMu.Lock()
	delete(m.subs, ch)
	m.subMu.Unlock()
}

func (m *Manager) broadcast(ev Event) {
	m.subMu.Lock()
	defer m.subMu.Unlock()
	for ch := range m.subs {
		select {
		case ch <- ev:
		default:
		}
	}
}

// Start 拉起传输子进程。kind=send|recv；cleanup 在进程退出后执行（临时文件清理）。
// relay 非空/禁打洞透传子模式（服务端默认推导中继；测试注入 fixture 中继保确定性）。
func (m *Manager) Start(kind, registry, code, path, outDir, relay string, noPunch bool, cleanup func()) error {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return ErrBusy
	}
	self, err := os.Executable()
	if err != nil {
		m.mu.Unlock()
		return fmt.Errorf("定位自身可执行文件: %w", err)
	}
	// 统一 --k=v 形式：便于 go test 二进制以 TestMain 分发子模式（见 e2e_test.go）
	args := []string{"--transfer-child=" + kind, "--registry=" + registry, "--code=" + code}
	if kind == "send" {
		args = append(args, "--path="+path)
	} else {
		args = append(args, "--out="+outDir)
	}
	if relay != "" {
		args = append(args, "--relay="+relay)
	}
	if noPunch {
		args = append(args, "--no-punch")
	}
	cmd := exec.Command(self, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		m.mu.Unlock()
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		m.mu.Unlock()
		return err
	}
	if err := cmd.Start(); err != nil {
		m.mu.Unlock()
		return fmt.Errorf("启动传输: %w", err)
	}
	m.cmd, m.running, m.role, m.code, m.donePath, m.donePaths, m.cleanup = cmd, true, kind, code, "", nil, cleanup
	m.mu.Unlock()

	m.broadcast(Event{Type: "code", Code: code})
	// 三协程 GoSafe:panic 走全局 panic handler,不静默打死 p2pcweb
	async.GoSafe(func() { m.pipe(stdout) })
	async.GoSafe(func() { m.pipe(stderr) })
	async.GoSafe(func() { m.wait() })
	return nil
}

// Cancel 终止当前传输。返回是否确有进程被终止。
func (m *Manager) Cancel() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.running || m.cmd == nil || m.cmd.Process == nil {
		return false
	}
	_ = m.cmd.Process.Kill()
	return true
}

// pipe 子进程输出 → 日志事件；标记行单独处理：DONE 记录接收落盘路径，
// PROGRESS 转结构化进度事件（字节计数走事件通道,不进日志面刷屏）。
func (m *Manager) pipe(r io.Reader) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, doneMarker) {
			paths := parseDonePaths(line)
			m.mu.Lock()
			m.donePaths = paths
			m.donePath = ""
			if len(paths) > 0 {
				m.donePath = paths[0]
			}
			m.mu.Unlock()
			continue
		}
		if got, total, ok := parseProgressLine(line); ok {
			m.broadcast(Event{Type: "progress", Got: got, Total: total})
			continue
		}
		m.broadcast(Event{Type: "log", Line: line})
	}
}

// parseDonePaths DONE 标记行 → 落盘路径清单。多文件以 \x1f 连接（路径可含
// 空格，控制字节不会出现在文件名）；单文件形态与旧版逐字节一致。
func parseDonePaths(line string) []string {
	v := strings.TrimSpace(strings.TrimPrefix(line, doneMarker))
	if v == "" {
		return nil
	}
	return strings.Split(v, "\x1f")
}

// parseProgressLine 解析子进程进度标记行「P2PCWEB-PROGRESS got=N total=M」。
func parseProgressLine(line string) (got, total int64, ok bool) {
	if !strings.HasPrefix(line, progressMarker) {
		return 0, 0, false
	}
	for _, f := range strings.Fields(strings.TrimPrefix(line, progressMarker)) {
		k, v, found := strings.Cut(f, "=")
		if !found {
			continue
		}
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 0 {
			continue
		}
		switch k {
		case "got":
			got, ok = n, true
		case "total":
			total = n
		}
	}
	return got, total, ok
}

func (m *Manager) wait() {
	err := m.cmd.Wait()
	m.mu.Lock()
	cleanup := m.cleanup
	path := m.donePath
	paths := m.donePaths
	m.running, m.role, m.code, m.donePath, m.donePaths, m.cleanup = false, "", "", "", nil, nil
	m.mu.Unlock()

	exitCode := 0
	msg := ""
	if err != nil {
		exitCode = 1
		msg = err.Error()
		// 非 kill 的失败（对端未接入/网络等）补一行可读原因；kill=用户取消，
		// 界面按取消态处理，不再刷 "signal: killed" 噪音
		if !strings.Contains(msg, "kill") {
			m.broadcast(Event{Type: "log", Line: "✗ " + msg})
		}
	}
	if cleanup != nil {
		cleanup()
	}
	m.broadcast(Event{Type: "exit", Exit: exitCode, Path: path, Paths: paths, Err: msg})
}

// runTransferChild 隐藏子模式：跑阻塞式 client，日志经 prettyHandler 转
// 人类可读行（去 time=/level= 噪音）供父进程捕获转发界面，进度走独立标记
// 行，结尾输出 DONE/ERROR 标记行。返回进程退出码。
func runTransferChild(o *options) int {
	slog.SetDefault(slog.New(&prettyHandler{w: os.Stdout}))
	c, err := client.New(client.Options{Registry: o.registry, RelayAddr: o.relay, DisablePunch: o.noPunch})
	if err != nil {
		return childFail(err)
	}
	switch o.child {
	case "send":
		if _, err := c.Send([]string{o.path}, strings.ToUpper(o.code)); err != nil {
			return childFail(err)
		}
		fmt.Println(doneMarker)
	case "recv":
		files, err := c.Receive(strings.ToUpper(strings.TrimSpace(o.code)), o.outDir)
		if err != nil {
			return childFail(err)
		}
		if len(files) == 0 {
			return childFail(fmt.Errorf("未收到文件"))
		}
		fmt.Println(doneMarker + " " + strings.Join(files, "\x1f"))
	default:
		return childFail(fmt.Errorf("未知传输子模式 %q", o.child))
	}
	return 0
}

// prettyHandler 子进程日志整形：普通记录输出「· 消息  k=v」，警告/错误加
// ⚠/✗ 前缀；「传输进度」记录不进日志面，改写为进度标记行由父进程结构化
// 消费（界面渲染进度条而非滚日志）。
type prettyHandler struct {
	w  io.Writer
	mu sync.Mutex
}

func (h *prettyHandler) Enabled(_ context.Context, l slog.Level) bool { return l >= slog.LevelInfo }

func (h *prettyHandler) Handle(_ context.Context, r slog.Record) error {
	var b strings.Builder
	if r.Message == "传输进度" {
		var got, total int64
		r.Attrs(func(a slog.Attr) bool {
			switch a.Key {
			case "got":
				got = a.Value.Int64()
			case "total":
				total = a.Value.Int64()
			}
			return true
		})
		fmt.Fprintf(&b, "%s got=%d total=%d\n", progressMarker, got, total)
	} else {
		switch {
		case r.Level >= slog.LevelError:
			b.WriteString("✗ ")
		case r.Level >= slog.LevelWarn:
			b.WriteString("⚠ ")
		default:
			b.WriteString("· ")
		}
		b.WriteString(r.Message)
		r.Attrs(func(a slog.Attr) bool {
			b.WriteString("  " + a.Key + "=" + a.Value.String())
			return true
		})
		b.WriteByte('\n')
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := io.WriteString(h.w, b.String())
	return err
}

func (h *prettyHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *prettyHandler) WithGroup(string) slog.Handler      { return h }

func childFail(err error) int {
	fmt.Printf("%s %v\n", errorMarker, err)
	return 1
}
