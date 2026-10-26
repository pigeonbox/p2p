package main

// 口令不得进子进程 argv 的守卫（2026-10-26 审计 P1）：
// Linux 上 /proc/<pid>/cmdline 默认全员可读，p2pcweb 正是 NAS 三端以服务
// 方式运行的形态 ⇒ 同机任意低权账号读到 cmdline 即得口令（唯一 bearer
// 凭据）⇒ 可抢先接入信道取走文件。口令改走 PB_P2P_CODE env（env 仅进程
// 属主可读）。

import (
	"os"
	"strings"
	"testing"
	"time"
)

// TestChildArgvHasNoSecret Manager 拉起的传输子进程，argv 不得含口令；
// 口令必须经 PB_P2P_CODE env 传入。
//
// 负对照：把 args 里的 `--code=` 改回来 ⇒ 红。
func TestChildArgvHasNoSecret(t *testing.T) {
	const secret = "ABCD-1234-WXYZ"
	m := NewManager()
	// 注册中心指向不可达端口：子进程会快速失败退出（本用例只关心 argv/env）
	err := m.Start("recv", "http://127.0.0.1:1", secret, "", t.TempDir(), "", true, nil)
	if err != nil {
		t.Fatalf("启动子进程: %v", err)
	}
	defer func() {
		m.Cancel()
		// 等子进程退出，避免遗留
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) && m.Busy() {
			time.Sleep(20 * time.Millisecond)
		}
	}()

	m.mu.Lock()
	cmd := m.cmd
	m.mu.Unlock()
	if cmd == nil {
		t.Fatal("未记录子进程")
	}

	for _, a := range cmd.Args {
		if strings.Contains(a, secret) {
			t.Fatalf("子进程 argv 含口令: %q", cmd.Args)
		}
		if strings.HasPrefix(a, "--code=") {
			t.Fatalf("子进程 argv 仍带 --code= 旗标: %q", cmd.Args)
		}
	}
	// 口令必须出现在 env 里（子进程侧 resolveChildCode 据此解析）
	found := false
	for _, e := range cmd.Env {
		if e == "PB_P2P_CODE="+secret {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("子进程 env 未带 PB_P2P_CODE（口令无处可取）: %v", cmd.Env)
	}
}

// TestResolveChildCode 子进程口令解析：旗标优先，其次 env。
func TestResolveChildCode(t *testing.T) {
	t.Setenv("PB_P2P_CODE", "ENV-CODE-1234")
	if got := resolveChildCode(""); got != "ENV-CODE-1234" {
		t.Fatalf("env 取码失败: %q", got)
	}
	if got := resolveChildCode("FLAG-CODE-5678"); got != "FLAG-CODE-5678" {
		t.Fatalf("旗标应优先: %q", got)
	}
	os.Unsetenv("PB_P2P_CODE")
	if got := resolveChildCode("  "); got != "" {
		t.Fatalf("无来源应为空: %q", got)
	}
}
