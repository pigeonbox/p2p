package client

// 配对码全链路 e2e：铸码→敲码→接受门→兑换→既有信道/PAKE/打洞/传输。
// 两个方向各一条：send --pair(发送方亮码) 与 recv --pair(接收方亮码反向)。

import (
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestSendPairedLoopback(t *testing.T) {
	f := newFixture(t, true)
	sendDir, recvDir := t.TempDir(), t.TempDir()
	src := randomFile(t, sendDir, "pair-发送.bin", 1<<20)

	so := testOpts(f, "psend")
	so.PunchBudget = 6 * time.Second
	codeCh := make(chan string, 1)
	errCh := make(chan error, 1)
	go func() {
		c, err := New(so)
		if err != nil {
			errCh <- err
			return
		}
		// OnRequest 为 nil = 自动接受(接受门人工路径另有单测覆盖)
		_, err = c.SendPaired([]string{src}, PairCallbacks{
			OnCode: func(code string, _ time.Duration) { codeCh <- code },
		})
		errCh <- err
	}()

	var pairCode string
	select {
	case pairCode = <-codeCh:
	case err := <-errCh:
		t.Fatalf("发送端提前退出: %v", err)
	case <-time.After(15 * time.Second):
		t.Fatal("等待配对码超时")
	}
	if !IsPairingCode(pairCode) {
		t.Fatalf("配对码形态异常: %q", pairCode)
	}

	ro := testOpts(f, "precv")
	ro.PunchBudget = 6 * time.Second
	rc, err := New(ro)
	if err != nil {
		t.Fatal(err)
	}
	// OnPending 每 2s 轮询触发一次,必须非阻塞——用计数器不用 channel
	// (缓冲 1 的 channel 第二次写入即卡死轮询协程,曾致 e2e 间歇死锁)。
	var pendingCount atomic.Int64
	files, err := rc.ReceivePaired(pairCode, recvDir, PairCallbacks{
		OnPending: func() { pendingCount.Add(1) },
	})
	if err != nil {
		t.Fatalf("ReceivePaired: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("应收到 1 个文件: %v", files)
	}
	data, err := os.ReadFile(filepath.Join(recvDir, filepath.Base(files[0])))
	if err != nil || len(data) != 1<<20 {
		t.Fatalf("落盘校验失败: err=%v size=%d", err, len(data))
	}
	if err := <-errCh; err != nil {
		t.Fatalf("发送端: %v", err)
	}
	if pendingCount.Load() == 0 {
		t.Fatal("claim 应经历 pending 态(接受门语义)")
	}
}

func TestReversePairedLoopback(t *testing.T) {
	f := newFixture(t, true)
	sendDir, recvDir := t.TempDir(), t.TempDir()
	src := randomFile(t, sendDir, "reverse-反向.bin", 512<<10)

	// 反向:接收方亮码(creator),批准后收件
	ro := testOpts(f, "rprecv")
	ro.PunchBudget = 6 * time.Second
	codeCh := make(chan string, 1)
	errCh := make(chan error, 1)
	go func() {
		c, err := New(ro)
		if err != nil {
			errCh <- err
			return
		}
		_, err = c.ReceivePairedAsCreator(recvDir, PairCallbacks{
			OnCode: func(code string, _ time.Duration) { codeCh <- code },
		})
		errCh <- err
	}()

	var pairCode string
	select {
	case pairCode = <-codeCh:
	case err := <-errCh:
		t.Fatalf("接收端提前退出: %v", err)
	case <-time.After(15 * time.Second):
		t.Fatal("等待配对码超时")
	}

	// 发送侧:输码推送(SendByClaim)
	so := testOpts(f, "rpsend")
	so.PunchBudget = 6 * time.Second
	sc, err := New(so)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sc.SendByClaim(pairCode, []string{src}, PairCallbacks{}); err != nil {
		t.Fatalf("SendByClaim: %v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("接收端: %v", err)
	}
	entries, _ := os.ReadDir(recvDir)
	if len(entries) != 1 {
		t.Fatalf("反向应落盘 1 个文件: %d", len(entries))
	}
}
