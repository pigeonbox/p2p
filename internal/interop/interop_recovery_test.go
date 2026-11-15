package interop

// 矩阵第五格「断网 / 恢复 / 重复发送」（pigeonbox/p2p#50）：
// 传输中断恢复 → 幂等（重复发送不重复落盘/不损坏）→ 最终哈希一致。
//
// 复用既有基建（transfer.go recvOneFileMeta）：
//   - 迅雷式暂存：传输写 <name>.part，完成才原子改名——半成品不伪装完整文件；
//   - 断点续传：接收方按 .part 字节数回 ready{offset}，发送端从 offset 续发，
//     前缀+剩余流式累计哈希与全文件 sha256 比对；
//   - 坏内容清理：校验失败删除半成品，不以正式文件名残留。
//
// 取舍（真断网 vs 预置现场）：e2e 层 Send/Receive 无 ctx 注入钩子，无法确定性
// 掐断进行中的连接（掐早了没建立、掐晚了已传完都是碰运气）⇒ 与 client 包
// TestSendRecvResumeFromPartial 同口径：用**预置 .part 半成品**确定性地
// 代表「上一轮中断留下的现场」，考恢复路径。前缀是否真被采用由负对照
// （篡改前缀）钉住——见子测试注释。

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pigeonbox/p2p/internal/client"
)

// TestInteropInterruptResumeIdempotent 矩阵第五格（细节见文件头）。
func TestInteropInterruptResumeIdempotent(t *testing.T) {
	f := newFixture(t) // 中继+反射器双能力；传输腿走 testOpts 默认 DisablePunch（确定性）

	payload := make([]byte, 1<<20) // 1MB：走压缩+单流（<8MB 多流阈值）
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(payload)
	wantHex := hex.EncodeToString(sum[:])
	const name = "中断恢复.bin"
	partName := name + ".part"

	// runOnce 完整跑一轮 Send/Receive 到 recvDir（新口令/新发送目录）。
	// 返回接收侧文件列表；两侧错误都带出现场（发送侧等待上限 10s）。
	runOnce := func(t *testing.T, recvDir string) ([]string, error) {
		t.Helper()
		code, err := client.GenerateCode()
		if err != nil {
			return nil, fmt.Errorf("生成口令: %w", err)
		}
		sendDir := t.TempDir()
		src := filepath.Join(sendDir, name)
		if err := os.WriteFile(src, payload, 0o644); err != nil {
			return nil, fmt.Errorf("写源文件: %w", err)
		}
		sendErr := make(chan error, 1)
		go func() {
			c, err := client.New(testOpts(f, "send"))
			if err != nil {
				sendErr <- fmt.Errorf("发送端构造: %w", err)
				return
			}
			_, err = c.Send([]string{src}, code)
			sendErr <- err
		}()
		waitForAnnounce(t, f.base, code)
		rc, err := client.New(testOpts(f, "recv"))
		if err != nil {
			return nil, fmt.Errorf("接收端构造: %w", err)
		}
		outFiles, rerr := rc.Receive(code, recvDir)
		var serr error
		select {
		case serr = <-sendErr:
		case <-time.After(10 * time.Second):
			serr = fmt.Errorf("发送侧 10s 未收尾")
		}
		if rerr != nil {
			if serr != nil {
				return nil, fmt.Errorf("接收: %v（发送侧: %w）", rerr, serr)
			}
			return nil, fmt.Errorf("接收: %w", rerr)
		}
		if serr != nil {
			return nil, fmt.Errorf("发送: %w", serr)
		}
		return outFiles, nil
	}

	// assertOneCleanFile 断言 recvDir 恰好一个正式文件、名对、哈希对、无 .part。
	assertOneCleanFile := func(t *testing.T, recvDir string, outFiles []string) {
		t.Helper()
		if len(outFiles) != 1 {
			t.Fatalf("期望 1 个文件，实际 %d: %v", len(outFiles), outFiles)
		}
		if filepath.Base(outFiles[0]) != name {
			t.Fatalf("落盘名 %q ≠ 原名 %q", filepath.Base(outFiles[0]), name)
		}
		if got := sha256File(t, outFiles[0]); got != wantHex {
			t.Fatalf("最终哈希不一致: got %s want %s", got, wantHex)
		}
		entries, err := os.ReadDir(recvDir)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 1 || entries[0].Name() != name {
			names := make([]string, 0, len(entries))
			for _, e := range entries {
				names = append(names, e.Name())
			}
			t.Fatalf("目录应只有 %q，实际 %v（重复落盘/半成品残留）", name, names)
		}
		if _, err := os.Stat(filepath.Join(recvDir, partName)); !os.IsNotExist(err) {
			t.Fatalf(".part 应已原子改名清理，stat err=%v", err)
		}
	}

	t.Run("断点恢复", func(t *testing.T) {
		// 中断现场：预置正确前缀的 .part（前 256KB）——上一轮传到 1/4 断网
		// 所留。恢复传输必须从 offset 续传并最终哈希一致。
		recvDir := t.TempDir()
		if err := os.WriteFile(filepath.Join(recvDir, partName), payload[:256<<10], 0o600); err != nil {
			t.Fatal(err)
		}
		outFiles, err := runOnce(t, recvDir)
		if err != nil {
			t.Fatalf("断点恢复传输失败: %v", err)
		}
		assertOneCleanFile(t, recvDir, outFiles)
	})

	t.Run("篡改前缀必失败(负对照)", func(t *testing.T) {
		// 负对照：把 .part 前缀篡改（同长度、内容不同）。
		//   - 续传语义为真（采用盘上前缀）⇒ 前缀哈希进全量校验 ⇒ 必
		//     sha256 不匹配 ⇒ 传输失败 + 坏内容不落正式名 ⇒ 本格绿；
		//   - 若实现退化为「忽略 .part 全量覆盖」⇒ 篡改被冲掉 ⇒ 传输成功
		//     ⇒ 本格红（续传语义丢失即被抓）。
		//   - 若实现「采前缀但不校验」⇒ 坏文件落正式名 ⇒ 本格红（不损坏
		//     文件的底线即被抓）。
		recvDir := t.TempDir()
		corrupt := make([]byte, 256<<10)
		for i := range corrupt {
			corrupt[i] = ^payload[i]
		}
		if err := os.WriteFile(filepath.Join(recvDir, partName), corrupt, 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := runOnce(t, recvDir)
		if err == nil {
			t.Fatal("篡改前缀的断点续传必须校验失败，实际传输成功（续传语义丢失或未校验）")
		}
		if !strings.Contains(err.Error(), "sha256 不匹配") {
			t.Fatalf("错误应点名 sha256 不匹配: %v", err)
		}
		// 坏内容清理：.part 已删、无正式文件残留。
		entries, rerr := os.ReadDir(recvDir)
		if rerr != nil {
			t.Fatal(rerr)
		}
		if len(entries) != 0 {
			names := make([]string, 0, len(entries))
			for _, e := range entries {
				names = append(names, e.Name())
			}
			t.Fatalf("校验失败后目录应为空（坏内容不残留），实际 %v", names)
		}
	})

	t.Run("重复发送幂等", func(t *testing.T) {
		// 同一内容完整发送两轮到同一目录：两轮都成功、目录恒为同一个文件
		// （不重复落盘）、两轮哈希都对（不损坏）、无 .part 残留。
		recvDir := t.TempDir()
		for round := 1; round <= 2; round++ {
			outFiles, err := runOnce(t, recvDir)
			if err != nil {
				t.Fatalf("第 %d 轮重复发送失败: %v", round, err)
			}
			assertOneCleanFile(t, recvDir, outFiles)
		}
	})
}
