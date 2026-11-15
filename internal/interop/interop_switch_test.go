package interop

// 矩阵第四格「中继 ↔ 直连切换」（pigeonbox/p2p#50）。
//
// 取舍（为何是「两腿强制路径」而不是「单会话中途 MsgSwap 换源」）：
//   - 单会话「中继先行 → 后台打洞升级 → 文件边界 MsgSwap 换源」的切换时刻
//     取决于后台升级何时 arm（loopback 上毫秒~秒级不定），CI 无法稳定断言
//     「真的切了」——切没切都可能绿，矩阵格会退化成摆设；
//   - 本格改用**路径可证明**的两腿 e2e，复用第一格 fixture（中继+反射器双能力）：
//     腿1 DisablePunch=true ⇒ 只可能走中继；腿2 NoRelay=true ⇒ 直连失败无中继
//     兜底（client.go establish：NoRelay 时 relayOK 恒 false ⇒ 不进 establishRelay）
//     ⇒ 腿2 成功即证明走的是直连。两腿同一载荷同名 ⇒ 哈希相等即「数据连续」。
//   - 单会话中途换源（MsgSwap）的确定性覆盖已有 client 包注入承载用例：
//     TestRecvAllKeepsCarrierUntilSwap / TestRecvAllAwaitsNewCarrierAfterSwap /
//     TestSendAllAwaitsNewCarrierAfterSwap（pipeXport 注入两腿，不依赖打洞）——
//     与本格互补：那边考「切的过程不断」，本格考「两条路各自端到端能通且同数据」。
//   - 打洞在 CI 上环境敏感（client_test.go U2a 取证）⇒ 直连腿带与
//     retryEstablishFlake 同口径的有界重试：只认建立层签名、3 次全命中仍红。

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

// linkLeg 一条腿的跑完结果。
type linkLeg struct {
	outPath string
	hash    string
}

// linkFlakeSignatures 建立层环境敏感 flake 签名——与 client_test.go
// establishFlakeSignatures 同单（那边是 _test 包内符号不可导入，此处按同
// 口径复制；收紧不放宽）。
var linkFlakeSignatures = []string{
	"打洞失败", "打洞超时",
	"quic 建立", "quic 拨号", "quic 接受连接", "quic 打开流", "quic 接受流",
	"no recent network activity",
}

// isLinkFlake 判定错误是否命中建立层 flake 签名（白名单见 linkFlakeSignatures）。
func isLinkFlake(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	for _, sig := range linkFlakeSignatures {
		if strings.Contains(msg, sig) {
			return true
		}
	}
	return false
}

// retryLinkLeg 有界重试：attempt 返回 nil 即成；非签名错误立即红；签名错误
// 至多 3 次，全命中仍红（保守报警，与 client retryEstablishFlake 同口径）。
func retryLinkLeg(t *testing.T, attempt func() (linkLeg, error)) linkLeg {
	t.Helper()
	const maxAttempts = 3
	var last error
	for i := 1; i <= maxAttempts; i++ {
		res, err := attempt()
		if err == nil {
			return res
		}
		if !isLinkFlake(err) {
			t.Fatalf("第 %d/%d 次尝试失败（非建立层 flake 签名，不重试）：%v", i, maxAttempts, err)
		}
		last = err
		t.Logf("第 %d/%d 次命中已知环境敏感 flake 签名，重试：%v", i, maxAttempts, err)
	}
	t.Fatalf("%d 次尝试均命中环境敏感 flake 签名（保守报警，按真失败处置）：%v", maxAttempts, last)
	return linkLeg{} // unreachable
}

// TestInteropRelayDirectSwitch 矩阵第四格「中继 ↔ 直连切换」：同一 fixture
// 上先走强制中继腿、再走强制直连腿，两腿端到端各传同一载荷同名文件——
// 各自 sha256 必须等于源（数据不因路变而坏），两腿哈希互等（数据连续）。
func TestInteropRelayDirectSwitch(t *testing.T) {
	f := newFixture(t)

	// 同一载荷跨两腿（1MB：与第一格同量级，走压缩+单流路径）
	payload := make([]byte, 1<<20)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	wantHash := sha256.Sum256(payload)
	wantHex := hex.EncodeToString(wantHash[:])
	const linkName = "链路切换.bin"

	// runLeg 跑一条腿：独立口令/目录，返回落盘路径与哈希。
	// mod 为 nil 时用 testOpts 默认（DisablePunch=true ⇒ 强制中继）。
	runLeg := func(t *testing.T, tag string, mod func(*client.Options)) (linkLeg, error) {
		t.Helper()
		code, err := client.GenerateCode()
		if err != nil {
			return linkLeg{}, fmt.Errorf("生成口令: %w", err)
		}
		sendDir := t.TempDir()
		recvDir := t.TempDir()
		src := filepath.Join(sendDir, linkName)
		if err := os.WriteFile(src, payload, 0o644); err != nil {
			return linkLeg{}, fmt.Errorf("写源文件: %w", err)
		}
		so := testOpts(f, "send-"+tag)
		ro := testOpts(f, "recv-"+tag)
		if mod != nil {
			mod(&so)
			mod(&ro)
		}
		sendErr := make(chan error, 1)
		go func() {
			c, err := client.New(so)
			if err != nil {
				sendErr <- fmt.Errorf("发送端构造: %w", err)
				return
			}
			_, err = c.Send([]string{src}, code)
			sendErr <- err
		}()
		waitForAnnounce(t, f.base, code)
		rc, err := client.New(ro)
		if err != nil {
			return linkLeg{}, fmt.Errorf("接收端构造: %w", err)
		}
		outFiles, rerr := rc.Receive(code, recvDir)
		if rerr != nil {
			select {
			case e := <-sendErr:
				return linkLeg{}, fmt.Errorf("接收: %v（发送侧: %v）", rerr, e)
			default:
				return linkLeg{}, fmt.Errorf("接收: %v（发送侧仍在跑，无错误上报）", rerr)
			}
		}
		if err := <-sendErr; err != nil {
			return linkLeg{}, fmt.Errorf("发送: %w", err)
		}
		if len(outFiles) != 1 {
			return linkLeg{}, fmt.Errorf("期望 1 个文件，实际 %d", len(outFiles))
		}
		return linkLeg{outPath: outFiles[0], hash: sha256File(t, outFiles[0])}, nil
	}

	var relayHash, directHash string

	t.Run("中继腿强制中继", func(t *testing.T) {
		res, err := runLeg(t, "relay", nil) // testOpts 默认 DisablePunch=true
		if err != nil {
			t.Fatalf("中继腿: %v", err)
		}
		if filepath.Base(res.outPath) != linkName {
			t.Errorf("落盘名 %q ≠ 原名 %q", filepath.Base(res.outPath), linkName)
		}
		if res.hash != wantHex {
			t.Fatalf("中继腿哈希不一致: got %s want %s", res.hash, wantHex)
		}
		relayHash = res.hash
	})

	t.Run("直连腿仅直连", func(t *testing.T) {
		directMod := func(o *client.Options) {
			o.DisablePunch = false // 打洞开
			o.NoRelay = true       // 中继不参与 ⇒ 成功即证明走的直连
			o.PunchBudget = 45 * time.Second
		}
		res := retryLinkLeg(t, func() (linkLeg, error) {
			return runLeg(t, "direct", directMod)
		})
		if filepath.Base(res.outPath) != linkName {
			t.Errorf("落盘名 %q ≠ 原名 %q", filepath.Base(res.outPath), linkName)
		}
		if res.hash != wantHex {
			t.Fatalf("直连腿哈希不一致: got %s want %s", res.hash, wantHex)
		}
		directHash = res.hash
	})

	t.Run("跨腿数据一致", func(t *testing.T) {
		if relayHash == "" || directHash == "" {
			t.Fatal("前置腿未跑完（见上文子测试）")
		}
		if relayHash != directHash {
			t.Fatalf("两腿哈希不一致（数据不连续）: 中继 %s ≠ 直连 %s", relayHash, directHash)
		}
	})
}
