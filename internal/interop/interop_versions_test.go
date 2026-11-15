package interop

// wire 互操作矩阵第二、三格（pigeonbox/p2p#50）：版本协商的跨版本验收。
//
// 取舍（in-proc 帧模拟 vs #50 的真二进制口径）：#50 验收写的是「按 tag 检出
// N-1 版本二进制、起双端真实进程」；本两格按任务约定先落零网络零二进制依赖
// 的 in-proc 版——对端握手帧按旧版 tag 的线上字节构造，经
// client.NegotiateWithPeerFrame（与线上 sendChannel/receiveFrom 同一
// negotiateVersion 实现）判定。真二进制矩阵格待 CI job 落地时在本包并列
// 补齐；届时本文件的帧字节即为对端帧的对照基线。
//
// 上一兼容版取数（git tag，2026-11-15 核）：
//   - v0.9.6（上一 release）：git diff v0.9.6..HEAD -- internal/client/protocol.go
//     为空 ⇒ 协商逻辑与当前逐字一致；出帧 versionFrame{Proto:4}（floor 省略）
//     ⇒ `{"proto":4}`。
//   - v0.6.11（上一 wire 格式代，floor 协商前）：json.Marshal(map[string]int
//     {"proto":4}) ⇒ 同字节 `{"proto":4}`；判定为等值匹配（peer.Proto==4）。

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/pigeonbox/p2p/internal/client"
)

// negotiateOnce 限时跑一次协商——第三格验收含「不挂死」：帧层虽为同步判定，
// 仍用统一口径钉住 5s 内必须返回。
func negotiateOnce(t *testing.T, peerFrame string) (agreed int, ownFrame []byte, err error) {
	t.Helper()
	type result struct {
		agreed int
		own    []byte
		err    error
	}
	ch := make(chan result, 1)
	go func() {
		a, o, e := client.NegotiateWithPeerFrame([]byte(peerFrame))
		ch <- result{a, o, e}
	}()
	select {
	case r := <-ch:
		return r.agreed, r.own, r.err
	case <-time.After(5 * time.Second):
		t.Fatalf("版本协商挂死(>5s)，对端帧=%s", peerFrame)
		return 0, nil, nil // unreachable
	}
}

// TestInteropCurrentPrevCompatible 矩阵第二格「当前版 ↔ 上一兼容版」：
// 上一兼容版实帧必须落进协议窗口（agreed=4，不误拒）；本端出帧必须是上一
// 兼容版可接受的形态（与之逐字节一致）；并复核窗口降级分支放行。
func TestInteropCurrentPrevCompatible(t *testing.T) {
	t.Run("上一兼容版实帧落窗", func(t *testing.T) {
		cases := []struct{ name, frame string }{
			// v0.9.6 与 v0.6.11 出帧同字节（见文件头取数）
			{"v0.9.6/v0.6.x同字节实帧", `{"proto":4}`},
			// floor 字段存在后的同窗形态（floor==proto 时旧端省略，此处补全窗口两端）
			{"同窗带floor形态", `{"proto":4,"floor":4}`},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				agreed, _, err := negotiateOnce(t, tc.frame)
				// 升 v5(floor=4) 后对 v4 上一兼容版仍 agreed=4；floor 抬出
				// v4 时本格应随「上一兼容版」换帧重审。
				if err != nil || agreed != 4 {
					t.Fatalf("上一兼容版应落窗 agreed=4: agreed=%d err=%v", agreed, err)
				}
			})
		}
	})

	t.Run("本端出帧上一兼容版可接受", func(t *testing.T) {
		agreed, own, err := negotiateOnce(t, `{"proto":4}`)
		if err != nil || agreed != 4 {
			t.Fatalf("agreed=%d err=%v", agreed, err)
		}
		// 与 v0.9.6/v0.6.x 出帧逐字节一致（同为 {"proto":4}）⇒ 互换即通。
		// protoVersion 升 v5 时此形态锁须随 wire 兼容窗口重审——同
		// protocol_test.TestNegotiateOutboundFrameCompat 的口径。
		if string(own) != `{"proto":4}` {
			t.Fatalf("本端出帧与上一兼容版形态不一致: got %s", own)
		}
		// v0.6.x 等值匹配规则复核（git show v0.6.11:internal/client/protocol.go：
		// peer.Proto != protoVersion 即拒）：本端帧 proto 必须 == 4。
		var f struct {
			Proto int `json:"proto"`
		}
		if err := json.Unmarshal(own, &f); err != nil || f.Proto != 4 {
			t.Fatalf("v0.6.x 等值匹配下本端帧不被接受: %s（解析 err=%v）", own, err)
		}
	})

	t.Run("窗口降级分支放行", func(t *testing.T) {
		// 对端为更高 proto 但 floor 落在本窗口内 ⇒ agreed=min=4（降级发生：
		// agreed < 对端 proto）。对偶方向共享同一判定式（agreed=min + 双
		// floor 下限），故本放行 ⇔ 本端升 v5(5,4) 后对 v4 上一兼容版放行——
		// v5 升版时本子项按新窗口重审（届时对端 (5,4) 变同版，降级由对偶
		// 方向的真实矩阵格覆盖）。
		agreed, _, err := negotiateOnce(t, `{"proto":5,"floor":4}`)
		if err != nil || agreed != 4 {
			t.Fatalf("窗口内可降对端应 agreed=4: agreed=%d err=%v", agreed, err)
		}
	})
}

// TestInteropCurrentIncompatibleOld 矩阵第三格「当前版 ↔ 不兼容旧版」：
// 对端 floor/proto 落在本端窗口外 ⇒ 可解释地拒绝——错误点名双方版本并带
// 升级指引（协议协商层错误，不是 AEAD 解密那种密码学报错），且同步返回
// 不挂死（5s 限时在 negotiateOnce 内）。
func TestInteropCurrentIncompatibleOld(t *testing.T) {
	cases := []struct {
		name  string
		frame string // 对端线上帧（旧版/越界真实形态）
		want  string // 可读错误必含片段
		ver   string // 对端版本点名片段（无协商帧形态为空）
	}{
		{"过旧v3等值代", `{"proto":3}`, "传输协议版本不兼容", "对端 v3"},
		{"过旧v3双格式", `{"proto":3,"floor":3}`, "传输协议版本不兼容", "对端 v3"},
		{"过旧v2及以下无协商帧", `{"hello":"world"}`, "不支持协议协商", ""},
		{"新端floor高于本端", `{"proto":5,"floor":5}`, "传输协议版本不兼容", "对端 v5"},
		{"新端无floor按不可降级", `{"proto":5}`, "传输协议版本不兼容", "对端 v5"},
		{"floor声明越界按不可降级", `{"proto":5,"floor":9}`, "传输协议版本不兼容", "对端 v5"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := negotiateOnce(t, tc.frame)
			if err == nil {
				t.Fatalf("不兼容对端应被拒绝却放行: %s", tc.frame)
			}
			msg := err.Error()
			if !strings.Contains(msg, tc.want) {
				t.Fatalf("错误不可读（缺 %q）: %q", tc.want, msg)
			}
			if tc.ver != "" && !strings.Contains(msg, tc.ver) {
				t.Fatalf("错误未点名对端版本（缺 %q）: %q", tc.ver, msg)
			}
			if !strings.Contains(msg, "github.com/pigeonbox/p2p/releases") {
				t.Fatalf("错误缺升级指引: %q", msg)
			}
		})
	}
}
