package client

import (
	"encoding/json"
	"strings"
	"testing"
)

// fakeExch 内存假身:回放对端版本帧,捕获本端帧。
type fakeExch struct {
	peer []byte
	sent []byte
}

func (f *fakeExch) send(p []byte) error   { f.sent = p; return nil }
func (f *fakeExch) recv() ([]byte, error) { return f.peer, nil }

func mustFrame(t *testing.T, v versionFrame) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// 本端帧形态锁:floor==proto 时省略,与 v0.6.x 线上帧逐字节一致——存量
// fleet 零 wire 变化的前提。protoVersion 升版时此断言须同步重审。
func TestNegotiateOutboundFrameCompat(t *testing.T) {
	f := &fakeExch{peer: mustFrame(t, versionFrame{Proto: protoVersion})}
	if _, err := negotiateVersion(f); err != nil {
		t.Fatalf("同版协商失败: %v", err)
	}
	if got := string(f.sent); got != `{"proto":4}` {
		t.Fatalf("本端帧形态漂移: got %s", got)
	}
}

func TestNegotiateSameVersionWithFloor(t *testing.T) {
	agreed, err := negotiateVersion(&fakeExch{peer: mustFrame(t, versionFrame{Proto: 4, Floor: 4})})
	if err != nil || agreed != 4 {
		t.Fatalf("agreed=%d err=%v", agreed, err)
	}
}

// 未来双格式端(能讲 v4):本端必须放行,由对端降级到 agreed——区间协商
// 的核心目标(高版本端负责降级,NAS 钉版旧端不升级也能互操作)。
func TestNegotiateNewerDowngradablePeer(t *testing.T) {
	agreed, err := negotiateVersion(&fakeExch{peer: mustFrame(t, versionFrame{Proto: 5, Floor: 4})})
	if err != nil || agreed != 4 {
		t.Fatalf("agreed=%d err=%v", agreed, err)
	}
}

func TestNegotiateIncompatiblePeers(t *testing.T) {
	cases := []struct {
		name string
		peer versionFrame
	}{
		{"新端不可降级", versionFrame{Proto: 5, Floor: 5}},
		{"新端无floor视作不可降级", versionFrame{Proto: 5}},
		{"floor声明越界", versionFrame{Proto: 5, Floor: 9}},
		{"v3过旧", versionFrame{Proto: 3}},
		{"v3双格式本端讲不了", versionFrame{Proto: 3, Floor: 3}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := negotiateVersion(&fakeExch{peer: mustFrame(t, tc.peer)})
			if err == nil {
				t.Fatal("应报错却成功")
			}
			if !strings.Contains(err.Error(), "github.com/pigeonbox/p2p/releases") {
				t.Fatalf("错误须带下载指引: %v", err)
			}
		})
	}
}

// v2 及以下(无协商帧)保持可读报错。
func TestNegotiateLegacyNoFrame(t *testing.T) {
	_, err := negotiateVersion(&fakeExch{peer: []byte(`{"hello":"world"}`)})
	if err == nil || !strings.Contains(err.Error(), "不支持协议协商") {
		t.Fatalf("err=%v", err)
	}
}

// TestProtoFloorNeedsDowngradePath protoFloor < protoVersion 时必须已落地
// 「按 agreed 选帧格式」的降级路径——否则 floor 只是注释里的承诺:判定会
// 放行低版本对端,本端却仍用高版本帧格式 ⇒ 静默不兼容。
//
// 这条守卫就是「下次按注释改常量不会静默失效」的机械保证:
// 下一个实施者把 protoFloor 调到 4 会先撞红本断言。
func TestProtoFloorNeedsDowngradePath(t *testing.T) {
	if protoFloor < protoVersion && !frameFormatDowngradeImplemented {
		t.Fatalf("protoFloor=v%d < protoVersion=v%d,但未实现「按 agreed 选帧格式」的降级路径 ⇒ N-1 兼容窗口是空承诺",
			protoFloor, protoVersion)
	}
}

// TestDecideVersionFloorSemantics 判定规则必须以 floor 为准（不是 proto）:
// 本端 v5(floor=4) 对 v4 对端 ⇒ 放行 agreed=4;对 v3 对端 ⇒ 拒。
func TestDecideVersionFloorSemantics(t *testing.T) {
	cases := []struct {
		name                   string
		localProto, localFloor int
		peerProto, peerFloor   int
		wantAgreed             int
		wantErr                bool
	}{
		{"同版", 4, 4, 4, 4, 4, false},
		{"过旧对端", 4, 4, 3, 3, 0, true},
		{"v5 本端 floor=4 放行 v4 对端", 5, 4, 4, 4, 4, false},
		{"v5 本端 floor=4 拒 v3 对端", 5, 4, 3, 3, 0, true},
		{"v4 本端对 v5 不可降级对端", 4, 4, 5, 5, 0, true},
		{"v4 本端对 v5 可降级对端", 4, 4, 5, 4, 4, false},
		{"对端无 floor 按其 proto", 5, 4, 4, 0, 4, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			agreed, err := decideVersion(tc.localProto, tc.localFloor, tc.peerProto, tc.peerFloor)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("应报错却成功(agreed=%d)", agreed)
				}
				if !strings.Contains(err.Error(), "github.com/pigeonbox/p2p/releases") {
					t.Fatalf("错误须带下载指引: %v", err)
				}
				return
			}
			if err != nil || agreed != tc.wantAgreed {
				t.Fatalf("agreed=%d err=%v,期望 agreed=%d", agreed, err, tc.wantAgreed)
			}
		})
	}
}

// 错误文案必须打印**真实 floor**（此前印「不可降级」与事实相反）。
func TestVersionErrorMentionsRealFloor(t *testing.T) {
	_, err := decideVersion(5, 4, 3, 3)
	if err == nil {
		t.Fatal("应报错")
	}
	msg := err.Error()
	if !strings.Contains(msg, "可低至 v4") {
		t.Fatalf("错误文案未打印本端真实 floor: %q", msg)
	}
	if strings.Contains(msg, "不可降级") {
		t.Fatalf("错误文案仍印「不可降级」: %q", msg)
	}
}
