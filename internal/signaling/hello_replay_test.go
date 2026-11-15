package signaling

import (
	"strings"
	"testing"
	"time"

	"github.com/pigeonbox/p2p/internal/registry"
)

// p2p#47 复现:hello 签名无一次性凭据——明文链路下 5 分钟窗口内观察者
// 可重放同一 hello 帧,以受害者 node_id 占住会话槽位(受害者真身接入即 4002 busy)。
// 修复方向(帧格式不动):ts 秒级时间戳在 ±MaxClockSkew 窗口内天然是一次性
// 凭据,服务端按 (node_id, code_hash, ts) 去重,与注册面 markNonce 同款。

// 同一 hello 帧(node/hash/ts)重放必须被拒;修复前重放会配对占槽。
func TestHelloReplayRejected(t *testing.T) {
	srv, svc := newFixture(t, nil)
	ws := "ws" + strings.TrimPrefix(srv.URL, "http")
	a := registerNode(t, svc, "https://a")
	hash := registry.CodeHash("replay-code-1234567890")
	ts := time.Now().Unix()

	conn1 := dial(t, ws, hash)
	hello(t, conn1, a, hash, ts)
	mustFrame(t, conn1) // waiting

	// 攻击者重放完全相同的 hello(同 node_id/hash/ts/sig)
	conn2 := dial(t, ws, hash)
	hello(t, conn2, a, hash, ts)
	_, code := readNext(t, conn2)
	if code != closeDenied {
		t.Fatalf("重放 hello 须拒(closeDenied=%d),实际 code=%d——修复前重放会配对占槽",
			closeDenied, code)
	}
}

// 反向保护:去重键不得过宽——同 node 换 ts(正常重连)、同 ts 换 hash
// (同秒开不同信道)都必须放行,否则正常接入被误杀。
func TestHelloFreshCredsAccepted(t *testing.T) {
	srv, svc := newFixture(t, nil)
	ws := "ws" + strings.TrimPrefix(srv.URL, "http")
	a := registerNode(t, svc, "https://a")
	ts := time.Now().Unix()

	// 场景1:同 hash 新 ts(断线重连/重试)——新配对,须放行
	h1 := registry.CodeHash("fresh-ts-code-1234567890")
	c1 := dial(t, ws, h1)
	hello(t, c1, a, h1, ts)
	mustFrame(t, c1) // waiting
	c2 := dial(t, ws, h1)
	hello(t, c2, a, h1, ts+1)
	if f := mustFrame(t, c2); f.Type != "paired" {
		t.Fatalf("新 ts 重连须放行并配对,得到 %+v", f)
	}

	// 场景2:同 ts 不同 hash(同一秒接入不同信道)——须放行
	h2 := registry.CodeHash("fresh-hash-code-1234567890")
	c3 := dial(t, ws, h2)
	hello(t, c3, a, h2, ts)
	if f := mustFrame(t, c3); f.Type != "waiting" {
		t.Fatalf("同秒不同信道须放行,得到 %+v", f)
	}
}
