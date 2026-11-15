package signaling

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/pigeonbox/p2p/internal/registry"
)

// p2p#46 复现组:信令全局会话配额(1024)没有 per-IP 维度,未配对会话
// 与已配对同 TTL——单 IP 多身份可近似持续占满全局配额,匿名阻断全站配对。

// 单 IP 未配对(waiting)会话超上限必须拒(closeBusy)。
// 修复前:join 只有全局+单节点两道闸,同 IP 第 N 条 waiting 照收。
func TestUnpairedPerIPCap(t *testing.T) {
	srv, svc := newFixture(t, func(c *Config) { c.MaxUnpairedPerIP = 2 })
	ws := "ws" + strings.TrimPrefix(srv.URL, "http")
	a := registerNode(t, svc, "https://a")

	for i := 0; i < 2; i++ {
		hash := registry.CodeHash(fmt.Sprintf("ipcap-code-%d-1234567890", i))
		conn := dial(t, ws, hash)
		hello(t, conn, a, hash, time.Now().Unix())
		if f := mustFrame(t, conn); f.Type != "waiting" {
			t.Fatalf("第 %d 条应为 waiting,得到 %s", i+1, f.Type)
		}
	}

	// 同 IP 第 3 条未配对:超限须拒
	hash := registry.CodeHash("ipcap-code-overflow-1234567890")
	conn := dial(t, ws, hash)
	hello(t, conn, a, hash, time.Now().Unix())
	expectClose(t, conn, closeBusy)
}

// 未配对会话按 UnpairedTTL 提前回收(修复前与 SessionTTL 同 10min,
// 攻击者 waiting 会话可占全局配额长达 10 分钟)。
func TestUnpairedSessionShortTTL(t *testing.T) {
	srv, svc := newFixture(t, func(c *Config) { c.UnpairedTTL = 400 * time.Millisecond })
	ws := "ws" + strings.TrimPrefix(srv.URL, "http")
	a := registerNode(t, svc, "https://a")
	hash := registry.CodeHash("shortttl-code-1234567890")
	conn := dial(t, ws, hash)
	hello(t, conn, a, hash, time.Now().Unix())
	mustFrame(t, conn) // waiting

	// janitor 间隔 = min(SessionTTL,UnpairedTTL)/2;1.5s 内必被清扫
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	expectClose(t, conn, 0)
}

// 反向保护:已配对会话不得被短 TTL 误伤(仍按 SessionTTL)。
// 若实现把 UnpairedTTL 错误套到已配对会话,800ms 后连接已被清扫 ⇒ 红。
func TestPairedSessionKeepsFullTTL(t *testing.T) {
	srv, svc := newFixture(t, func(c *Config) {
		c.UnpairedTTL = 400 * time.Millisecond
		c.SessionTTL = 5 * time.Second
	})
	ws := "ws" + strings.TrimPrefix(srv.URL, "http")
	a := registerNode(t, svc, "https://a")
	b := registerNode(t, svc, "https://b")
	hash := registry.CodeHash("pairedttl-code-1234567890")
	ts := time.Now().Unix()

	connA := dial(t, ws, hash)
	hello(t, connA, a, hash, ts)
	mustFrame(t, connA) // waiting
	connB := dial(t, ws, hash)
	hello(t, connB, b, hash, ts)
	mustFrame(t, connA) // paired
	mustFrame(t, connB)

	time.Sleep(800 * time.Millisecond) // > UnpairedTTL, < SessionTTL
	sendData(t, connA, []byte("still-here"))
	f := mustFrame(t, connB)
	if f.Type != "data" || string(f.Payload) != "still-here" {
		t.Fatalf("已配对会话应存活并可转发,得到 %+v", f)
	}
}
