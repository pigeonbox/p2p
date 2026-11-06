package relay

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// 回归锁（2026-11-06 P1）：per-IP 并发槽位必须在**等待配对期间**保持占用。
//
// 缺陷：handle 里槽位由无条件 defer 归还，而连接挂进 s.waiting 之后 handle
// 立刻返回 ⇒ 槽位当场释放，可连接还躺在 waiting 里占着全局名额（最长
// waitingTimeout=60s）⇒ 攻击者用随机 token 每轮开满 maxConnsPerIP 条、拿到
// 槽位即释放，可以无限次灌 waiting、把全局 maxWaiting 占满 ⇒ **per-IP 配额
// 在 waiting 阶段完全失效**（正是当初引入它的那个 DoS 面）。
//
// 负对照：把 handle 末尾的 release = false 删掉（回到无条件 defer 归还），
// 本用例会断言 perIP == 16 而实际为 0 ⇒ 转红。
func TestHandle_WaitingKeepsPerIPSlot(t *testing.T) {
	ctx := context.Background()
	s := &server{
		waiting:        map[string]net.Conn{},
		since:          map[string]time.Time{},
		perIP:          map[string]int{},
		waitingIP:      map[string]string{},
		maxWaiting:     1024,
		maxConnsPerIP:  16,
		waitingTimeout: time.Minute,
	}

	var clients []net.Conn
	for i := 0; i < s.maxConnsPerIP; i++ {
		srv, cli := net.Pipe()
		clients = append(clients, cli)
		go s.handle(ctx, srv)
		// token 必须是 64 位小写 hex（readLine 的硬判据）
		line := fmt.Sprintf("RELAY %064x\n", i+1)
		go func(c net.Conn, l string) { _, _ = c.Write([]byte(l)) }(cli, line)
	}
	t.Cleanup(func() {
		for _, c := range clients {
			_ = c.Close()
		}
	})

	require.Eventually(t, func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		return len(s.waiting) == s.maxConnsPerIP
	}, 5*time.Second, 10*time.Millisecond, "全部连接应已被收纳进 waiting")

	s.mu.Lock()
	got := s.perIP["pipe"]
	waitingIPs := len(s.waitingIP)
	s.mu.Unlock()
	assert.Equal(t, s.maxConnsPerIP, got,
		"等待配对期间 per-IP 槽位必须保持占用（否则全局 waiting 可被单 IP 灌满）")
	assert.Equal(t, s.maxConnsPerIP, waitingIPs, "每个 waiting 条目都应记着自己的槽位属主")

	// 超限的第 17 条：拒绝，且不得影响已有计数
	srv17, cli17 := net.Pipe()
	t.Cleanup(func() { _ = srv17.Close(); _ = cli17.Close() })
	s.handle(ctx, srv17) // 判据在 readLine 之前 ⇒ 立即返回
	s.mu.Lock()
	after := s.perIP["pipe"]
	s.mu.Unlock()
	assert.Equal(t, s.maxConnsPerIP, after, "被拒连接不得改动计数")
}

// 配对成功时两个槽位都要归还：否则长时间运行后 perIP 只增不减，
// 同一 IP 的用户会在若干次正常传输后被永久拒连。
func TestHandle_PairingReleasesBothSlots(t *testing.T) {
	ctx := context.Background()
	s := &server{
		waiting:        map[string]net.Conn{},
		since:          map[string]time.Time{},
		perIP:          map[string]int{},
		waitingIP:      map[string]string{},
		maxWaiting:     1024,
		maxConnsPerIP:  16,
		waitingTimeout: time.Minute,
	}

	token := fmt.Sprintf("%064x", 42)
	line := "RELAY " + token + "\n"

	srv1, cli1 := net.Pipe()
	go s.handle(ctx, srv1)
	go func() { _, _ = cli1.Write([]byte(line)) }()
	require.Eventually(t, func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		return len(s.waiting) == 1
	}, 5*time.Second, 10*time.Millisecond)

	srv2, cli2 := net.Pipe()
	go s.handle(ctx, srv2)
	go func() { _, _ = cli2.Write([]byte(line)) }()

	// 配对后两条 pipe 各自搬运直到对端关闭；关闭客户端即结束
	require.Eventually(t, func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		return len(s.waiting) == 0
	}, 5*time.Second, 10*time.Millisecond, "同 token 的两条连接应配对出队")

	_ = cli1.Close()
	_ = cli2.Close()

	require.Eventually(t, func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.perIP["pipe"] == 0 && len(s.waitingIP) == 0
	}, 5*time.Second, 10*time.Millisecond, "配对/拆除后两个槽位都必须归还干净")
}
