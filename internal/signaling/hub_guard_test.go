// NewHub 构造期 fail-fast 守卫（p2p#38 的第二道；镜像 config.validate 启动期口径）。
//
// 缺陷形态：NewHub 是公开构造器，绕过 config.Load→validate 的程序化构造
// 漏填 PingPeriod/WriteWait 时，原会在**首个连接的 pingPump** 里以
// time.NewTicker(0) 的晦涩 panic 晚炸（生产路径已被 validate 拦，此守卫
// 堵的是测试/新调用方这条旁路）。
//
// 负对照：撤掉 NewHub 里的校验 ⇒ TestNewHub_RejectsInvalidConfig 转红。
package signaling

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pigeonbox/p2p/internal/registry"
	"github.com/pigeonbox/p2p/internal/store/memory"
)

// newGuardSvc 造一个最小 registry.Service（守卫只校验 cfg，不碰 reg）。
func newGuardSvc() *registry.Service {
	return registry.New(registry.Params{
		Store: memory.New(), MinNodeTTL: time.Minute, MaxNodeTTL: time.Hour,
		MaxAnnounces: 10, MaxAnnounceTTL: time.Hour,
	})
}

// TestNewHub_RejectsInvalidConfig 非法 Config 构造期即 panic（不等到首连接）。
func TestNewHub_RejectsInvalidConfig(t *testing.T) {
	svc := newGuardSvc()
	cases := map[string]func(*Config){
		"PingPeriod=0":     func(c *Config) { c.PingPeriod = 0 },
		"WriteWait=0":      func(c *Config) { c.WriteWait = 0 },
		"PingPeriod>=Idle": func(c *Config) { c.PingPeriod = c.IdleTimeout },
		"负 PingPeriod":     func(c *Config) { c.PingPeriod = -time.Second },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := DefaultConfig()
			mutate(&cfg)
			assert.PanicsWithValue(t, true, func() {
				defer func() {
					if r := recover(); r != nil {
						// 消息必须点名字段与修法（早炸要带清晰信息，不是裸 Ticker panic）
						msg, _ := r.(string)
						require.Contains(t, msg, "PingPeriod=")
						require.Contains(t, msg, "DefaultConfig()")
						panic(true) // 重新抛给 assert.PanicsWithValue 判定
					}
				}()
				NewHub(context.Background(), cfg, svc, nil)
			}, "非法 Config 必须构造期 panic")
		})
	}
}

// TestNewHub_AcceptsValidConfig 合法 Config 正常构造（正对照：守卫不误伤）。
func TestNewHub_AcceptsValidConfig(t *testing.T) {
	cfg := DefaultConfig()
	h := NewHub(context.Background(), cfg, newGuardSvc(), nil)
	require.NotNil(t, h)
	// 边界：PingPeriod 恰好 < IdleTimeout 的最大合法值可构造
	cfg2 := DefaultConfig()
	cfg2.PingPeriod = cfg2.IdleTimeout - time.Millisecond
	require.NotNil(t, NewHub(context.Background(), cfg2, newGuardSvc(), nil))
}
