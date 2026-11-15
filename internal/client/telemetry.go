package client

import (
	"context"
	"time"

	"github.com/oekit/concurrency/async"
)

// reportSession 会话建立结果遥测上报(p2p#51 直连率)。
//
// best-effort 三重兜底:异步(GoSafe 收编 panic)+短超时(3s)+失败仅 Debug
// ——遥测绝不拖慢或打断传输。regBase 为空(单测/未知基址)时直接跳过。
func (c *Client) reportSession(regBase, kind, path, reason string) {
	if regBase == "" {
		return
	}
	async.GoSafeLabeled("p2p-telemetry", func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := newRegistryAPI(regBase).telemetry(ctx, c.id, kind, path, reason); err != nil {
			c.log.Debug("遥测上报失败", "err", err)
		}
	})
}
