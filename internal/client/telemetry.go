package client

import (
	"context"
	"net"
	"net/netip"
	"time"

	"github.com/oekit/concurrency/async"
	"github.com/pigeonbox/p2p/internal/registry"
)

// ---- 直连成功率的网络环境分桶(p2p#51) ----
//
// 取值恒为三选一(public|nat|unknown)⇒ 标签基数天然封顶;**任何地址都不进
// 标签**(脱敏)。

// 网络环境分桶取值(与 registry 侧白名单同源)。
const (
	netPublic  = registry.NetPublic
	netNAT     = registry.NetNAT
	netUnknown = registry.NetUnknown
)

// cgnatPrefix CGNAT 网段 100.64.0.0/10(RFC 6598)。
//
// Go 的 netip.IsPrivate 不认它(既非 RFC1918 也非 ULA)⇒ 不显式归入 NAT 侧
// 就会被当成公网地址 ⇒ 直连率分桶失真(运营商 NAT 后的家庭宽带会被算成
// 「公网直连率极高」,结论直接反了)。
var cgnatPrefix = netip.MustParsePrefix("100.64.0.0/10")

// classifyNetClass 按地址集合判定网络环境分桶(纯函数,便于单测)。
//
// 为什么**不**按 NAT 行为类型(对称/端口受限/锥形)分桶:那需要 RFC 5780
// 行为探测(同一 socket 换源端口再探、看映射端口是否变化),本仓没有这类探测
// ⇒ 臆造一个「对称 NAT」标签只会得到错误结论。这里用代码**确实能判定**的
// 等价维度——本机网卡上有没有公网地址:
//
//	public  — 有公网地址(裸机/云主机)⇒ 直连可达性预期高
//	nat     — 只有私网/CGNAT 地址 ⇒ 处于 NAT 之后(家庭/企业网关/运营商 CGNAT)
//	unknown — 判定不了(接口枚举失败,或只有回环与链路本地地址)
//
// 负对照:把 CGNAT 判成公网(或把私网判成公网)⇒ 直连率分桶失真。
func classifyNetClass(addrs []netip.Addr) string {
	var hasPublic, hasPrivate bool
	for _, a := range addrs {
		a = a.Unmap()
		if a.IsUnspecified() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() {
			continue
		}
		if a.IsPrivate() || cgnatPrefix.Contains(a) {
			hasPrivate = true
			continue
		}
		if a.IsGlobalUnicast() {
			hasPublic = true
		}
	}
	switch {
	case hasPublic:
		return netPublic
	case hasPrivate:
		return netNAT
	default:
		return netUnknown
	}
}

// localNetClass 枚举本机网卡地址并分桶(枚举失败即 unknown)。
//
// 只取**地址类别**,不取地址本身——地址不进标签、不进日志、不进上报载荷。
func localNetClass() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return netUnknown
	}
	var addrs []netip.Addr
	for _, ifi := range ifaces {
		list, err := ifi.Addrs()
		if err != nil {
			continue // 单网卡枚举失败不影响其余网卡
		}
		for _, a := range list {
			if ip, err := netip.ParsePrefix(a.String()); err == nil {
				addrs = append(addrs, ip.Addr())
			}
		}
	}
	return classifyNetClass(addrs)
}

// sessionReporter 会话遥测上报器:一次会话一具,持有注册中心基址、网络环境
// 分桶与会话起点(回退触发耗时的计时基准)。
type sessionReporter struct {
	regBase string
	net     string
	started time.Time
}

// newSessionReporter 构造上报器(网络分桶在此刻定格,一次会话内不变)。
func newSessionReporter(regBase string) *sessionReporter {
	return &sessionReporter{regBase: regBase, net: localNetClass(), started: time.Now()}
}

// reportSession 上报一条会话遥测(p2p#51 直连率：补齐分桶与耗时)。
//
// best-effort 三重兜底:异步(GoSafe 收编 panic)+短超时(3s)+失败仅 Debug
// ——遥测绝不拖慢或打断传输。rep 为 nil 或 regBase 为空(单测/未知基址)
// 时直接跳过。
//
// kind/path/reason 必须是 registry 白名单枚举(服务端再校验一次);net 是
// 网络环境分桶(public|nat|unknown);dur>0 时附耗时毫秒数(回退触发耗时/
// 直连升级耗时)。载荷里**只有枚举与耗时数字**——无地址、无错误原文。
func (c *Client) reportSession(rep *sessionReporter, kind, path, reason string, dur time.Duration) {
	if rep == nil || rep.regBase == "" {
		return
	}
	durMS := int64(0)
	if dur > 0 {
		durMS = dur.Milliseconds()
	}
	netClass := rep.net
	async.GoSafeLabeled("p2p-telemetry", func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := newRegistryAPI(rep.regBase).telemetry(ctx, c.id, kind, path, reason, netClass, durMS); err != nil {
			c.log.Debug("遥测上报失败", "err", err)
		}
	})
}

// upgradeCtx 直连升级遥测上下文(中继就绪时刻 = 升级耗时计时起点)。
type upgradeCtx struct {
	rep   *sessionReporter
	since time.Time
}

// reportUpgrade 上报直连升级结果(p2p#51:升级成功/超时/失败 + 耗时)。
//
// 负对照:漏报或把 result 写死成一种取值 ⇒ 升级成功率与升级耗时两个口径
// 都会失真(指标恒为一条序列)。
func (c *Client) reportUpgrade(up *upgradeCtx, result string) {
	if up == nil {
		return
	}
	c.reportSession(up.rep, registry.TelemetryDirectUpgrade, "", result, time.Since(up.since))
}
