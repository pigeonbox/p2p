// Package directpolicy 直传客户端策略(p2p#51:中继回退的触发条件与延迟)。
//
// 决策方在**客户端**(p2pc):回退与否由客户端的打洞结果决定,p2pd 不参与
// ⇒ 这些旋钮**不进 p2pd 的配置文件键集**(避免 p2pd#38 同款「死配置」:
// 登记了键却没人读)。注入方式是环境变量(PB_P2P_DIRECT_*)。
//
// ⚠️ 缺省值逐字等于 2026-11-15 前的硬编码行为 ⇒ **不配置时行为与今天
// 完全一致**(回退决策链见 internal/client/client.go 的 establish)。
//
// ⚠️ 本包**刻意不依赖 viper**:internal/config 带 viper,而 p2pc 只需要本包
// ⇒ 策略若留在 config,viper 会被链进 p2pc 二进制(+~900KB;NAS 三端随包
// 发的 p2pc 也一起胖)。本包只用标准库读 env,**取值口径与原 viper 实现
// 逐字对等**(policy_test.go 里有 viper 参考实现做逐项对账)。
package directpolicy

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// Policy 直传策略。
type Policy struct {
	// FastPunchBudget 快打洞预算:直连尝试多久后回退中继(=回退触发延迟)。
	// 缺省 1.5s(与旧硬编码一致)。env: PB_P2P_DIRECT_FAST_PUNCH_BUDGET
	FastPunchBudget time.Duration
	// PunchBudget 长打洞兜底预算:回退路径里「没有中继可用」时的直连尝试
	// 时长。缺省 4s(与 client.Options.PunchBudget 的缺省一致)。
	// env: PB_P2P_DIRECT_PUNCH_BUDGET
	PunchBudget time.Duration
	// RelayProbeTimeout 中继可达性探测超时:探测窗口多长算中继不可用。
	// 缺省 2s(与旧硬编码一致)。env: PB_P2P_DIRECT_RELAY_PROBE_TIMEOUT
	RelayProbeTimeout time.Duration
	// RelayFallbackEnabled 是否允许回退中继(false=只长打洞兜底,等同
	// client.Options.NoRelay 的语义)。缺省 true(中继是打洞失败的必要兜底)。
	// env: PB_P2P_DIRECT_RELAY_FALLBACK_ENABLED
	RelayFallbackEnabled bool
}

// 直传策略缺省值(逐字等于 2026-11-15 前的硬编码行为;改动即改行为,须同步
// internal/client 的回退决策链与本包的断言)。
const (
	DefaultFastPunchBudget     = 1500 * time.Millisecond
	DefaultPunchBudget         = 4 * time.Second
	DefaultRelayProbeTimeout   = 2 * time.Second
	DefaultRelayFallbackEnable = true
)

// 环境变量键(与 viper 的 PB_P2P 前缀 + "."→"_" 替换口径逐字一致)。
const (
	EnvFastPunchBudget     = "PB_P2P_DIRECT_FAST_PUNCH_BUDGET"
	EnvPunchBudget         = "PB_P2P_DIRECT_PUNCH_BUDGET"
	EnvRelayProbeTimeout   = "PB_P2P_DIRECT_RELAY_PROBE_TIMEOUT"
	EnvRelayFallbackEnable = "PB_P2P_DIRECT_RELAY_FALLBACK_ENABLED"
)

// 配置键(点号形态,与原 viper 实现的键名逐字一致 ⇒ 告警文案不变)。
const (
	KeyFastPunchBudget     = "direct.fast_punch_budget"
	KeyPunchBudget         = "direct.punch_budget"
	KeyRelayProbeTimeout   = "direct.relay_probe_timeout"
	KeyRelayFallbackEnable = "direct.relay_fallback_enabled"
)

// Load 读取直传策略:环境变量优先,缺省=内置缺省。
//
// 返回的告警串由调用方打日志(客户端侧)。非法取值**钳回缺省**而非报错:
// p2pc 是无状态 CLI,策略拼错不该让它起不来(p2pd 侧的配置错误是
// refuse-to-start,这里是 best-effort + 告警)。
//
// 取值口径(逐项对账见 policy_test.go 的 viper 参考实现):
//   - 未设置/空串 ⇒ 缺省(空串按未设置处理,与 viper allowEmptyEnv=false 同);
//   - 时长串 ⇒ 与 cast.ToDuration 同口径:串内不含 "nsuµmh" 时按**纳秒**
//     解析(viper 的 GetDuration 走 cast ⇒ "5" = 5ns),否则 time.ParseDuration;
//   - 布尔串 ⇒ 白名单("1/t/true/yes/y/on" 与 "0/f/false/no/n/off"),
//     其余折回缺省并告警(不走 cast.ToBool:它把无法识别的串一律给 false
//     ⇒ 一次手误("flase")就会**静默关掉中继回退**)。
func Load() (Policy, []string) {
	p := Policy{
		FastPunchBudget:      DefaultFastPunchBudget,
		PunchBudget:          DefaultPunchBudget,
		RelayProbeTimeout:    DefaultRelayProbeTimeout,
		RelayFallbackEnabled: DefaultRelayFallbackEnable,
	}
	var warns []string
	// 三个时长先解析:解析失败**记 0 且不在此处告警**,交由 Normalize 统一钳回
	// 缺省 ⇒ 告警文案与出现顺序都逐字等于原 viper 实现(布尔告警在前、
	// 时长钳制告警在后)。
	p.FastPunchBudget = durationFromEnv(EnvFastPunchBudget, DefaultFastPunchBudget)
	p.PunchBudget = durationFromEnv(EnvPunchBudget, DefaultPunchBudget)
	p.RelayProbeTimeout = durationFromEnv(EnvRelayProbeTimeout, DefaultRelayProbeTimeout)
	// 布尔项:白名单外 ⇒ 告警 + 缺省(原实现同位置同文案)。
	p.RelayFallbackEnabled, warns = boolFromEnv(EnvRelayFallbackEnable, KeyRelayFallbackEnable, DefaultRelayFallbackEnable, warns)
	p, normWarns := Normalize(p)
	return p, append(warns, normWarns...)
}

// Normalize 钳制策略取值:非法值回退缺省,返回告警串。
//
// 客户端显式指定策略时也走这里(显式值同样要过钳制——零值/负值会让打洞
// 预算变成 0 ⇒ 快打洞立刻判负 ⇒ 行为比不配置更糟)。
func Normalize(p Policy) (Policy, []string) {
	var warns []string
	if p.FastPunchBudget <= 0 {
		warns = append(warns, KeyFastPunchBudget+" 取值非法,已回退缺省 "+DefaultFastPunchBudget.String())
		p.FastPunchBudget = DefaultFastPunchBudget
	}
	if p.PunchBudget <= 0 {
		warns = append(warns, KeyPunchBudget+" 取值非法,已回退缺省 "+DefaultPunchBudget.String())
		p.PunchBudget = DefaultPunchBudget
	}
	if p.RelayProbeTimeout <= 0 {
		warns = append(warns, KeyRelayProbeTimeout+" 取值非法,已回退缺省 "+DefaultRelayProbeTimeout.String())
		p.RelayProbeTimeout = DefaultRelayProbeTimeout
	}
	return p, warns
}

// durationFromEnv 读时长型环境变量:未设置/空串 ⇒ 缺省;解析失败 ⇒ 记 0
// (由 Normalize 统一钳回缺省并告警,告警文案/顺序与原实现逐字一致)。
//
// 解析口径与 cast.ToDuration 逐字一致(不含单位字母时补 "ns"),故「5」这种
// 无单位串在两套实现里都是 5ns(不是 5s)——口径变了才是行为漂移。
func durationFromEnv(envKey string, def time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(envKey))
	if raw == "" {
		return def
	}
	d, err := parseDurationLikeCast(raw)
	if err != nil {
		// 返回 0(而非缺省)以复刻原实现的告警路径:原实现里 viper 的
		// GetDuration 解析失败静默给 0,是 Normalize 统一把它钳回缺省并告警。
		return 0
	}
	return d
}

// boolFromEnv 读布尔型环境变量:未设置/空串 ⇒ 缺省;白名单外 ⇒ 告警 + 缺省。
func boolFromEnv(envKey, cfgKey string, def bool, warns []string) (bool, []string) {
	raw := strings.ToLower(strings.TrimSpace(os.Getenv(envKey)))
	if raw == "" {
		return def, warns
	}
	switch raw {
	case "1", "t", "true", "yes", "y", "on":
		return true, warns
	case "0", "f", "false", "no", "n", "off":
		return false, warns
	default:
		warns = append(warns, cfgKey+" 取值非法,已回退缺省 "+strconv.FormatBool(def))
		return def, warns
	}
}

// parseDurationLikeCast 与 github.com/spf13/cast.ToDurationE 的字符串分支同口径:
//
//	case string:
//	    if !strings.ContainsAny(s, "nsuµmh") { return time.ParseDuration(s + "ns") }
//	    return time.ParseDuration(s)
//
// (viper 的 GetDuration → cast.ToDuration ⇒ 原实现走的就是这条规则。)
func parseDurationLikeCast(s string) (time.Duration, error) {
	if !strings.ContainsAny(s, "nsuµmh") {
		return time.ParseDuration(s + "ns")
	}
	return time.ParseDuration(s)
}
