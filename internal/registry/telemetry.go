package registry

import (
	"fmt"
	"strings"
	"time"
)

// 遥测契约(p2p#51 直连率：补齐分桶与回退可观测):客户端在打洞/会话
// 建立的**结果路径**上报到 p2pd /v1/telemetry/session,由 p2pd 落 Prometheus
// (p2p_session_* / p2p_relay_fallback_* / p2p_direct_upgrade_* 指标)。
//
// 脱敏铁律:载荷与指标 label **只记枚举**,不记对端地址/错误原文——枚举集合
// 由本文件白名单钉死,服务端拒绝集合外取值(否则任意字符串进 label =
// 基数爆炸 + 地址泄露)。签名负载格式(sign.go 注释同步):
//
//	遥测 v2: node_id | kind | path | reason | net | dur_ms | ts
//	遥测 v1: node_id | kind | path | reason | ts   (旧客户端,服务端兼容校验)
//
// v1 只在**服务端验签回落**时使用(旧客户端上报),新客户端一律签 v2。

// 遥测事件类型。
const (
	TelemetryEstablished   = "established"    // 会话建立成功,path 必填
	TelemetryFailed        = "failed"         // 会话建立失败,reason 必填
	TelemetryRelayFallback = "relay_fallback" // 回退中继触发,reason 必填
	// TelemetryDirectUpgrade 直连升级结果(p2p#51):中继兜底后后台打洞
	// 升级为直连的结果,reason 必填。
	TelemetryDirectUpgrade = "direct_upgrade"
)

// 网络环境分桶(p2p#51):直连成功率按网络环境分桶。
//
// 取值恒为三选一 ⇒ 标签基数天然封顶。**不含任何地址**(IP/前缀一律不进
// 标签);判定依据见 internal/client 的 classifyNetClass。
const (
	NetPublic  = "public"  // 本机持有公网地址(裸机/云主机)
	NetNAT     = "nat"     // 本机只有私网/CGNAT 地址 ⇒ 处于 NAT 之后
	NetUnknown = "unknown" // 判定不了(缺省:旧客户端不上报该维度)
)

// 直连升级结果枚举(p2p#51)。
const (
	UpgradeUpgraded = "upgraded"        // 升级成功(直连就绪,文件边界换源)
	UpgradeTimeout  = "upgrade_timeout" // 升级超时(全程中继)
	UpgradeFailed   = "upgrade_failed"  // 升级失败(打洞/拨号/信令出错)
)

// TelemetryOtherLabel 集合外取值的归一落点(基数封顶的兜底桶)。
const TelemetryOtherLabel = "other"

// MaxTelemetryDurationMS 遥测耗时字段的上限(毫秒)。超出即钳到上限——
// 耗时是客户端侧计时值,异常大值不该进指标桶(也不该让整条上报被拒)。
const MaxTelemetryDurationMS = 3600_000 // 1h

// 遥测枚举白名单(服务端校验的唯一真相源;新增枚举先改这里)。
var telemetryKinds = map[string][]string{
	TelemetryEstablished:   nil, // path 单独白名单(telemetryPaths)
	TelemetryFailed:        {"punch_failed", "quic_failed", "relay_failed"},
	TelemetryRelayFallback: {"punch_failed", "direct_failed"},
	TelemetryDirectUpgrade: {UpgradeUpgraded, UpgradeTimeout, UpgradeFailed},
}

// telemetryPaths established 的 path 白名单:
//
//	punch    快打洞直连成功(快路径)
//	relay    中继承载成功(打洞失败/直连失败后的回退)
//	fallback 中继不可用时长打洞兜底直连成功(第二级回退)
var telemetryPaths = []string{"punch", "relay", "fallback"}

// TelemetryInput 遥测上报请求体。
type TelemetryInput struct {
	NodeID string `json:"node_id"`
	Kind   string `json:"kind"`
	Path   string `json:"path,omitempty"`
	Reason string `json:"reason,omitempty"`
	// Net 网络环境分桶(public|nat|unknown);旧客户端不上报 ⇒ 空。
	Net string `json:"net,omitempty"`
	// DurMS 耗时(毫秒):回退触发耗时/直连升级耗时;不适用时为 0。
	DurMS int64  `json:"dur_ms,omitempty"`
	TS    int64  `json:"ts"`
	Sig   string `json:"sig"`
}

// BuildTelemetryPayload 构造遥测签名字节(v2;客户端与服务端必须同源调用)。
func BuildTelemetryPayload(nodeID, kind, path, reason, net string, durMS int64, ts int64) []byte {
	return BuildPayload(nodeID, kind, path, reason, net, fmt.Sprint(durMS), fmt.Sprint(ts))
}

// BuildLegacyTelemetryPayload 构造旧版遥测签名字节(v1)。
//
// 仅供**服务端兼容校验**旧客户端上报使用(新客户端一律签 v2)。
func BuildLegacyTelemetryPayload(nodeID, kind, path, reason string, ts int64) []byte {
	return BuildPayload(nodeID, kind, path, reason, fmt.Sprint(ts))
}

// Validate 校验 kind/path/reason 落在白名单内(脱敏与 label 基数的守门)。
func (in TelemetryInput) Validate() error {
	reasons, ok := telemetryKinds[in.Kind]
	if !ok {
		return fmt.Errorf("%w: kind 须为 established|failed|relay_fallback|direct_upgrade", ErrInvalidRequest)
	}
	if in.Kind == TelemetryEstablished {
		for _, p := range telemetryPaths {
			if in.Path == p {
				return nil
			}
		}
		return fmt.Errorf("%w: path 须为 punch|relay|fallback", ErrInvalidRequest)
	}
	for _, r := range reasons {
		if in.Reason == r {
			return nil
		}
	}
	return fmt.Errorf("%w: reason 不在白名单(仅收枚举,不收自由文本)", ErrInvalidRequest)
}

// TelemetrySign 校验遥测签名与时间窗(±MaxClockSkew)。
//
// v2 验签失败时**仅当** net 与 dur_ms 皆缺省才回落 v1 校验——旧客户端
// (2026-11-15 那批)上报不带这两个维度,服务端须继续收;带维度的事件不许
// 用旧负载签名(否则同一事件存在两套可接受签名,重放面翻倍)。
func (in TelemetryInput) TelemetrySign(now time.Time) error {
	pub, err := ParseNodeID(in.NodeID)
	if err != nil {
		return fmt.Errorf("%w: node_id 非法", ErrInvalidRequest)
	}
	if err := VerifySignature(pub, BuildTelemetryPayload(in.NodeID, in.Kind, in.Path, in.Reason, in.Net, in.DurMS, in.TS), in.Sig); err != nil {
		if in.Net != "" || in.DurMS != 0 {
			return err
		}
		if err2 := VerifySignature(pub, BuildLegacyTelemetryPayload(in.NodeID, in.Kind, in.Path, in.Reason, in.TS), in.Sig); err2 != nil {
			return err
		}
	}
	return CheckTimestamp(in.TS, now)
}

// NormalizeTelemetryKind 小写归一(客户端枚举恒小写,防御性收口)。
func NormalizeTelemetryKind(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// NormalizeTelemetryNet 网络环境分桶归一:集合外(含空)一律折进 unknown。
//
// **不拒绝、只折叠**:net 是客户端派生的分桶(不是自由文本注入面),集合外
// 取值折进 unknown 即可——label 值恒为三选一 ⇒ 基数封顶;且不因新分桶
// 取值把整条事件(路径/原因/耗时)一起丢掉。
func NormalizeTelemetryNet(s string) string {
	switch s {
	case NetPublic:
		return NetPublic
	case NetNAT:
		return NetNAT
	default:
		return NetUnknown
	}
}

// NormalizeTelemetryPath 路径归一:白名单内原样,集合外折进 other(基数封顶)。
func NormalizeTelemetryPath(p string) string {
	for _, v := range telemetryPaths {
		if p == v {
			return v
		}
	}
	return TelemetryOtherLabel
}

// NormalizeTelemetryReason 原因归一:按 kind 取白名单,集合外(或 kind 未知)
// 折进 other(基数封顶)。
func NormalizeTelemetryReason(kind, reason string) string {
	reasons, ok := telemetryKinds[kind]
	if !ok {
		return TelemetryOtherLabel
	}
	for _, r := range reasons {
		if reason == r {
			return r
		}
	}
	return TelemetryOtherLabel
}

// ClampTelemetryDurationMS 耗时钳制:负值归零、超上限钳到上限。
func ClampTelemetryDurationMS(ms int64) int64 {
	if ms < 0 {
		return 0
	}
	if ms > MaxTelemetryDurationMS {
		return MaxTelemetryDurationMS
	}
	return ms
}
