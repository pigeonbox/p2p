package registry

import (
	"fmt"
	"strings"
	"time"
)

// 遥测契约(p2p#51 直连率):客户端在打洞/会话建立的**结果路径**上报到
// p2pd /v1/telemetry/session,由 p2pd 落 Prometheus(p2p_session_* 指标)。
//
// 脱敏铁律:载荷与指标 label **只记枚举**,不记对端地址/错误原文——枚举集合
// 由本文件白名单钉死,服务端拒绝集合外取值(否则任意字符串进 label =
// 基数爆炸 + 地址泄露)。签名负载格式(sign.go 注释同步):
//
//	遥测: node_id | kind | path | reason | ts

// 遥测事件类型。
const (
	TelemetryEstablished   = "established"    // 会话建立成功,path 必填
	TelemetryFailed        = "failed"         // 会话建立失败,reason 必填
	TelemetryRelayFallback = "relay_fallback" // 回退中继触发,reason 必填
)

// 遥测枚举白名单(服务端校验的唯一真相源;新增枚举先改这里)。
var telemetryKinds = map[string][]string{
	TelemetryEstablished:   nil, // path 单独白名单(telemetryPaths)
	TelemetryFailed:        {"punch_failed", "quic_failed", "relay_failed"},
	TelemetryRelayFallback: {"punch_failed", "direct_failed"},
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
	TS     int64  `json:"ts"`
	Sig    string `json:"sig"`
}

// BuildTelemetryPayload 构造遥测签名字节(客户端与服务端必须同源调用)。
func BuildTelemetryPayload(nodeID, kind, path, reason string, ts int64) []byte {
	return BuildPayload(nodeID, kind, path, reason, fmt.Sprint(ts))
}

// Validate 校验 kind/path/reason 落在白名单内(脱敏与 label 基数的守门)。
func (in TelemetryInput) Validate() error {
	reasons, ok := telemetryKinds[in.Kind]
	if !ok {
		return fmt.Errorf("%w: kind 须为 established|failed|relay_fallback", ErrInvalidRequest)
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
func (in TelemetryInput) TelemetrySign(now time.Time) error {
	pub, err := ParseNodeID(in.NodeID)
	if err != nil {
		return fmt.Errorf("%w: node_id 非法", ErrInvalidRequest)
	}
	if err := VerifySignature(pub, BuildTelemetryPayload(in.NodeID, in.Kind, in.Path, in.Reason, in.TS), in.Sig); err != nil {
		return err
	}
	return CheckTimestamp(in.TS, now)
}

// NormalizeTelemetryKind 小写归一(客户端枚举恒小写,防御性收口)。
func NormalizeTelemetryKind(s string) string { return strings.ToLower(strings.TrimSpace(s)) }
