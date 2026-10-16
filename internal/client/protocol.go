// 传输协议版本协商(v3 起):配对完成后、PAKE 之前,双方经信令信道显式
// 交换协议版本。此前"破坏性变更须客户端同版"只靠行为约定,版本不一致
// 表现为 AEAD 帧解密失败的密码学报错(wire.ErrCorrupt),用户无从判断;
// 显式协商后给出可读错误。版本帧走信令信道的明文 data——它只服务可诊断性,
// 不承担认证职责(认证仍由 PAKE+传输层首帧 AEAD 把守,信令侧另有节点签名
// 准入),篡改它的最坏结果是传输失败,不构成降权。
//
// 区间协商(v0.7.0 起,PigeonBeam 拆分 Phase 2①):帧从"等值匹配"升级为
// {proto:最高支持, floor:最低支持},一致规则 agreed=min(双方 proto) 且
// 不得低于双方 floor——高版本端负责降级到 agreed 对话(wire 破坏性变更
// 从此必须带 N-1 双格式实现,见 docs/PRODUCT.md)。floor 缺省=对端 proto
// (旧客户端只说得出自己那版)。v4 的 floor 恒等于 proto,omitempty 后
// 线上帧与 v0.6.x 逐字节一致——本改动对存量 fleet 零 wire 变化,只为未来
// v5+ 的降级互操作预埋判定规则:本端收到更高 proto 不再硬拒,交由更新
// 的对端降级。
package client

import (
	"encoding/json"
	"fmt"
)

// protoVersion 当前直传传输协议版本(同时是本端 floor:仅会讲这一种格式)。
//
//	v2 (2026-10-05): 方向标签 nonce 分离+HKDF 派生(破坏性,双端同版)
//	v3 (2026-10-09): +显式版本协商;QUIC 直传多流并行分段(relay 路径帧格式不变)
//	v4 (2026-10-09): 多文件 manifest 流(逐文件授权/zstd 压缩/单遍哈希/
//	                  文件边界换源升级);帧上限 1MB(压缩批量)
const protoVersion = 4

// protoFloor 本端可降级到的最低格式版本。v4 仅一种格式,恒等于 protoVersion;
// 未来按 Phase 2① 约定引入 N-1 双格式实现时改此常量并落地旧格式路径,
// 协商帧自那时起才会出现 floor 字段。
const protoFloor = protoVersion

// versionFrame 协商帧。floor=可降级到的最低格式版本;由构造省略
// (floor==proto 不写字段),帧形态与 v0.6.x 逐字节一致。接收侧 floor
// 缺省按对端 proto 解释(旧客户端只说得出自己那版)。
type versionFrame struct {
	Proto int `json:"proto"`
	Floor int `json:"floor,omitempty"`
}

// versionExchanger 协商所需的最小信道面(*channel 天然满足;测试用内存假身)。
type versionExchanger interface {
	send(payload []byte) error
	recv() ([]byte, error)
}

// negotiateVersion 双方互换协议版本帧,返回一致后的传输版本。两侧先发后收:
// 信令信道双向独立排队,不会互等死锁;帧序 FIFO 保证先收到对方的版本帧
// 再进入 PAKE。
func negotiateVersion(ch versionExchanger) (int, error) {
	vf := versionFrame{Proto: protoVersion}
	if protoFloor != protoVersion {
		vf.Floor = protoFloor
	}
	payload, err := json.Marshal(vf)
	if err != nil {
		return 0, err
	}
	if err := ch.send(payload); err != nil {
		return 0, fmt.Errorf("协议版本发送: %w", err)
	}
	raw, err := ch.recv()
	if err != nil {
		return 0, fmt.Errorf("协议版本接收: %w", err)
	}
	var peer versionFrame
	if err := json.Unmarshal(raw, &peer); err != nil || peer.Proto == 0 {
		return 0, fmt.Errorf("对端不支持协议协商(传输协议 v2 及以下),请升级过旧一端: github.com/pigeonbox/p2p/releases")
	}
	peerFloor := peer.Floor
	if peerFloor == 0 || peerFloor > peer.Proto {
		peerFloor = peer.Proto // 旧客户端无 floor;声明越界按不可降级处理
	}
	agreed := peer.Proto
	if protoVersion < agreed {
		agreed = protoVersion
	}
	if agreed < protoVersion || agreed < peerFloor {
		return 0, fmt.Errorf("传输协议版本不兼容: 本端 v%d(不可降级),对端 v%d(可低至 v%d)——请升级过旧一端: github.com/pigeonbox/p2p/releases",
			protoVersion, peer.Proto, peerFloor)
	}
	return agreed, nil
}
