// Package interop 承载 wire 互操作测试矩阵（pigeonbox/p2p#50）的端到端验收用例。
//
// 矩阵口径（issue #50）：当前版↔当前版 / 当前版↔上一兼容版 / 当前版↔不兼容旧版 /
// 中继↔直连切换 / 断网恢复。本包只放跨版本与链路形态的端到端用例；单机单测
// （fakeExch 注入的协商语义）仍归 internal/client/protocol_test.go，不在此重复。
package interop
