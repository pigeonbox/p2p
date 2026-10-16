# PigeonBeam（信鸽直传）产品定位与拆分路线

> 2026-10-16 拍板：**设备直传拆独立应用，联邦与注册中心留守 PigeonBox。**
> 本档是该决定的真相源：定位、边界、三阶段路线与品牌约定。

## 定位

**PigeonBeam（信鸽直传）** 是设备直传独立应用：`p2pc`（CLI）+ `p2pc-web`（网页模式）。任意两台设备端到端直传——口令即身份（PAKE）、无需账号、无需同网段、打洞优先中继兜底。

**p2pd** 是注册中心/加密中继基础设施，一份底座服务两个产品面：

- PigeonBeam 的公共 rendezvous（官方公共节点已运营）；
- PigeonBox 联邦（跨站口令路由/在线名录/邀请信箱）——联邦是「快递柜」模型的自然延伸，接收方仍是浏览器用户，**留守 PigeonBox 产品内禀能力**。

拆分依据：直传的用户是站长自己的设备（两端都要装），交互模型是「双方在线·配对·会话式」，与快递柜的「异步投递·口令取件」相反——接收方永远不会装 p2pc。两个产品面共享 p2pd 与 wire 协议栈，但业务上互不依赖。

## 与 PigeonBox 的关系

| | PigeonBeam（本仓直传面） | PigeonBox（文件快递柜） |
|---|---|---|
| 用户 | 站长自己的设备（两端安装） | 匿名接收方（只有浏览器） |
| 模型 | 双方在线·配对·会话式 | 异步投递·口令取件 |
| 集成 | 可选：装了才有，缺省优雅降级 | 主产品 |

现状集成点（Phase 2 前全部保留）：core `p2px` supervisor（管理台直发/收件入柜）、server 镜像 `.p2pc-version` 随包、fnos/qnap/openwrt `P2PC_REF` 随包、desktop sidecar（bundle.externalBin）、MCP 七直传工具、`pb` CLI p2p 九子命令。

## 直传维护模式（冻结新特性）

自本档起，`p2pc` / `p2pc-web` 功能面进入维护模式：**只修 bug、安全与兼容性，不做新特性**。新投入只允许流向：

1. 协议兼容窗口（Phase 2 ①）；
2. 平台打包健康度与发版链路；
3. 文档与产品包装。

联邦（名录/信箱/口令联邦路由）**不在冻结范围内**，继续随 PigeonBox 产品迭代。

## 三阶段拆分路线

**Phase 1（本档，零破坏，已完成 2026-10-16）**
独立品牌 PigeonBeam + README 重构定位 + 本档。二进制名（p2pc / p2pc-web / p2pd）、wire 协议、Releases 出口、随包钉版全部不变——主产品一行代码未动。

**Phase 2（① 已落地 v0.7.1；② 随下一列车实施，禁止绕列车手改钉版）**

① wire N-1 兼容窗口（✅ v0.7.1，协商层）：版本帧从「等值匹配」升级为区间协商 `{proto:最高支持, floor:最低支持}`，一致规则 `agreed=min(双方 proto)` 且不得低于双方 floor，**高版本端负责降级到 agreed 对话**。v4 的 floor 恒等于 proto，线上帧逐字节不变（形态锁单测把守）。约束随之生效：**wire 破坏性变更（v5 起）必须带 N-1 双格式实现**（旧格式路径+按 agreed 选格式），否则不得升 proto。存量 fleet（NAS/desktop 钉版不升级）由此获得未来过渡期互操作。

② 打包钉版与列车脱钩（待列车编排实施）。五处钉版点位与目标动作：

| 点位 | 现状 | 目标 |
|---|---|---|
| server `.p2pc-version` / Dockerfile `ARG P2PC_VERSION` | 每列车随 bump 矩阵自动动 | 冻结在 v0.7.0；仅 p2p 出安全/相关 bug 修复时手动 bump |
| fnos `DEPS.env P2PC_REF`（+sha256 校验） | 同上 | 同上 |
| qnap `P2PC_REF` | 同上 | 同上 |
| openwrt `P2PC_REF` | 同上 | 同上 |
| desktop sidecar（CI 按 triple 拉 + bundle.externalBin） | 随列车同升 | 同上 |

实施要点：列车编排器（hub `release/train.yaml` + trainctl）把上述点位从自动 bump 矩阵移出，保留手动 bump 通道；sha256 校验、缺省优雅降级机制一律不动；`make train-verify` 对钉版一致性的断言保留（防幽灵版本的守卫仍需钉版点自洽）。收益：直传维护模式下 p2p 不再绑架列车节奏；过渡期互操作由 ① 保障。

**Phase 3（2.0.0 窗口，与单码制同车拍板）**
若独立应用立住，主产品编排层收缩为可选集成：admin 直传控制台改为「检测到 p2pc 才显示」（或移除），MCP 直传工具与 `pb` p2p 子命令同步收缩。**联邦与 p2pd 不动。**

## 品牌约定

- 品牌名 **PigeonBeam**，中文 **信鸽直传**（2026-10-16 选定）。`PigeonDrop` 已否决——pigeon drop 是知名诈骗手法名称（警方公告通用术语），检索污染严重。
- **二进制名与协议名不改**：`p2pc` / `p2pc-web` / `p2pd` / wire v4 维持原名，打包钉版（`P2PC_REF` / `.p2pc-version` / triple 资产名）与既有文档不破坏。
- UI 呈现：p2pc-web 标题「PigeonBeam 信鸽直传」，副署 PigeonBox 生态；仓库名 `pigeonbox/p2p` 暂不改（Phase 3 后再评估）。
