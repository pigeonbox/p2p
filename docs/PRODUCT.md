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

**豁免 = 「投递到柜」桥**（Wave A1，hub `docs/specs/2026-10-16-two-app-split-design.md`）：p2pcweb 经 Box 公开 API（`/share/file/` + X-API-Key）把收到的文件转存为文件柜分享换取取件码。它服务的是拆分终态（两应用集成的唯一通道），不属于独立直传特性面——Box 侧零改动是验收硬条件。

**豁免二 = 「配对码」易用性收口**（2026-10-18 拍板，hub `docs/specs/2026-10-18-p2p-pairing-code-design.md`）：四位定时配对码替代 12 位口令的人手转抄，属既有口令配对流程的易用性替换面（协议零 wire 改动，新面收敛在注册中心 HTTP 端点），不是新特性方向。

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

**Phase 3（v3.0.0 主波；细案见 hub `docs/specs/2026-10-16-two-app-split-design.md`，决策点 D1-D4 待拍板）**
两应用终态分拆（原 2.0.0 窗口已随 v2.0.1 发运，破坏性拆除顺延至下一主版本）：Box 侧整体拆除直传编排层——p2px supervisor / admin 8 直传端点 / MCP 4 工具 / CLI 5 子命令 / P2pTransfer 直传控制台 / SystemConfig `direct` 段 / 随包钉版 / desktop sidecar；联邦面与 p2pd 原样留守。**桥方向翻转**：不再是 Box 内嵌编排 p2pc，而是 Beam 作 Box 的 API 客户端——p2pcweb「投递到柜」（收件经 Box 公开 API 建分享拿取件码），Box 零 Beam 代码。Wave A 非破坏项（投递到柜 / NAS 内嵌 Beam 客户端 / desktop sidecar 冻结 / docs）随 2.0.x 列车先行。

## 品牌约定

- 品牌名 **PigeonBeam**，中文 **信鸽直传**（2026-10-16 选定）。`PigeonDrop` 已否决——pigeon drop 是知名诈骗手法名称（警方公告通用术语），检索污染严重。
- **二进制名与协议名不改**：`p2pc` / `p2pc-web` / `p2pd` / wire v4 维持原名，打包钉版（`P2PC_REF` / `.p2pc-version` / triple 资产名）与既有文档不破坏。
- UI 呈现：p2pc-web 标题「PigeonBeam 信鸽直传」，副署 PigeonBox 生态；仓库名 `pigeonbox/p2p` 暂不改（Phase 3 后再评估）。

## 直传维护模式的本次豁免范围（p2p#51）

> 2026-11-18 拍板：把 p2p#51 的「可观测面最小豁免」（2026-11-15，commit 647e7f9 / PR #57）补成完整形态。
> 豁免**仅限**两件事：① 直连成功率遥测的**分桶统计**；② 中继回退的**可配置/可观测**。
> 本节是本次豁免的范围声明（既有拍板段落不改）。

**豁免一 = 直连成功率按网络环境分桶**

- 分桶维度 `net` ∈ {`public`, `nat`, `unknown`}：判定依据是**本机网卡上有没有公网地址**（`public` = 裸机/云主机；`nat` = 私网或 CGNAT，即处于 NAT 之后；`unknown` = 判定不了）。
- **不按 NAT 行为类型（对称/端口受限/锥形）分桶**：那需要 RFC 5780 行为探测（同一 socket 换源端口再探、看映射端口是否变化），本仓没有这类探测 ⇒ 臆造「对称 NAT」标签只会得到错误结论。宁可少一维，不造假维度。
- 脱敏与基数封顶：桶标签**只记枚举**（不含任何 IP/前缀/设备指纹/用户标识）；集合外取值一律折进 `unknown`，指标层再兜底折进 `other` ⇒ 灌入任意多不同维度都不增序列。

**豁免二 = 中继回退可配置 + 可观测**

- 可配置（触发条件与延迟，环境变量注入，**不新增 CLI 旗标**）：`PB_P2P_DIRECT_FAST_PUNCH_BUDGET`（快打洞预算 = 回退触发延迟，缺省 1.5s）、`PB_P2P_DIRECT_PUNCH_BUDGET`（长打洞兜底预算，缺省 4s）、`PB_P2P_DIRECT_RELAY_PROBE_TIMEOUT`（中继可达性探测窗口，缺省 2s）、`PB_P2P_DIRECT_RELAY_FALLBACK_ENABLED`（是否允许回退中继，缺省 true）。
- 可观测（此前回退是黑盒）：是否回退、回退原因分类（`punch_failed` / `direct_failed`）、回退触发耗时（直连尝试开始→回退决策）、直连升级耗时与结果（`upgraded` / `upgrade_timeout` / `upgrade_failed`，中继就绪→升级就绪/超时）。
- 指标：`p2p_session_established_by_net_total{path,net}`、`p2p_session_failed_by_net_total{reason,net}`、`p2p_relay_fallback_by_net_total{reason,net}`、`p2p_relay_fallback_duration_seconds{reason,net}`、`p2p_direct_upgrade_total{result,net}`、`p2p_direct_upgrade_duration_seconds{result,net}`（既有三个 `p2p_session_*`/`p2p_relay_fallback_total` 指标不动，避免打断既有看板）。

**本次豁免**不包含（明文边界）

- **不做 DHT**（p2p#51 原方向③，与本文件定位一致，仍然冻结）。
- **不改 wire 协议字节布局**：`internal/wire/**` 是破坏性冻结区，本次零改动。
- **不改 `p2pc` CLI 行为**：不加旗标、不改子命令；策略一律走环境变量注入。
- **不新增第三方依赖**：直传策略只用标准库读 env，落在**无 viper 的 `internal/directpolicy`**（viper 只留在 p2pd 侧的 `internal/config`）⇒ viper 不再被链进 p2pc 二进制（相对 main 净增 **272B**，而非策略留在 `internal/config` 时的 +899KB）。
- **不新增直传产品能力**：本次只加观测面与策略旋钮，不加用户可见功能。

**默认行为不变（硬要求，已由单测钉住）**

- 四项策略缺省值**逐字等于** 2026-11-15 前的硬编码值（1.5s / 4s / 2s / 允许回退）⇒ 不配置时回退决策链与今天完全一致。
- **取值口径逐字不变**：与原 viper 实现做**逐项对账**（21 组矩阵：取值 + 告警文案与出现顺序全等）⇒ 换实现不改行为（时长解析复刻 `cast.ToDuration` 字符串分支：串内不含 `ns/u/µ/m/h` 时按纳秒解析，故 `"5"` 仍是 5ns）。
- 遥测契约**向后兼容**：签名负载升 v2（`node_id|kind|path|reason|net|dur_ms|ts`），服务端仍接受旧客户端的 v1 负载（仅当 `net` 与 `dur_ms` 都缺省时才回落）。
- 已知代价（如实记录）：**新客户端 → 旧服务端**时遥测上报会被旧服务端拒签（负载格式变了），丢的只是这一维度遥测，传输本身不受影响；两端同版本即无此问题。
