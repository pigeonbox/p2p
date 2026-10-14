# PigeonBox P2P

[![CI](https://github.com/pigeonbox/p2p/actions/workflows/ci.yml/badge.svg)](https://github.com/pigeonbox/p2p/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/tag/pigeonbox/p2p?label=release)](https://github.com/pigeonbox/p2p/releases)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](./LICENSE)
[![Go](https://img.shields.io/badge/Go-1.26-00ADD8?logo=go&logoColor=white)](https://go.dev)

PigeonBox 生态的 **P2P 联邦注册中心**：让任意多个 PigeonBox 节点（server / fnos / desktop）互相发现，口令分享跨站可达——文件始终从源节点直出，注册中心不落盘、不见明文。

**The federated registry for PigeonBox**: nodes register, passcodes resolve across sites, files flow directly from the source node — the registry stores no files and never sees plaintext passcodes.

## 它解决什么

| 能力 | 说明 | 状态 |
|---|---|---|
| 节点注册与心跳 | Ed25519 签名租约（node_id 即公钥），TTL 到期自动清扫 | ✅ v0.1 |
| 口令联邦路由 | `SHA-256(口令) → 源节点`，取件方直连源节点、源节点本地校验口令，零跨节点信任 | ✅ v0.1 |
| 信令信道 | WS 同口令双方配对 + 不透明握手帧转发（节点签名准入，服务端零知识） | ✅ v0.2 |
| **设备直传** | PAKE → 加密候选交换 → UDP 同时开洞 → 失败走加密中继；AEAD 传输+断点续传+sha256 校验 | ✅ v0.3（`p2pc` 参考客户端，六平台二进制随 Release 发布） |
| 安全加固 | wire AEAD 跨方向 nonce 重用修复（方向标签分离 nonce 空间）、注册 token 恒时比较、注册中心容量治理（全局节点/公告上限）、中继每 IP 限流、信令会话存活检查、HKDF 密钥派生 | ✅ v0.4 |
| **传输协议 v2（破坏性）** | v0.4 起 wire 帧 nonce 空间与密钥派生（HKDF）整体轮换，**与 v0.3.x 及更早版本互不兼容**——双端（p2pc/desktop）须同版升级，旧版互传首帧直接失败 | ✅ v0.4 |
| 安全运营加固 + 传输协议 v3 | XFF 末段取 IP（可信反代网段）、resolve per-hash 限流（单口令枚举闸）、TLS 信令、公告快照持久化（重启消除失联窗口）、原生 fuzz×6；协议 v3=配对后显式版本协商（不一致给可读错误而非密码学报错）+ QUIC 大文件多流并行（每流独立派生密钥） | ✅ v0.5 |
| **传输协议 v4（破坏性）** | 多文件 manifest 流（逐文件授权/部分接受/目录白名单消毒/zstd 压缩/单遍哈希）、IPv6 双栈、PCP·NAT-PMP·UPnP 端口映射、先通后优（中继先行+后台打洞升级直连）、DNS SRV 多注册中心+rendezvous 分片、中继默认开；**双端（p2pc/desktop）须同版** | ✅ v0.6 |

非目标：内容 DHT 去中心化、离线传输、文件中转存储。

## 快速开始

```bash
docker run -d --name fcb-p2p -p 12346:12346 \
  -e PB_P2P_ADMIN_PASSWORD=$(openssl rand -hex 16) \
  ghcr.io/pigeonbox/p2p:latest
```

源码构建：

```bash
make build && ./bin/p2pd            # 服务端:12346(HTTP/WS/反射器)+12347(中继,默认关)
make smoke                          # 冒烟:注册/公告/解析/信令/直传回环全流程
```

## 设备直传（p2pc，M3+）

支持多文件/目录、断点续传、可选 zstd 压缩(>1MB 自动)、逐文件授权、
大文件多流并行、先通后优(中继先行+后台打洞升级直连)与 IPv6 双栈。

```bash
# 发送方(自动生成口令 XXXX-XXXX-XXXX 并等待对方取走)
p2pc send 报告.pdf --registry http://p2p.example.com:12346

# 接收方(输入同一口令,文件直连下载到当前目录)
p2pc recv XXXX-XXXX-XXXX --registry http://p2p.example.com:12346

# 接收方亦可经 env 传码(v0.6.2 起):`recv -` 从 PB_P2P_CODE 读口令,
# argv 不留码——同机 `ps` 看不到口令,适合共享主机/CI 环境
PB_P2P_CODE=XXXX-XXXX-XXXX p2pc recv - --registry http://p2p.example.com:12346
```

流程：节点注册+口令公告 → WS 信令配对（接收方与 resolve 源身份交叉核对）→ PAKE（口令派生会话密钥）→ 候选地址交换（PAKE 派生密钥加密）→ **UDP 同时开洞**（反射器提供公网映射；成功走 QUIC 指纹钉定 mTLS 直连）→ 失败回落**加密中继**（12347，令牌配对+限速）→ AEAD 消息传输（meta/ready/chunk/final，断点续传）→ sha256 全量校验。服务端全程只见密文。

### 网页模式（p2pc-web）

面向无 webkit2gtk-4.1 的老底座桌面（统信 UOS V20 全系 / 银河麒麟 V10 SP1 等）的浏览器版客户端：单个纯静态二进制，本机起回环 HTTP 服务，浏览器即界面——文件柜快捷入口 + 设备直传收发（内置 p2p，与 p2pc 同协议，双端须同为协议 v2）。

```bash
./p2pc-web-x86_64-unknown-linux-gnu                       # 默认 127.0.0.1:12348,自动开浏览器
./p2pc-web-x86_64-unknown-linux-gnu --out ~/下载 --no-open # 另有 --addr --max-upload --relay --no-punch
```

安全：启动生成随机令牌（进入须用启动打印的完整地址），回环部署校验 Host 头防 DNS rebinding；上传流式落临时目录（保留原始文件名给对端），传输完即清理。六平台二进制随 Release 发布（资产名 `p2pc-web-<triple>`）。

### 分发面（p2pc 随包渠道）

除本仓 Release 的独立二进制外，p2pc 还经以下渠道随包分发（版本均随发布列车对齐）：

- **server 镜像**：Dockerfile 按架构内置 `/app/p2pc`（版本真相源为 server 仓 `.p2pc-version`，构建参数 `P2PC_VERSION` 缺省=优雅降级）；
- **fnos / qnap / openwrt 安装包**：各自随包 p2pc 二进制，应用内开箱可用；
- **core `p2px` supervisor**：standalone 部署模式下由 core 进程内调度（spawn p2pc 子进程做数据面），管理面 `/admin/p2p/*` 六端点（contracts `AdminP2PService`）。

## 配置

优先级：`PB_P2P_*` 环境变量 > 配置文件（`--config` / `CONFIG_PATH`）> 内置默认。完整样例见 [configs/config.yaml](./configs/config.yaml)。

| 环境变量 | 默认 | 说明 |
|---|---|---|
| `PB_P2P_SERVER_PORT` | `12346` | HTTP/信令端口 |
| `PB_P2P_SERVER_BEHIND_PROXY` | `false` | 反代部署置 true（从 X-Forwarded-For **末段**解析客户端 IP，首段客户端可伪造不可信） |
| `PB_P2P_SERVER_TRUSTED_PROXIES` | — | 可信反代网段 CIDR（逗号分隔）；设置后仅直连对端落在网段内才采信 XFF，从右向左跳过可信跳 |
| `PB_P2P_TLS_CERT` / `PB_P2P_TLS_KEY` | — | 成对配置时 HTTP/WS 信令以 TLS 提供（推荐反代终结，裸机公网直连才用） |
| `PB_P2P_REGISTRATION_MODE` | `open` | `open` 开放注册 / `token` 邀请制 |
| `PB_P2P_REGISTRATION_TOKEN` | — | token 模式的共享注册密钥 |
| `PB_P2P_ADMIN_PASSWORD` | — | 留空 = 管理 API 整体禁用；生产必须注入 |
| `PB_P2P_ANNOUNCE_MAX_PER_NODE` | `1000` | 单节点公告配额 |
| `PB_P2P_ANNOUNCE_MAX_TTL` | `168h` | 公告最大存活 |
| `PB_P2P_REGISTRATION_MAX_NODES` | `5000` | 全局节点租约上限（内存耗尽防护；0=默认值） |
| `PB_P2P_ANNOUNCE_MAX_TOTAL` | `50000` | 全局公告上限（0=默认值） |
| `PB_P2P_SIGNALING_ENABLED` | `true` | 信令信道开关（关闭仅影响直传配对） |
| `PB_P2P_SIGNALING_SESSION_TTL` | `10m` | 信令会话最长生命周期 |
| `PB_P2P_SIGNALING_IDLE_TIMEOUT` | `2m` | 连接空闲上限 |
| `PB_P2P_SIGNALING_MAX_PER_NODE` | `8` | 单节点并发信令会话上限 |
| `PB_P2P_REFLECTOR_ENABLED` | `true` | UDP 地址反射器（打洞前提） |
| `PB_P2P_RELAY_ENABLED` | `true` | 加密中继开关(打洞失败兜底;令牌配对非开放代理) |
| `PB_P2P_RELAY_PORT` | `12347` | 中继 TCP 端口 |
| `PB_P2P_RELAY_MBPS` | `10` | 单信道带宽上限（Mbps，0=不限） |
| `PB_P2P_RELAY_MAX_WAITING` | `1024` | 中继等待配对连接数上限 |
| `PB_P2P_RELAY_MAX_CONNS_PER_IP` | `16` | 中继单 IP 并发连接上限（防随机 token 占满等待槽） |
| `PB_P2P_RELAY_WAITING_TIMEOUT` | `60s` | 中继等待配对超时 |
| `PB_P2P_STORE_SNAPSHOT_PATH` | — | 快照文件路径（空=纯内存；设置后周期+停机落盘、重启恢复） |
| `PB_P2P_METRICS_STRICT` | `false` | true=未配置管理口令时 `/metrics` 直接 404（公共部署加固） |
| `PB_P2P_LOG_LEVEL` | `info` | debug / info / warn / error |
| `PB_P2P_SERVER_TLS_CERT/_KEY` | — | HTTP/WS 信令 TLS(成对配置) |
| `PB_P2P_STORE_SNAPSHOT_PATH` | — | 公告快照持久化(重启消除失联窗口) |
| `PB_P2P_METRICS_STRICT` | `false` | 未配管理口令时 /metrics 404(公共部署加固) |
| `PB_P2P_CODE` | — | p2pc 客户端(v0.6.2 起):`p2pc recv -` 从 env 读取口令,argv 不留码,防同机 ps 可见 |

客户端多源:`PB_P2P_REGISTRIES` 未设时可用 `--registries`(逗号分隔);
`--registry` 传裸域名自动走 DNS SRV(`_p2pc._tcp.<域>`)发现。公共节点
运营(部署/DNS/容量/滥用治理)见 [docs/PUBLIC-NODES.md](./docs/PUBLIC-NODES.md)。

## API（v1）

| 方法 路径 | 说明 |
|---|---|
| `POST /v1/nodes/register` | 注册/续租（`/v1/nodes/heartbeat` 同语义别名） |
| `DELETE /v1/nodes/{id}` | 注销并级联撤公告 |
| `GET /v1/nodes/{id}` | 节点公开信息 |
| `POST /v1/announces` | 宣告 `code_hash → 本节点`（先到先得，冲突 409） |
| `DELETE /v1/announces/{hash}` | 撤销（仅宣告节点） |
| `GET /v1/resolve/{hash}` | 解析 → `{node_id, url, ...}`；未接入 404 |
| `WS /v1/channel/{hash}` | **信令信道（M3）**：同 hash 双方配对，转发不透明握手帧（见下节契约） |
| `GET /health` · `GET /metrics` | 健康检查（显式 GET）/ Prometheus 指标 |
| `GET/DELETE /v1/admin/*` | 统计/列表/强制下线（Bearer 管理口令） |

### 签名约定

所有写操作带 Ed25519 签名（base64 std），负载为字段按序 `"\n"` 连接，签名公钥即 `node_id`：

```
注册/心跳:   node_id | url | name | version | caps(逗号连接) | ttl_seconds | nonce | ts
公告:        node_id | code_hash | expires_at | size_hint | ts
注销节点:    node_id | ts
撤销公告:    node_id | code_hash | ts
```

`ts` 为 unix 秒，允许 ±300s 偏移。参考实现见 [scripts/smokegen](./scripts/smokegen)（生态侧已由 core `federation` 域服务封装）。

## 信令信道协议（M3）

口令即房间号：发送方设备与接收方以**同一口令的 SHA-256** 接入 `WS /v1/channel/{code_hash}`，服务端按到达顺序配对（首个收 `waiting`，第二个配对成功双方各收 `paired`），之后在两 peer 间转发不透明帧。服务端职责止步于配对+转发+治理；PAKE/打洞/传输全部在对等端完成。

**准入（hello 帧，接入后 10s 内必须发出）：**

```json
{"type":"hello","node_id":"<hex>","ts":1700000000,"sig":"<base64 std>"}
```

签名负载逐字节为 `"channel-join\n<node_id>\n<code_hash>\n<ts>"`（Ed25519，私钥即节点身份密钥；node_id 必须处于有效租约内）。匿名者与未注册节点进不了门。

**服务端帧：**

| 帧 | 说明 |
|---|---|
| `{"type":"waiting"}` | 首个接入者：等待对方 |
| `{"type":"paired","peer_id":"<对方 node_id>"}` | 配对成功（双方各收一份；**接收方必须与 resolve 返回的源 node_id 交叉核对，防换人**） |
| `{"type":"data","from":"<发送方 node_id>","payload":"<base64>"}` | 转发的握手帧 |
| `{"type":"peer_left"}` | 对方断开 |
| `{"type":"error","message":"…"}` | 协议违规/会话超时 |

关闭码：`4001` hello 缺失或非法 · `4002` 信道占用或超配额 · `4003` 未授权（签名/身份/租约）。

**客户端义务（安全契约，p2pc 已全部实现）：**

1. 配对后先跑 **PAKE**（p2pc 用 [schollz/pake](https://github.com/schollz/pake) SIEC 曲线 2 消息流），data 帧里传不透明 PAKE 消息——服务端可见但无法推导密钥；
2. PAKE 完成后再传**候选地址**等敏感信息，且必须用 PAKE 派生密钥加密——明文候选=可被注入劫持；
3. 打洞：反射器取公网映射 + LAN 候选，UDP 同时开洞（探针须可解密=身份确认）；成功走 QUIC（会话级证书指纹钉定 mTLS）直连；
4. 失败走中继：令牌=PAKE 派生凭据，传输首帧 AEAD 认证（令牌被窃仅构成 DoS）；
5. 响应服务端 ping（主流 WS 库默认自动回 pong；pong 与数据帧均续空闲期）。

**服务端治理**（均可配置）：data 帧负载 ≤16KB · 会话 TTL 10 分钟 · 连接空闲 2 分钟 · 单节点并发会话 8 · 全局 1024；已满信道拒绝第三人（4002）。

## 安全模型

- **注册中心不接触明文口令**：公告只存 `SHA-256(口令)`；解析方须持有口令才能计算哈希查询。
- **离线枚举防线在宣布侧**：生态客户端（core）只对熵 ≥40bit 的口令发联邦公告，短数字取件码不出站；解析接口按 IP 严格限流。
- **身份不可冒名**：node_id 即 Ed25519 公钥，全部写操作验签；管理端可强制下线作恶节点。
- **限流分层**：读/写/管理路径独立令牌桶，超限 429；resolve 叠加 per-hash 维度封顶（IP 池绕不过的单口令枚举闸），反代部署采信 XFF 仅限可信网段且取末段（首段可伪造）。
- **传输协议版本协商（v3）**：配对后 PAKE 前双方显式交换协议版本，不一致给出可读错误而非密码学报错；QUIC 直传大文件多流并行（每流独立派生密钥防跨流 nonce 重用），中继/续传恒单流。
- **信令信道准入**：WS 接入须持节点 Ed25519 签名（channel-join 负载）+ 有效租约；帧限 16KB、会话 TTL/空闲上限、单节点与全局配额——不存在匿名可占的房间。
- **中继默认开启**但非开放代理:配对须 PAKE 派生令牌,无令牌连接 60s 超时即断,另有等待槽/单 IP/带宽三重上限(先通后优:中继上起传,后台打洞成功后文件边界自动升级直连)。
- **传输协议版本协商(v4)**:多文件 manifest 流(逐文件授权/部分接受/目录白名单消毒/zstd 压缩/单遍哈希);多注册中心按 rendezvous hashing 零协调分片,失败顺延。

## 生态导航

| 仓库 | 角色 |
|---|---|
| [pigeonbox](https://github.com/pigeonbox/pigeonbox) | 装配 hub：go.work + 文档 + 部署清单 |
| [contracts](https://github.com/pigeonbox/contracts) · [core](https://github.com/pigeonbox/core) | 契约层 · 业务核心库（`federation` 域服务对接本服务） |
| [server](https://github.com/pigeonbox/server) · [frontend](https://github.com/pigeonbox/frontend) | 独立部署壳 · Web 前端 |
| [fnos](https://github.com/pigeonbox/fnos) · [desktop](https://github.com/pigeonbox/desktop) | 飞牛 fnOS 适配 · 桌面客户端（M3 直传对等端） |
| [charts](https://github.com/pigeonbox/charts) | Kubernetes Helm Chart |

依赖方向：`server / fnos / frontend → core → contracts`；p2p 为叶子仓，业务链零生态依赖（stdlib net/http，无 Hertz，CI 守卫强制），不在依赖链上。唯一允许的地基层依赖是 [kit](https://github.com/pigeonbox/kit)（共享工具库，本身零生态依赖，依赖方向恒为 p2p → kit 单向无环；2026-10-05 起按键限流器采用 kit/ratelimit）。

## License

[Apache-2.0](./LICENSE) — `Copyright 2026 PigeonBox`。本项目为独立实现，未移植 vastsa/PigeonBox（LGPL-3.0）或 schollz/croc（MIT，仅以依赖方式参考其 PAKE 思路）的源码。
