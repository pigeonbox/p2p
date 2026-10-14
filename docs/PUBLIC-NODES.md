# 公共注册中心(Public p2pd)运营手册

> 目标:让没有服务器/不会部署的用户开箱可用。行业模板取自 Bitcoin DNS seed
> (多运营者 DNS 列表引导)、croc 中继网络(成本失控教训)、wormhole mailbox
> 迁移事故(存储无界增长)与 Syncthing relay pool(自愿加入+择优选路)。

## 核心原则

1. **节点=接入点,不是管道**。注册中心/信令/反射器是轻量控制面;传输
   优先 P2P 直连,中继只兜底。官方节点不背大流量。
2. **2-3 台、各自运营者、互为备份**,不做单台权威。客户端按
   rendezvous hashing(SHA-256(口令|基址))对节点表确定性排序——两端同表
   自然汇聚同一节点,节点间零协调。
3. **一切有上限**:公告 TTL/总量、信令会话、中继等待槽/单 IP/带宽
   (p2pd 内建,见 configs/config.yaml)。无上限的 rendezvous 死法参考
   wormhole mailbox(存储塞爆迁移)与 croc(单人扛 40TB/月)。

## 节点部署清单

```bash
# 1. p2pd(注册/公告/解析 + WS 信令 + UDP 反射器 + 加密中继)
PB_P2P_ADMIN_PASSWORD=$(openssl rand -hex 16) \
PB_P2P_METRICS_STRICT=true \
docker run -d --name p2pd -p 12346:12346/udp -p 12346:12346 -p 12347:12347 \
  ghcr.io/pigeonbox/p2p:<版本>
# 反射器与 HTTP 同端口(12346/udp);中继 12347/tcp 默认开

# 2. 推荐 config 覆盖(中继容量按带宽定)
# relay.mbps_per_channel: 20     # 单信道限速
# relay.max_waiting: 1024
# metrics.strict: true
```

- 端口:12346/tcp+udp(HTTP/WS/反射器)、12347/tcp(中继,默认开)。
- 建议 TLS 反代(443 终结)或 `server.tls_cert/tls_key` 直配。
- 监控:`/metrics`(配 PB_P2P_ADMIN_PASSWORD 后需 Bearer);重点看
  `p2p_rate_limited_total`、`p2p_signaling_joins_total{result="busy"}`、
  中继带宽(自备 node_exporter/容器指标)。
- **成本告警**:中继出向流量超预算即告警——croc 教训,勿裸奔。

## DNS 发现约定(客户端引导)

客户端 `--registry <裸域名>`(无 scheme/端口)时自动:

1. SRV `_p2pc._tcp.<域名>`(优先,多记录=多节点,priority/weight 生效)
2. 回落 A/AAAA `<域名>`(端口 12346)

运营者 DNS 配置示例(BIND/云 DNS 均可):

```
_p2pc._tcp.pigeonbox.example.com. IN SRV 10 10 12346 p2p1.example.com.
_p2pc._tcp.pigeonbox.example.com. IN SRV 10 10 12346 p2p2.example.com.
```

用户侧:

```bash
export PB_P2P_REGISTRIES=http://p2p1.example.com:12346,http://p2p2.example.com:12346
# 或 CLI: p2pc send 文件 --registry pigeonbox.example.com --registries ...
```

v0.6.2 起 p2pc 支持 `PB_P2P_CODE` env 传码:`p2pc recv -` 从环境变量读口令,
argv 不留码——同机 `ps` 看不到口令,适合共享主机/CI 环境。

## 滥用治理

- 注册/公告/信令全量 Ed25519 签名准入(无身份写入不存在);
- resolve 叠加 per-hash 限流(IP 池无法对热点口令枚举);
- 中继须 PAKE 派生令牌配对,无令牌 60s 等待超时即断——**不是开放代理**;
- 红队曾把加密中继当数据外泄通道(croc 案例):保留流量画像能力
  (字节计数已内建限速桶),服务条款明示禁止违法传输。

## 容量参考(单 2C4G VPS)

| 面 | 上限 | 说明 |
|---|---|---|
| 节点/公告 | 5000 / 50000 | 默认容量上限,可调 |
| WS 信令会话 | 1024 总/8 每节点 | 直传配对用,毫秒级驻留 |
| 中继等待 | 1024 槽/60s 超时/16 每 IP | 兜底管道,按带宽设限速 |
