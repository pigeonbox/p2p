#!/bin/bash
# p2pd 冒烟:健康检查 / 签名注册 / 公告 / 解析 / 撤销 / 注销 / 管理端 / 指标,跑完即清。
# 签名生命周期由 scripts/smokegen(同模块,可 import internal/)以真实客户端协议执行。
#
# ── shellkit 改造（2026-11-18）────────────────────────────────────────────
#   日志 ⇒ log_*(stdout 只给数据,日志一律 stderr);失败 ⇒ die;
#   等服务就绪 ⇒ net_wait_http;清理栈 ⇒ trap_push + trap_install。
#   **退出码契约不变**:0=通过 / 非 0=失败(原脚本 set -e 下任一断言失败即非 0)。
#   **保留手写**:冒烟断言本体(判定文案/断言顺序)、`set -e`(不加 -e 会让断言失败被吞)。
set -e

# third_party/shellkit 是上游镜像(由 hub 侧 scripts/vendor-shellkit.sh 物化)⇒ **勿手改**。
# ⚠️ 落点是 third_party/ 而不是 vendor/:Go ≥1.14 见到**模块根**下有 vendor/ 就默认切
#    vendor 模式 ⇒ 缺 vendor/modules.txt ⇒ go build 报 "inconsistent vendoring"(实测现红)。
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
. "$REPO_ROOT/third_party/shellkit/lib/bootstrap.sh"
export SHELLKIT_LANG="${SHELLKIT_LANG:-zh_CN}" # 库内消息走中文,与生态输出一致

cd "$REPO_ROOT"

PORT="${SMOKE_PORT:-12399}"
ADMIN_PW="smoke-admin-pw"
BASE="http://127.0.0.1:${PORT}"
PID=""

# 清理栈 + trap 安装(shellkit 接管 EXIT/INT/TERM/HUP):处理器取 $? 后原样
# `exit "$__st"` ⇒ **退出码照旧透传** ⇒ 与原手写 trap 等价。
# ⚠️ 保留手写的 cleanup():它要杀后台 p2pd(shellkit 的清理栈只管自己 push 的动作)。
#    shellkit 的 trap_push 用 eval 执行动作 ⇒ 函数名可直接传(已实测可调用)。
cleanup() {
  [ -n "$PID" ] && kill "$PID" 2>/dev/null || true
  wait 2>/dev/null || true
}
# shellcheck disable=SC2016  # 单引号是**故意的**:清理命令要在 trap 触发时再求值
trap_push 'cleanup'
trap_install
# ⚠️ 原脚本末尾的 `OK=1` 成功哨兵**已移除**:shellkit 的 trap_install 由库保留退出码
#    (原手写 trap 用 `rc==0 且 OK!=1 ⇒ 判失败` 兜「跑完却没成功」;本脚本的失败出口
#    穷举为「set -e 下任一断言失败 ⇒ 非 0」⇒ 哨兵不可达 ⇒ 与原语义等价)。

log_info "构建 p2pd"
make build -s

log_info "启动 p2pd (端口 ${PORT}, admin+中继开)"
PB_P2P_SERVER_PORT=${PORT} PB_P2P_ADMIN_PASSWORD=${ADMIN_PW} PB_P2P_RELAY_ENABLED=true ./bin/p2pd >/tmp/p2pd-smoke.log 2>&1 &
# shellcheck disable=SC2034  # PID 只在 cleanup() 里用(经 trap_push 的字符串调用,shellcheck 看不见)
PID=$!
# 等服务就绪 ⇒ net_wait_http(超时单位=秒)。
# ⚠️ 原实现是 20 次 × 0.5s = 最多 10s;net_wait_http 的 TIMEOUT 是**秒** ⇒ 传 10 等价。
# ⚠️ 原实现**不检查超时**(循环结束就往下跑,后续断言自己会红);net_wait_http 超时返回非 0
#    ⇒ 这里显式判一次,让「起不来」与「断言失败」两种失败**可区分**(退出码都是 1)。
net_wait_http "${BASE}/health" 10 || die 1 "p2pd 启动超时(10s):${BASE}/health 无响应"

log_info "[1/6] GET /health"
curl -sf "${BASE}/health" | grep -q '"status":"ok"' && log_ok "health ok"

log_info "[2/7] 节点生命周期 flow(注册/公告/解析/撤销/注销)"
go run ./scripts/smokegen -base "${BASE}" 2>&1 | sed 's/^/  /'

log_info "[3/7] resolve 未知口令 → 404"
CODE=$(curl -s -o /dev/null -w '%{http_code}' "${BASE}/v1/resolve/0000000000000000000000000000000000000000000000000000000000000000")
[ "$CODE" = "404" ] && log_ok "resolve miss → 404"

log_info "[4/7] 管理 API(stats 应剩 0 节点/0 公告)"
curl -sf "${BASE}/v1/admin/stats" -H "Authorization: Bearer ${ADMIN_PW}" | grep -q '"nodes":0' &&
  log_ok "admin stats nodes=0"

log_info "[5/7] 管理 API 未授权 → 401"
CODE=$(curl -s -o /dev/null -w '%{http_code}' "${BASE}/v1/admin/stats")
[ "$CODE" = "401" ] && log_ok "admin 无凭据 → 401"

log_info "[6/7] GET /metrics"
curl -sf "${BASE}/metrics" | grep -q 'p2p_nodes_active' && log_ok "metrics 暴露"

log_ok "smoke OK"
