#!/bin/bash
# p2pd 冒烟:健康检查 / 签名注册 / 公告 / 解析 / 撤销 / 注销 / 管理端 / 指标,跑完即清。
# 签名生命周期由 scripts/smokegen(同模块,可 import internal/)以真实客户端协议执行。
set -e
cd "$(dirname "$0")/.."

PORT="${SMOKE_PORT:-12399}"
ADMIN_PW="smoke-admin-pw"
BASE="http://127.0.0.1:${PORT}"
PID=""

cleanup() {
  [ -n "$PID" ] && kill "$PID" 2>/dev/null || true
  wait 2>/dev/null || true
}
OK=0
# shellcheck disable=SC2154  # rc 在 trap 体内赋值，shellcheck 看不见
trap 'rc=$?; cleanup; if [ "$rc" -ne 0 ]; then exit $rc; fi; if [ "${OK:-0}" != 1 ]; then exit 1; fi; exit 0' EXIT

echo "── 构建 p2pd"
make build -s

echo "── 启动 p2pd (端口 ${PORT}, admin+中继开)"
PB_P2P_SERVER_PORT=${PORT} PB_P2P_ADMIN_PASSWORD=${ADMIN_PW} PB_P2P_RELAY_ENABLED=true ./bin/p2pd > /tmp/p2pd-smoke.log 2>&1 &
PID=$!
for i in $(seq 1 20); do
  curl -sf "${BASE}/health" >/dev/null 2>&1 && break
  sleep 0.5
done

echo "── [1/6] GET /health"
curl -sf "${BASE}/health" | grep -q '"status":"ok"' && echo "  ✓ health ok"

echo "── [2/7] 节点生命周期 flow(注册/公告/解析/撤销/注销)"
go run ./scripts/smokegen -base "${BASE}" 2>&1 | sed 's/^/  /'

echo "── [3/7] resolve 未知口令 → 404"
CODE=$(curl -s -o /dev/null -w '%{http_code}' "${BASE}/v1/resolve/0000000000000000000000000000000000000000000000000000000000000000")
[ "$CODE" = "404" ] && echo "  ✓ resolve miss → 404"

echo "── [4/7] 管理 API(stats 应剩 0 节点/0 公告)"
curl -sf "${BASE}/v1/admin/stats" -H "Authorization: Bearer ${ADMIN_PW}" | grep -q '"nodes":0' \
  && echo "  ✓ admin stats nodes=0"

echo "── [5/7] 管理 API 未授权 → 401"
CODE=$(curl -s -o /dev/null -w '%{http_code}' "${BASE}/v1/admin/stats")
[ "$CODE" = "401" ] && echo "  ✓ admin 无凭据 → 401"

echo "── [6/7] GET /metrics"
curl -sf "${BASE}/metrics" | grep -q 'p2p_nodes_active' && echo "  ✓ metrics 暴露"

echo
echo "✓ smoke OK"
OK=1
