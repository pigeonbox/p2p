#!/bin/bash
# Release 工作流静态校验（p2p#59）。
#
# 背景：hub 上的 p2p-v* Release 曾被仓外动作删除，而 release.yml 只能由 tag
# push 触发 ⇒ 已发 tag 无法重跑回挂，发布列车卡死。修复要求：
#   1) workflow_dispatch + version 输入（已发 tag 可重跑）；
#   2) 全链路按 inputs.version || github.ref_name 取目标 tag；
#   3) 回挂后回调 hub 列车（train-advance）；
#   4) 回挂资产完整性校验。
# 本脚本把上述约束钉成 CI 门禁：工作流被改回 tag-only 或回挂步丢失即红。
set -euo pipefail

cd "$(dirname "$0")/.."
WF=".github/workflows/release.yml"
FAIL=0

chk() {
    local desc="$1"; shift
    if "$@"; then
        printf '  ✓ %s\n' "$desc"
    else
        printf '  ✗ %s\n' "$desc" >&2
        FAIL=1
    fi
}

has()      { grep -Fq -- "$1" "$WF"; }
has_re()   { grep -Eq -- "$1" "$WF"; }
not_has()  { ! grep -Fq -- "$1" "$WF"; }
count_ge() { [ "$(grep -Fc -- "$1" "$WF")" -ge "$2" ]; }

echo "── release.yml 回挂自愈门禁"
chk "存在 workflow_dispatch 触发" has 'workflow_dispatch:'
chk "workflow_dispatch 有 version 输入" bash -c "grep -A5 '^  workflow_dispatch:' '$WF' | grep -Fq 'version:'"
chk "version 输入标记 required: true" bash -c "grep -A7 '^  workflow_dispatch:' '$WF' | grep -Fq 'required: true'"
chk "并发组按 inputs.version || github.ref_name 分组" has_re 'group:.*inputs\.version \|\| github\.ref_name'
chk "三个作业都解析 REL_TAG" count_ge 'REL_TAG: ${{ inputs.version || github.ref_name }}' 3
chk "release/p2pc 作业按 REL_TAG 检出目标 tag" count_ge 'ref: ${{ env.REL_TAG }}' 2
chk "dispatch 镜像标签显式补 version" has 'type=raw,value=${{ steps.ver.outputs.version }}'
chk "dispatch 镜像标签显式补 major.minor" has 'type=raw,value=${{ steps.ver.outputs.major_minor }}'
chk "镜像 VERSION 取 REL_TAG（非 github.ref_name）" has 'VERSION=${{ env.REL_TAG }}'
chk "二进制版本取 REL_TAG（不再用 GITHUB_REF_NAME）" bash -c "grep -Fq 'VERSION=\"\${REL_TAG#v}\"' '$WF' && ! grep -Fq 'GITHUB_REF_NAME' '$WF'"
chk "本仓 Release 上传按 TAG 环境变量" bash -c "grep -Fq 'gh release upload \"\$TAG\" out/p2pc-*' '$WF'"
chk "回挂作业回调 hub 列车 train-advance" has 'train-advance'
chk "回调 payload 标注 component=p2p" has '\"component\":\"p2p\"'
chk "回挂后校验 hub 资产数与本仓一致" bash -c "grep -Fq 'expected=' '$WF' && grep -Fq 'hub 回挂资产数' '$WF'"

if [ "$FAIL" -ne 0 ]; then
    echo "✗ release.yml 回挂自愈门禁失败" >&2
    exit 1
fi
echo "✓ release.yml 回挂自愈门禁通过"