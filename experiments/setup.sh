#!/bin/bash
# experiments/setup.sh
# 初始化实验环境

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=============================================="
echo "  PATCHWEAVER 实验环境初始化"
echo "=============================================="

# 检查依赖
echo ""
echo "[1/6] 检查系统依赖..."
MISSING=()

command -v python3 >/dev/null 2>&1 || MISSING+=("python3")
command -v clang >/dev/null 2>&1 || MISSING+=("clang")
command -v git >/dev/null 2>&1 || MISSING+=("git")
command -v curl >/dev/null 2>&1 || MISSING+=("curl")
command -v make >/dev/null 2>&1 || MISSING+=("make")

if [ ${#MISSING[@]} -gt 0 ]; then
    echo "缺少依赖: ${MISSING[*]}"
    echo "请先安装缺少的依赖"
    exit 1
fi

echo "  ✓ Python3: $(python3 --version)"
echo "  ✓ Clang: $(clang --version | head -1)"
echo "  ✓ Git: $(git --version)"
echo "  ✓ Make: $(make --version | head -1)"
echo "  ✓ Curl: $(curl --version | head -1)"

# 创建目录结构
echo ""
echo "[2/6] 创建目录结构..."
mkdir -p targets/{sqlite,libxml2,curl}/{src,patches,ground_truth}
mkdir -p outputs
mkdir -p configs
mkdir -p results/{raw_data,tables,figures,paper}
echo "  ✓ 目录创建完成"

# Python 依赖
echo ""
echo "[3/6] 安装 Python 依赖..."
pip3 install -q pyyaml pandas matplotlib seaborn jinja2 tqdm 2>/dev/null || {
    echo "  ! pip install 失败，请手动安装: pip3 install pyyaml pandas matplotlib seaborn jinja2 tqdm"
}
echo "  ✓ Python 依赖就绪"

# 检查 CodeQL
echo ""
echo "[4/6] 检查 CodeQL..."
if command -v codeql &> /dev/null; then
    CODEQL_VERSION=$(codeql version 2>/dev/null | head -1 || echo "unknown")
    echo "  ✓ CodeQL: $CODEQL_VERSION"
elif [ -d "$HOME/codeql" ]; then
    export PATH="$HOME/codeql:$PATH"
    echo "  ✓ CodeQL: $(ls $HOME/codeql/ 2>/dev/null | head -1)"
else
    echo "  ! CodeQL 未安装"
    echo "    下载: https://github.com/github/codeql-cli-binaries/releases"
    echo "    解压到 ~/codeql/ 并添加到 PATH"
fi

# 检查基线工具
echo ""
echo "[5/6] 检查基线工具..."

# cppcheck
if command -v cppcheck &> /dev/null; then
    echo "  ✓ cppcheck: $(cppcheck --version 2>&1 || echo 'installed')"
else
    echo "  ! cppcheck 未安装"
    echo "    安装: sudo apt-get install cppcheck"
fi

# scan-build (clang-tools)
if command -v scan-build &> /dev/null; then
    echo "  ✓ scan-build: 已安装"
else
    echo "  ! scan-build 未安装"
    echo "    安装: sudo apt-get install clang-tools"
fi

# Infer (可选)
if [ -d "$HOME/infer" ]; then
    export PATH="$HOME/infer/bin:$PATH"
    echo "  ✓ Infer: $(infer --version 2>&1 | head -1 || echo 'installed')"
elif command -v infer &> /dev/null; then
    echo "  ✓ Infer: $(infer --version 2>&1 | head -1 || echo 'installed')"
else
    echo "  - Infer (可选): 未安装"
    echo "    下载: https://fbinfer.github.io/"
fi

# 创建配置文件
echo ""
echo "[6/6] 创建配置文件..."

# 基线配置
cat > configs/baseline.yaml << 'EOF'
# 基线配置: 仅 Generate，无证据系统
experiment:
  name: "baseline"
  description: "Generate only without evidence system"

patchweaver:
  enabled: false
  preflight_analysis: false

evidence:
  enabled: false

generate:
  max_iterations: 12
  max_knowledge_search_calls: 2
  temperature: 0.15

refine:
  enabled: false

quality_gates:
  artifact_review:
    enabled: true
  lsp_validation:
    enabled: true
EOF

# 完整配置
cat > configs/full_pipeline.yaml << 'EOF'
# 完整配置: Generate + 证据系统 + Refine
experiment:
  name: "full_pipeline"
  description: "Full pipeline with evidence system and refinement"

patchweaver:
  enabled: true
  preflight_analysis: true
  max_planned_requirements: 8

evidence:
  enabled: true
  types:
    - patch_fact
    - semantic_slice
    - dataflow_candidate
    - call_chain
    - allocation_lifecycle
    - state_transition
    - path_guard
    - context_summary
    - validation_outcome

generate:
  max_iterations: 12
  max_knowledge_search_calls: 2
  temperature: 0.15

refine:
  enabled: true
  max_iterations: 8
  structural_candidate:
    enabled: true

quality_gates:
  artifact_review:
    enabled: true
  lsp_validation:
    enabled: true
EOF

# 仅证据系统
cat > configs/with_evidence.yaml << 'EOF'
# 证据系统配置: Generate + 证据系统，无 Refine
experiment:
  name: "with_evidence"
  description: "Generate with evidence system, without refinement"

patchweaver:
  enabled: true
  preflight_analysis: true
  max_planned_requirements: 8

evidence:
  enabled: true

generate:
  max_iterations: 12
  max_knowledge_search_calls: 2
  temperature: 0.15

refine:
  enabled: false

quality_gates:
  artifact_review:
    enabled: true
  lsp_validation:
    enabled: true
EOF

echo "  ✓ configs/baseline.yaml"
echo "  ✓ configs/with_evidence.yaml"
echo "  ✓ configs/full_pipeline.yaml"

# 完成
echo ""
echo "=============================================="
echo "  初始化完成!"
echo "=============================================="
echo ""
echo "下一步:"
echo "  1. 下载目标项目: python3 scripts/setup_targets.py --all"
echo "  2. 准备补丁文件: python3 scripts/prepare_patches.py --all"
echo "  3. 运行实验: python3 scripts/run_experiment.py --help"
echo ""