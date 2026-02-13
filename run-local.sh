#!/bin/bash
# =============================================================================
# LLM-Native 宿主机运行脚本
#
# 使用方法:
#   source ./run-local.sh       # 设置环境变量（推荐）
#   ./run-local.sh --start-chroma  # 启动 ChromaDB 服务
#   ./run-local.sh --stop-chroma   # 停止 ChromaDB 服务
#   ./run-local.sh --check         # 检查环境
#
# 设置环境后运行:
#   python3 src/main.py generate_detector --patch_file tests/simple/null_ptr_dereference.patch ...
# =============================================================================

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# 获取脚本所在目录
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

info() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[OK]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }

# ChromaDB 配置
CHROMA_CONTAINER_NAME="llm_native_chroma"
CHROMA_PORT=8001

# 设置环境变量
setup_environment() {
    export LLM_NATIVE_ROOT="$SCRIPT_DIR"
    export PYTHONPATH="$SCRIPT_DIR/src:$SCRIPT_DIR"

    # 加载 .env 文件
    if [ -f "$SCRIPT_DIR/.env" ]; then
        info "加载 .env 文件"
        set -a
        source "$SCRIPT_DIR/.env"
        set +a
    fi

    # 检测 ChromaDB
    if curl -s "http://localhost:$CHROMA_PORT/api/v1/heartbeat" > /dev/null 2>&1; then
        export CHROMA_HOST=localhost
        export CHROMA_PORT=$CHROMA_PORT
        success "ChromaDB 服务已连接 (端口 $CHROMA_PORT)"
    else
        info "ChromaDB 服务未运行，将使用本地持久化模式"
    fi

    success "环境变量已设置:"
    echo "  LLM_NATIVE_ROOT=$LLM_NATIVE_ROOT"
    echo "  PYTHONPATH=$PYTHONPATH"
}

# 启动 ChromaDB
start_chroma() {
    info "启动 ChromaDB 服务..."

    if ! command -v docker &> /dev/null; then
        warn "未安装 Docker，将使用本地持久化模式"
        return 1
    fi

    # 检查是否已运行
    if docker ps --format '{{.Names}}' | grep -q "^${CHROMA_CONTAINER_NAME}$"; then
        success "ChromaDB 已在运行"
        return 0
    fi

    # 启动容器
    if docker ps -a --format '{{.Names}}' | grep -q "^${CHROMA_CONTAINER_NAME}$"; then
        docker start $CHROMA_CONTAINER_NAME
    else
        docker run -d \
            --name $CHROMA_CONTAINER_NAME \
            -p $CHROMA_PORT:8000 \
            -v llm_native_chroma_data:/chroma/chroma \
            chromadb/chroma:latest
    fi

    sleep 3

    if curl -s "http://localhost:$CHROMA_PORT/api/v1/heartbeat" > /dev/null 2>&1; then
        success "ChromaDB 启动成功 (端口 $CHROMA_PORT)"
        return 0
    else
        warn "ChromaDB 启动中，请稍后再试"
        return 1
    fi
}

# 停止 ChromaDB
stop_chroma() {
    info "停止 ChromaDB..."
    if docker ps --format '{{.Names}}' | grep -q "^${CHROMA_CONTAINER_NAME}$"; then
        docker stop $CHROMA_CONTAINER_NAME
        success "ChromaDB 已停止"
    else
        info "ChromaDB 未运行"
    fi
}

# 检查环境
check_environment() {
    echo ""
    echo "========================================"
    echo "LLM-Native 环境检查"
    echo "========================================"

    # Python
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
        success "Python3: $PYTHON_VERSION"
    else
        error "Python3: 未安装"
    fi

    # 依赖
    echo ""
    info "检查 Python 依赖..."
    for pkg in fire loguru yaml chromadb; do
        if python3 -c "import $pkg" 2>/dev/null; then
            success "  $pkg: OK"
        else
            warn "  $pkg: 未安装"
        fi
    done

    # ChromaDB
    echo ""
    if curl -s "http://localhost:$CHROMA_PORT/api/v1/heartbeat" > /dev/null 2>&1; then
        success "ChromaDB: 运行中 (端口 $CHROMA_PORT)"
    else
        info "ChromaDB: 未运行 (将使用本地持久化模式)"
    fi

    echo ""
    info "环境变量:"
    echo "  LLM_NATIVE_ROOT: ${LLM_NATIVE_ROOT:-<未设置>}"
    echo "  PYTHONPATH: ${PYTHONPATH:-<未设置>}"
    echo "========================================"
}

# 显示帮助
show_help() {
    echo "
LLM-Native 宿主机运行脚本

使用方法:
  source ./run-local.sh           # 设置环境变量（推荐）
  ./run-local.sh --start-chroma   # 启动 ChromaDB 服务
  ./run-local.sh --stop-chroma    # 停止 ChromaDB 服务
  ./run-local.sh --check          # 检查环境

设置环境后运行:
  python3 src/main.py generate_detector --patch_file tests/simple/null_ptr_dereference.patch --target_framework clang --verbose

注意:
  - 使用 source 命令设置环境变量
  - 如不启动 ChromaDB，程序会使用本地持久化模式
"
}

# 主函数
main() {
    case "${1:-}" in
        --start-chroma)
            start_chroma
            ;;
        --stop-chroma)
            stop_chroma
            ;;
        --check)
            setup_environment
            check_environment
            ;;
        --help|-h)
            show_help
            ;;
        "")
            setup_environment
            echo ""
            info "环境已就绪，运行命令示例:"
            echo "  python3 src/main.py generate_detector --patch_file tests/simple/null_ptr_dereference.patch"
            ;;
        *)
            error "未知选项: $1"
            echo "运行 './run-local.sh --help' 查看帮助"
            return 1
            ;;
    esac
}

# 如果是 source 执行，只设置环境
if [[ "${BASH_SOURCE[0]}" != "${0}" ]]; then
    setup_environment
else
    main "$@"
fi
