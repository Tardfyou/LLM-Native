#!/bin/bash
# setup_rag.sh - 设置 RAG 知识库环境
#
# 功能:
# 1. 安装 Python 依赖 (chromadb, llama-index, sentence-transformers)
# 2. 启动 ChromaDB Docker 容器
# 3. 下载嵌入模型 (可选，使用本地缓存)
#
# 用法:
#   ./scripts/setup_rag.sh          # 完整安装
#   ./scripts/setup_rag.sh --skip-deps  # 跳过依赖安装

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

echo "=========================================="
echo "RAG 知识库环境设置"
echo "=========================================="
echo "项目目录: $PROJECT_DIR"
echo ""

# 解析参数
SKIP_DEPS=false
while [[ $# -gt 0 ]]; do
    case $1 in
        --skip-deps)
            SKIP_DEPS=true
            shift
            ;;
        *)
            echo "未知参数: $1"
            exit 1
            ;;
    esac
done

# 1. 安装 Python 依赖
if [ "$SKIP_DEPS" = false ]; then
    echo ">>> 步骤 1: 安装 Python 依赖..."
    echo ""

    echo "安装核心依赖..."
    pip install -q openai loguru pyyaml

    echo "安装 RAG 依赖..."
    pip install -q chromadb>=0.4.0 \
        llama-index-core>=0.10.0 \
        llama-index-vector-stores-chroma>=0.1.0 \
        llama-index-embeddings-huggingface>=0.1.0 \
        sentence-transformers>=2.2.0

    echo "✓ 依赖安装完成"
else
    echo ">>> 跳过依赖安装 (--skip-deps)"
fi

echo ""

# 2. 检查 Docker
echo ">>> 步骤 2: 检查 Docker..."
if ! command -v docker &> /dev/null; then
    echo "⚠ Docker 未安装，ChromaDB 将无法启动"
    echo "  请安装 Docker 后重新运行此脚本"
    echo ""
    echo "  或者使用内存模式运行 (不需要 Docker):"
    echo "    python scripts/test_rag.py --memory"
    exit 0
fi

if ! docker info &> /dev/null; then
    echo "⚠ Docker 未运行，请启动 Docker 服务"
    echo "  sudo systemctl start docker"
    exit 1
fi

echo "✓ Docker 可用"
echo ""

# 3. 启动 ChromaDB
echo ">>> 步骤 3: 启动 ChromaDB 容器..."

# 检查是否已运行
if docker ps | grep -q checker-chromadb; then
    echo "ChromaDB 容器已在运行"
else
    # 检查是否存在但未运行
    if docker ps -a | grep -q checker-chromadb; then
        echo "启动已存在的 ChromaDB 容器..."
        docker start checker-chromadb
    else
        echo "创建并启动 ChromaDB 容器..."
        docker-compose up -d
    fi
fi

echo ""

# 4. 等待 ChromaDB 就绪
echo ">>> 步骤 4: 等待 ChromaDB 就绪..."
MAX_RETRIES=30
RETRY_COUNT=0

while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
    if curl -s http://localhost:8001/api/v1/heartbeat > /dev/null 2>&1; then
        echo "✓ ChromaDB 已就绪"
        break
    fi

    RETRY_COUNT=$((RETRY_COUNT + 1))
    echo "  等待中... ($RETRY_COUNT/$MAX_RETRIES)"
    sleep 1
done

if [ $RETRY_COUNT -eq $MAX_RETRIES ]; then
    echo "⚠ ChromaDB 启动超时"
    echo "  请检查日志: docker logs checker-chromadb"
    exit 1
fi

echo ""

# 5. 检查嵌入模型
echo ">>> 步骤 5: 检查嵌入模型..."
MODEL_DIR="$PROJECT_DIR/pretrained_models"

if [ -d "$MODEL_DIR" ]; then
    echo "本地模型目录: $MODEL_DIR"
    # 检查是否有模型
    if ls "$MODEL_DIR"/models--* 1> /dev/null 2>&1; then
        echo "✓ 找到本地缓存模型"
    else
        echo "本地模型目录为空，首次运行时将自动下载"
    fi
else
    echo "创建模型缓存目录..."
    mkdir -p "$MODEL_DIR"
    echo "首次运行时将自动下载嵌入模型"
fi

echo ""
echo "=========================================="
echo "✓ RAG 环境设置完成!"
echo ""
echo "测试 RAG 功能:"
echo "  python scripts/test_rag.py"
echo ""
echo "运行智能体 (带 RAG):"
echo "  python -m src.main generate --patch tests/null_ptr_dereference.patch"
echo "=========================================="
