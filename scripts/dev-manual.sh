#!/bin/bash
# Manual development environment launcher for LLM-Native Framework
# 当docker-compose不可用时的手动启动脚本
# 使用方法: ./scripts/dev-manual.sh

set -e

echo "🚀 手动启动LLM-Native开发环境..."
echo "⚠️  注意：此脚本用于docker-compose不可用的情况"

# 检查Docker是否运行
if ! docker info >/dev/null 2>&1; then
    echo "❌ Docker未运行，请先启动Docker"
    exit 1
fi

# 创建必要的目录
mkdir -p data/knowledge data/benchmarks results logs

# 构建镜像（如果需要）
echo "🏗️ 构建开发镜像..."
if ! docker images | grep -q "llm-native"; then
    docker build -t llm-native:dev .
    echo "✅ 镜像构建完成"
else
    echo "✅ 镜像已存在，跳过构建"
fi

# 创建网络（如果不存在）
docker network ls | grep -q "llm_native_network" || docker network create llm_native_network

# 启动向量数据库
echo "🐳 启动ChromaDB向量数据库..."
CONTAINER_NAME="llm_native_vector_db"

# 停止已存在的容器
docker stop $CONTAINER_NAME 2>/dev/null || true
docker rm $CONTAINER_NAME 2>/dev/null || true

docker run -d \
    --name $CONTAINER_NAME \
    --network llm_native_network \
    -p 8001:8000 \
    -v llm_native_vector_data:/chroma/chroma \
    chromadb/chroma:latest

echo "⏳ 等待向量数据库启动..."
sleep 5

# 检查向量数据库是否启动成功
if ! curl -s http://localhost:8001/api/v1/heartbeat >/dev/null; then
    echo "⚠️  向量数据库可能启动失败，但继续启动主容器..."
fi

# 启动开发容器
echo "🏗️ 启动开发容器..."
DEV_CONTAINER_NAME="llm_native_dev"

# 停止已存在的容器
docker stop $DEV_CONTAINER_NAME 2>/dev/null || true
docker rm $DEV_CONTAINER_NAME 2>/dev/null || true

# 获取当前目录的绝对路径
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

docker run -it \
    --name $DEV_CONTAINER_NAME \
    --network llm_native_network \
    -p 8000:8000 \
    -v "$PROJECT_ROOT:/app:cached" \
    -v llm_native_knowledge:/app/data/knowledge \
    -v llm_native_benchmarks:/app/data/benchmarks \
    -v llm_native_results:/app/results \
    -v llm_native_logs:/app/logs \
    -e PYTHONPATH=/app/src:/app \
    -e DEEPSEEK_API_KEY=sk-6b1ae1bdb0e24c0189f0f0e9db43a94a \
    -e LOG_LEVEL=DEBUG \
    --workdir /app \
    llm-native:dev \
    bash

echo "✅ 开发环境已启动！"
echo ""
echo "💡 常用命令："
echo "  # 重新进入容器"
echo "  docker start -i $DEV_CONTAINER_NAME"
echo ""
echo "  # 查看容器状态"
echo "  docker ps"
echo ""
echo "  # 停止环境"
echo "  docker stop $DEV_CONTAINER_NAME $CONTAINER_NAME"
echo "  docker rm $DEV_CONTAINER_NAME $CONTAINER_NAME"
