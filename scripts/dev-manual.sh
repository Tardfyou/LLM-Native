#!/bin/bash
# Manual development environment launcher for LLM-Native Framework
# 当docker-compose不可用时的手动启动脚本
# 使用方法: ./scripts/dev-manual.sh [选项]
#
# 选项:
#   (无参数)  - 启动开发环境
#   build     - 强制重新构建镜像
#   clang     - 启动并运行Clang环境测试
#   test      - 检查Clang环境后运行生成引擎测试
#   full      - 运行完整测试套件（Clang + 生成引擎）

set -e

echo -e "\033[94m[INFO]\033[0m Starting LLM-Native development environment manually..."
echo -e "\033[93m[WARNING]\033[0m Note: This script is used when docker-compose is not available"

# 检查Docker是否运行
if ! docker info >/dev/null 2>&1; then
    echo -e "\033[91m[ERROR]\033[0m Docker is not running, please start Docker first"
    exit 1
fi

# 创建必要的目录
mkdir -p data/knowledge data/benchmarks results logs

# 构建镜像（如果需要）
BUILD_REQUESTED=false
if [ "$1" = "build" ] || [ "$2" = "build" ]; then
    BUILD_REQUESTED=true
fi

if [ "$BUILD_REQUESTED" = true ] || ! docker images | grep -q "llm-native"; then
    echo -e "\033[94m[INFO]\033[0m Building development image..."
    docker build -t llm-native:dev .
    echo -e "\033[92m[SUCCESS]\033[0m Image build completed"
else
    echo -e "\033[92m[SUCCESS]\033[0m Image already exists, skipping build"
fi

# 创建网络（如果不存在）
docker network ls | grep -q "llm_native_network" || docker network create llm_native_network

# 启动向量数据库
echo -e "\033[94m[INFO]\033[0m Starting ChromaDB vector database..."
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

echo -e "\033[94m[INFO]\033[0m Waiting for vector database to start..."
sleep 5

# 检查向量数据库是否启动成功
if ! curl -s http://localhost:8001/api/v1/heartbeat >/dev/null; then
    echo -e "\033[93m[WARNING]\033[0m Vector database may have failed to start, but continuing with main container..."
fi

# 启动开发容器
echo -e "\033[94m[INFO]\033[0m Starting development container..."
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
    -v "$PROJECT_ROOT/pretrained_models:/root/.cache/huggingface/hub:cached" \
    -v llm_native_knowledge:/app/data/knowledge \
    -v llm_native_benchmarks:/app/data/benchmarks \
    -v "$PROJECT_ROOT/results:/app/results" \
    -v "$PROJECT_ROOT/logs:/app/logs" \
    -e PYTHONPATH=/app/src:/app \
    -e DEEPSEEK_API_KEY=sk-6b1ae1bdb0e24c0189f0f0e9db43a94a \
    -e LOG_LEVEL=DEBUG \
    -e HF_HUB_CACHE=/root/.cache/huggingface/hub \
    -e TRANSFORMERS_CACHE=/root/.cache/huggingface/hub \
    --workdir /app \
    llm-native:dev \
    bash

echo -e "\033[92m[SUCCESS]\033[0m Development environment has been started!"
echo ""
echo -e "\033[96m[HELP]\033[0m Common commands:"
echo "  # Re-enter container"
echo "  docker start -i $DEV_CONTAINER_NAME"
echo ""
echo "  # Check container status"
echo "  docker ps"
echo ""
echo "  # Stop environment"
echo "  docker stop $DEV_CONTAINER_NAME $CONTAINER_NAME"
echo "  docker rm $DEV_CONTAINER_NAME $CONTAINER_NAME"
echo ""
echo -e "\033[96m[HELP]\033[0m Model download instructions:"
echo "  # Download pretrained models: python3 scripts/download_models.py"
echo "  # Check model status: python3 scripts/check_models.py"
echo "  # Model cache location: ./pretrained_models/"
echo ""
echo -e "\033[96m[HELP]\033[0m Run tests:"
echo "  # Run comprehensive environment test: python3 scripts/test_environment_comprehensive.py"
echo "  # Run Clang environment test: python3 scripts/test_clang_environment.py"
echo "  # Run generator engine test: python3 scripts/test_generator_engine.py basic"

# 根据参数执行测试
if [ "$1" = "clang" ]; then
    echo ""
    echo -e "\033[94m[INFO]\033[0m Running Clang environment test..."
    docker exec $DEV_CONTAINER_NAME python3 scripts/test_clang_environment.py
elif [ "$1" = "test" ]; then
    echo ""
    echo -e "\033[94m[INFO]\033[0m Checking Clang environment and running generator engine test..."
    echo -e "\033[94m[INFO]\033[0m  1. Checking Clang environment..."
    if docker exec $DEV_CONTAINER_NAME python3 scripts/test_clang_environment.py >/dev/null 2>&1; then
        echo -e "\033[92m[SUCCESS]\033[0m  Clang environment is normal"
        echo ""
        echo -e "\033[94m[INFO]\033[0m  2. Running generator engine basic test..."
        docker exec $DEV_CONTAINER_NAME python3 scripts/test_generator_engine.py basic
    else
        echo -e "\033[91m[ERROR]\033[0m  Clang environment abnormal, please rebuild image or check environment configuration"
        echo -e "\033[93m[WARNING]\033[0m  Tip: Use './scripts/dev-manual.sh build' to rebuild"
        exit 1
    fi
elif [ "$1" = "full" ]; then
    echo ""
    echo -e "\033[94m[INFO]\033[0m Running full test suite..."
    echo -e "\033[94m[INFO]\033[0m  1. Clang environment test..."
    if docker exec $DEV_CONTAINER_NAME python3 scripts/test_clang_environment.py; then
        echo -e "\033[92m[SUCCESS]\033[0m  Clang environment test passed"
        echo ""
        echo -e "\033[94m[INFO]\033[0m  2. Generator engine test..."
        docker exec $DEV_CONTAINER_NAME python3 scripts/test_generator_engine.py basic
    else
        echo -e "\033[91m[ERROR]\033[0m  Clang environment test failed, skipping generator engine test"
        echo -e "\033[93m[WARNING]\033[0m  Tip: Use './scripts/dev-manual.sh build' to rebuild"
        exit 1
    fi
fi



