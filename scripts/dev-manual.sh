#!/bin/bash
# Manual development environment launcher for LLM-Native Framework
# 当docker-compose不可用时的手动启动脚本
# 使用方法: ./scripts/dev-manual.sh [选项]
#
# 选项:
#   (无参数)  - 启动开发环境（如容器已存在则直接进入）
#   build     - 强制重新构建镜像
#   rebuild   - 强制重新创建容器
#   clang     - 启动并运行Clang环境测试
#   test      - 检查Clang环境后运行生成引擎测试
#   full      - 运行完整测试套件（Clang + 生成引擎）
#   local     - 在宿主机上直接运行命令（不使用容器）
#   chroma    - 仅启动 ChromaDB 向量数据库服务
#
# 本地运行示例:
#   ./scripts/dev-manual.sh local generate_detector --patch_file tests/simple/null_ptr_dereference.patch
#   ./scripts/dev-manual.sh local --help

set -e

# 获取当前目录的绝对路径
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# === 处理 local 模式（在所有 Docker 操作之前）===
if [ "$1" = "local" ]; then
    echo -e "\033[94m[INFO]\033[0m Running in local mode (on host machine)..."

    # 检查 Python
    if ! command -v python3 &> /dev/null; then
        echo -e "\033[91m[ERROR]\033[0m Python3 not found"
        exit 1
    fi

    # 设置环境变量
    export LLM_NATIVE_ROOT="$PROJECT_ROOT"
    export PYTHONPATH="$PROJECT_ROOT/src:$PROJECT_ROOT"

    # 检查 ChromaDB 是否可用
    if curl -s http://localhost:8001/api/v1/heartbeat > /dev/null 2>&1; then
        echo -e "\033[92m[INFO]\033[0m ChromaDB server detected on port 8001"
        export CHROMA_HOST=localhost
        export CHROMA_PORT=8001
    else
        echo -e "\033[93m[INFO]\033[0m ChromaDB server not available, using local persistence mode"
    fi

    # 加载 .env 文件（如果存在）
    if [ -f "$PROJECT_ROOT/.env" ]; then
        echo -e "\033[94m[INFO]\033[0m Loading environment from .env"
        export $(grep -v '^#' "$PROJECT_ROOT/.env" | xargs)
    fi

    # 获取要运行的命令（移除 "local" 参数）
    shift

    # 如果没有提供命令，显示帮助
    if [ -z "$1" ]; then
        echo -e "\033[94m[INFO]\033[0m No command specified. Available commands:"
        echo "  generate_detector  - Generate a static analysis detector"
        echo "  validate_detector  - Validate a generated detector"
        echo "  knowledge_search   - Search the knowledge base"
        echo "  triage_report      - Classify a report as TP/FP"
        echo "  refine_detector    - Refine a detector to reduce false positives"
        echo "  api_server         - Start the API server"
        echo ""
        echo "Example:"
        echo "  ./scripts/dev-manual.sh local generate_detector --patch_file tests/simple/null_ptr_dereference.patch"
        echo ""
        echo "Run with --help for more options:"
        echo "  ./scripts/dev-manual.sh local --help"
        exit 0
    fi

    # 运行命令
    echo -e "\033[94m[INFO]\033[0m Running: python3 src/main.py $@"
    cd "$PROJECT_ROOT"
    python3 src/main.py "$@"
    exit $?
fi

# === 处理 chroma 模式（在所有 Docker 操作之前）===
if [ "$1" = "chroma" ]; then
    echo -e "\033[94m[INFO]\033[0m Starting ChromaDB vector database only..."
    CONTAINER_NAME="llm_native_chroma_standalone"

    # 检查 Docker
    if ! command -v docker &> /dev/null; then
        echo -e "\033[91m[ERROR]\033[0m Docker not found"
        exit 1
    fi

    # 检查是否已在运行
    if docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
        echo -e "\033[92m[SUCCESS]\033[0m ChromaDB is already running"
        echo "Container: $CONTAINER_NAME"
        echo "Port: 8001"
        exit 0
    fi

    # 检查是否存在已停止的容器
    if docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
        echo -e "\033[94m[INFO]\033[0m Starting existing ChromaDB container..."
        docker start $CONTAINER_NAME
    else
        echo -e "\033[94m[INFO]\033[0m Creating new ChromaDB container..."
        docker run -d \
            --name $CONTAINER_NAME \
            -p 8001:8000 \
            -v llm_native_chroma_data:/chroma/chroma \
            chromadb/chroma:latest
    fi

    # 等待服务启动
    echo -e "\033[94m[INFO]\033[0m Waiting for ChromaDB to start..."
    sleep 5

    # 检查服务是否可用
    if curl -s http://localhost:8001/api/v1/heartbeat > /dev/null 2>&1; then
        echo -e "\033[92m[SUCCESS]\033[0m ChromaDB is running on port 8001"
        echo ""
        echo "To stop: docker stop $CONTAINER_NAME"
        echo "To use: export CHROMA_HOST=localhost CHROMA_PORT=8001"
    else
        echo -e "\033[91m[ERROR]\033[0m ChromaDB failed to start"
        exit 1
    fi
    exit 0
fi

echo -e "\033[94m[INFO]\033[0m Starting LLM-Native development environment manually..."
echo -e "\033[93m[WARNING]\033[0m Note: This script is used when docker-compose is not available"

# 检查Docker是否运行（对于非 local/chroma 模式）
if ! docker info >/dev/null 2>&1; then
    echo -e "\033[91m[ERROR]\033[0m Docker is not running, please start Docker first"
    echo -e "\033[93m[TIP]\033[0m For running without Docker, use: ./scripts/dev-manual.sh local <command>"
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

# 检查是否需要重新创建容器
REBUILD_CONTAINER=false
if [ "$1" = "rebuild" ] || [ "$2" = "rebuild" ]; then
    REBUILD_CONTAINER=true
fi

# 检查容器是否已存在
CONTAINER_EXISTS=false
if docker ps -a --format '{{.Names}}' | grep -q "^${DEV_CONTAINER_NAME}$"; then
    CONTAINER_EXISTS=true
fi

if [ "$CONTAINER_EXISTS" = true ] && [ "$REBUILD_CONTAINER" = false ]; then
    echo -e "\033[92m[INFO]\033[0m Container '$DEV_CONTAINER_NAME' already exists, attaching to it..."
    echo -e "\033[93m[TIP]\033[0m Use './scripts/dev-manual.sh rebuild' to recreate the container"
    docker start -i $DEV_CONTAINER_NAME
elif [ "$CONTAINER_EXISTS" = true ] && [ "$REBUILD_CONTAINER" = true ]; then
    echo -e "\033[93m[INFO]\033[0m Removing existing container '$DEV_CONTAINER_NAME'..."
    docker rm -f $DEV_CONTAINER_NAME 2>/dev/null || true
    echo -e "\033[92m[INFO]\033[0m Creating new container '$DEV_CONTAINER_NAME'..."
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
else
    echo -e "\033[92m[INFO]\033[0m Creating new container '$DEV_CONTAINER_NAME'..."
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
fi

echo -e "\033[92m[SUCCESS]\033[0m Development environment has been started!"
echo ""
echo -e "\033[96m[HELP]\033[0m Common commands:"
echo "  # Re-enter container (same as running this script again)"
echo "  docker start -i $DEV_CONTAINER_NAME"
echo "  ./scripts/dev-manual.sh"
echo ""
echo "  # Check container status"
echo "  docker ps -a | grep $DEV_CONTAINER_NAME"
echo ""
echo "  # Recreate container (if needed)"
echo "  ./scripts/dev-manual.sh rebuild"
echo ""
echo "  # Stop environment (keeps container for later use)"
echo "  docker stop $DEV_CONTAINER_NAME $CONTAINER_NAME"
echo ""
echo "  # Remove containers (clean up - use only if needed)"
echo "  docker rm -f $DEV_CONTAINER_NAME $CONTAINER_NAME"
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
if [ "$1" = "clang" ] || [ "$2" = "clang" ]; then
    echo ""
    echo -e "\033[94m[INFO]\033[0m Running Clang environment test..."
    # 确保容器正在运行
    if ! docker ps --format '{{.Names}}' | grep -q "^${DEV_CONTAINER_NAME}$"; then
        echo -e "\033[93m[INFO]\033[0m Starting container..."
        docker start $DEV_CONTAINER_NAME >/dev/null 2>&1
    fi
    docker exec $DEV_CONTAINER_NAME python3 scripts/test_clang_environment.py
elif [ "$1" = "test" ] || [ "$2" = "test" ]; then
    echo ""
    echo -e "\033[94m[INFO]\033[0m Checking Clang environment and running generator engine test..."
    echo -e "\033[94m[INFO]\033[0m  1. Checking Clang environment..."
    # 确保容器正在运行
    if ! docker ps --format '{{.Names}}' | grep -q "^${DEV_CONTAINER_NAME}$"; then
        echo -e "\033[93m[INFO]\033[0m Starting container..."
        docker start $DEV_CONTAINER_NAME >/dev/null 2>&1
    fi
    if docker exec $DEV_CONTAINER_NAME python3 scripts/test_clang_environment.py >/dev/null 2>&1; then
        echo -e "\033[92m[SUCCESS]\033[0m  Clang environment is normal"
        echo ""
        echo -e "\033[94m[INFO]\033[0m  2. Running generator engine basic test..."
        docker exec $DEV_CONTAINER_NAME python3 scripts/test_generator_engine.py basic
    else
        echo -e "\033[91m[ERROR]\033[0m  Clang environment abnormal, please rebuild image or check environment configuration"
        echo -e "\033[93m[WARNING]\033[0m  Tip: Use './scripts/dev-manual.sh build' to rebuild image"
        echo -e "\033[93m[WARNING]\033[0m  Tip: Use './scripts/dev-manual.sh rebuild' to recreate container"
        exit 1
    fi
elif [ "$1" = "full" ] || [ "$2" = "full" ]; then
    echo ""
    echo -e "\033[94m[INFO]\033[0m Running full test suite..."
    echo -e "\033[94m[INFO]\033[0m  1. Clang environment test..."
    # 确保容器正在运行
    if ! docker ps --format '{{.Names}}' | grep -q "^${DEV_CONTAINER_NAME}$"; then
        echo -e "\033[93m[INFO]\033[0m Starting container..."
        docker start $DEV_CONTAINER_NAME >/dev/null 2>&1
    fi
    if docker exec $DEV_CONTAINER_NAME python3 scripts/test_clang_environment.py; then
        echo -e "\033[92m[SUCCESS]\033[0m  Clang environment test passed"
        echo ""
        echo -e "\033[94m[INFO]\033[0m  2. Generator engine test..."
        docker exec $DEV_CONTAINER_NAME python3 scripts/test_generator_engine.py basic
    else
        echo -e "\033[91m[ERROR]\033[0m  Clang environment test failed, skipping generator engine test"
        echo -e "\033[93m[WARNING]\033[0m  Tip: Use './scripts/dev-manual.sh build' to rebuild image"
        echo -e "\033[93m[WARNING]\033[0m  Tip: Use './scripts/dev-manual.sh rebuild' to recreate container"
        exit 1
    fi
elif [ "$1" = "local" ]; then
    # === 本地模式：在宿主机上直接运行 ===
    echo -e "\033[94m[INFO]\033[0m Running in local mode (on host machine)..."

    # 检查 Python
    if ! command -v python3 &> /dev/null; then
        echo -e "\033[91m[ERROR]\033[0m Python3 not found"
        exit 1
    fi

    # 设置环境变量
    export LLM_NATIVE_ROOT="$PROJECT_ROOT"
    export PYTHONPATH="$PROJECT_ROOT/src:$PROJECT_ROOT"

    # 检查 ChromaDB 是否可用
    if curl -s http://localhost:8001/api/v1/heartbeat > /dev/null 2>&1; then
        echo -e "\033[92m[INFO]\033[0m ChromaDB server detected on port 8001"
        export CHROMA_HOST=localhost
        export CHROMA_PORT=8001
    else
        echo -e "\033[93m[INFO]\033[0m ChromaDB server not available, using local persistence mode"
    fi

    # 加载 .env 文件（如果存在）
    if [ -f "$PROJECT_ROOT/.env" ]; then
        echo -e "\033[94m[INFO]\033[0m Loading environment from .env"
        export $(grep -v '^#' "$PROJECT_ROOT/.env" | xargs)
    fi

    # 获取要运行的命令（移除 "local" 参数）
    shift

    # 如果没有提供命令，显示帮助
    if [ -z "$1" ]; then
        echo -e "\033[94m[INFO]\033[0m No command specified. Available commands:"
        echo "  generate_detector  - Generate a static analysis detector"
        echo "  validate_detector  - Validate a generated detector"
        echo "  knowledge_search   - Search the knowledge base"
        echo "  triage_report      - Classify a report as TP/FP"
        echo "  refine_detector    - Refine a detector to reduce false positives"
        echo "  api_server         - Start the API server"
        echo ""
        echo "Example:"
        echo "  ./scripts/dev-manual.sh local generate_detector --patch_file tests/simple/null_ptr_dereference.patch"
        echo ""
        echo "Run with --help for more options:"
        echo "  ./scripts/dev-manual.sh local --help"
        exit 0
    fi

    # 运行命令
    echo -e "\033[94m[INFO]\033[0m Running: python3 src/main.py $@"
    cd "$PROJECT_ROOT"
    python3 src/main.py "$@"
    exit $?

elif [ "$1" = "chroma" ]; then
    # === 仅启动 ChromaDB ===
    echo -e "\033[94m[INFO]\033[0m Starting ChromaDB vector database only..."
    CONTAINER_NAME="llm_native_chroma_standalone"

    # 检查是否已在运行
    if docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
        echo -e "\033[92m[SUCCESS]\033[0m ChromaDB is already running"
        echo "Container: $CONTAINER_NAME"
        echo "Port: 8001"
        exit 0
    fi

    # 检查是否存在已停止的容器
    if docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
        echo -e "\033[94m[INFO]\033[0m Starting existing ChromaDB container..."
        docker start $CONTAINER_NAME
    else
        echo -e "\033[94m[INFO]\033[0m Creating new ChromaDB container..."
        docker run -d \
            --name $CONTAINER_NAME \
            -p 8001:8000 \
            -v llm_native_chroma_data:/chroma/chroma \
            chromadb/chroma:latest
    fi

    # 等待服务启动
    echo -e "\033[94m[INFO]\033[0m Waiting for ChromaDB to start..."
    sleep 5

    # 检查服务是否可用
    if curl -s http://localhost:8001/api/v1/heartbeat > /dev/null 2>&1; then
        echo -e "\033[92m[SUCCESS]\033[0m ChromaDB is running on port 8001"
        echo ""
        echo "To stop: docker stop $CONTAINER_NAME"
        echo "To use: export CHROMA_HOST=localhost CHROMA_PORT=8001"
    else
        echo -e "\033[91m[ERROR]\033[0m ChromaDB failed to start"
        exit 1
    fi
fi



