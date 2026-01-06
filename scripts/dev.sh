#!/bin/bash
# Development environment launcher for LLM-Native Framework
# 使用方法: ./scripts/dev.sh

set -e

echo "🚀 启动LLM-Native开发环境..."

# 检查Docker是否运行
if ! docker info >/dev/null 2>&1; then
    echo "❌ Docker未运行，请先启动Docker"
    exit 1
fi

# 检查Docker Compose命令
DOCKER_COMPOSE_CMD=""
if command -v docker-compose >/dev/null 2>&1; then
    DOCKER_COMPOSE_CMD="docker-compose"
    echo "✅ 使用 docker-compose 命令"
elif docker compose version >/dev/null 2>&1 2>/dev/null; then
    DOCKER_COMPOSE_CMD="docker compose"
    echo "✅ 使用 docker compose 命令 (新版本)"
else
    echo "❌ Docker Compose未安装或不可用"
    echo ""
    echo "💡 安装方法："
    echo "   方法1 - 安装插件（推荐）:"
    echo "   sudo apt-get update && sudo apt-get install docker-compose-plugin"
    echo ""
    echo "   方法2 - 安装独立版本:"
    echo "   sudo curl -L \"https://github.com/docker/compose/releases/download/v2.24.0/docker-compose-\$(uname -s)-\$(uname -m)\" -o /usr/local/bin/docker-compose"
    echo "   sudo chmod +x /usr/local/bin/docker-compose"
    echo ""
    echo "   方法3 - 使用Python pip安装:"
    echo "   sudo pip3 install docker-compose"
    echo ""
    echo "🔄 或者使用手动启动脚本（无需docker-compose）:"
    echo "   ./scripts/dev-manual.sh"
    echo ""
    echo "安装完成后重新运行此脚本。"
    exit 1
fi

# 创建必要的目录
mkdir -p data/knowledge data/benchmarks results logs

# 启动开发环境
echo "🐳 启动向量数据库..."
$DOCKER_COMPOSE_CMD --profile dev up -d vector-db

echo "⏳ 等待向量数据库启动..."
sleep 5

echo "🏗️ 启动开发容器..."
$DOCKER_COMPOSE_CMD --profile dev up dev

echo "✅ 开发环境已启动！"
echo ""
echo "💡 常用命令："
echo "  # 在容器内运行命令"
echo "  $DOCKER_COMPOSE_CMD --profile dev exec dev bash"
echo ""
echo "  # 运行生成器测试"
echo "  $DOCKER_COMPOSE_CMD --profile dev exec dev python3 src/main.py generate_detector --vulnerability_desc '测试缓冲区溢出' --target_framework codeql"
echo ""
echo "  # 查看日志"
echo "  $DOCKER_COMPOSE_CMD --profile dev logs -f"
echo ""
echo "  # 停止环境"
echo "  $DOCKER_COMPOSE_CMD --profile dev down"
