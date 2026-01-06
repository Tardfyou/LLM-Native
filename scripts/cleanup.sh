#!/bin/bash
# Cleanup script for LLM-Native Framework development environment
# 清理LLM-Native开发环境
# 使用方法: ./scripts/cleanup.sh

# 脚本配置
set -o pipefail

# 全局变量
DOCKER_COMPOSE_CMD=""
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 日志函数
log_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

log_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

log_error() {
    echo -e "${RED}❌ $1${NC}"
}

# 检查Docker
check_docker() {
    if ! docker info >/dev/null 2>&1; then
        log_error "Docker未运行，无法清理"
        exit 1
    fi

    # 检查Docker Compose
    if command -v docker-compose >/dev/null 2>&1; then
        DOCKER_COMPOSE_CMD="docker-compose"
    elif docker compose version >/dev/null 2>&1 2>/dev/null; then
        DOCKER_COMPOSE_CMD="docker compose"
    fi
}

# 停止服务
stop_services() {
    log_info "停止运行中的服务..."

    # 停止Docker Compose服务（如果可用）
    if [[ -n "$DOCKER_COMPOSE_CMD" ]] && [[ -f "docker-compose.yml" ]]; then
        $DOCKER_COMPOSE_CMD --profile dev down 2>/dev/null || true
        $DOCKER_COMPOSE_CMD --profile test down 2>/dev/null || true
        log_success "Docker Compose服务已停止"
    fi

    # 停止遗留容器
    docker stop llm_native_dev llm_native_vector_db 2>/dev/null || true
    docker rm llm_native_dev llm_native_vector_db 2>/dev/null || true
    log_success "遗留容器已清理"
}

# 清理网络
cleanup_networks() {
    log_info "清理Docker网络..."
    docker network rm llm_native_network 2>/dev/null || true
    log_success "网络清理完成"
}

# 清理数据卷
cleanup_volumes() {
    log_info "清理数据卷..."
    docker volume rm llm_native_vector_data llm_native_knowledge llm_native_benchmarks llm_native_results llm_native_logs 2>/dev/null || true
    log_success "数据卷清理完成"
}

# 清理镜像
cleanup_images() {
    log_info "清理Docker镜像..."
    docker rmi llm-native:dev 2>/dev/null || true
    log_success "镜像清理完成"
}

# 清理临时文件
cleanup_temp_files() {
    log_info "清理临时文件..."

    # 清理__pycache__目录
    find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true

    # 清理.pytest_cache
    rm -rf .pytest_cache 2>/dev/null || true

    # 清理Python字节码文件
    find . -name "*.pyc" -delete 2>/dev/null || true
    find . -name "*.pyo" -delete 2>/dev/null || true

    log_success "临时文件清理完成"
}

# 深度清理
deep_cleanup() {
    log_warning "执行深度清理（这将删除所有相关的Docker资源）"
    echo ""

    read -p "确定要执行深度清理吗？这将删除所有相关的容器、镜像和数据卷 (y/N): " -n 1 -r
    echo ""

    if [[ $REPLY =~ ^[Yy]$ ]]; then
        log_info "执行深度清理..."

        # Docker系统清理
        docker system prune -f
        docker volume prune -f
        docker network prune -f

        log_success "深度清理完成"
    else
        log_info "跳过深度清理"
    fi
}

# 显示清理状态
show_status() {
    echo ""
    log_success "清理完成！"
    echo ""
    echo -e "${BLUE}📊 当前状态：${NC}"

    echo "容器:"
    docker ps -a --filter "name=llm_native" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

    echo ""
    echo "数据卷:"
    docker volume ls --filter "name=llm_native" --format "table {{.Name}}"

    echo ""
    echo "网络:"
    docker network ls --filter "name=llm_native" --format "table {{.Name}}\t{{.Driver}}"

    echo ""
    echo "磁盘使用:"
    docker system df
}

# 显示帮助信息
show_help() {
    echo "LLM-Native环境清理脚本"
    echo ""
    echo "用法:"
    echo "  ./scripts/cleanup.sh              # 标准清理"
    echo "  ./scripts/cleanup.sh --deep       # 深度清理"
    echo "  ./scripts/cleanup.sh --help       # 显示帮助"
    echo ""
    echo "清理内容:"
    echo "  - 停止并删除运行中的容器"
    echo "  - 删除相关的数据卷和网络"
    echo "  - 清理临时文件和缓存"
    echo "  - 可选：深度清理Docker系统资源"
}

# 主函数
main() {
    local deep_clean=false

    # 解析命令行参数
    while [[ $# -gt 0 ]]; do
        case $1 in
            --deep)
                deep_clean=true
                shift
                ;;
            --help)
                show_help
                exit 0
                ;;
            *)
                log_error "未知参数: $1"
                show_help
                exit 1
                ;;
        esac
    done

    echo -e "${BLUE}🧹 清理LLM-Native开发环境...${NC}"
    echo ""

    # 检查Docker
    check_docker

    # 执行清理步骤
    stop_services
    cleanup_networks
    cleanup_volumes
    cleanup_images
    cleanup_temp_files

    # 可选深度清理
    if [[ "$deep_clean" == true ]]; then
        deep_cleanup
    fi

    # 显示状态
    show_status

    echo ""
    log_success "清理完成！您可以重新运行开发环境。"
    echo -e "${BLUE}💡 重新启动环境：${NC}"
    echo "  ./scripts/dev.sh        # 使用Docker Compose"
    echo "  ./scripts/dev-manual.sh # 手动启动"
}

# 检查是否在项目根目录
if [[ ! -f "Dockerfile" ]] || [[ ! -d "src" ]]; then
    log_error "请在LLM-Native项目根目录下运行此脚本"
    exit 1
fi

# 执行主函数
main "$@"
