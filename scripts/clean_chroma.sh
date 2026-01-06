#!/bin/bash
# ChromaDB清理脚本
# 清理旧的Chroma镜像和容器，为重新构建做准备

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

# 主函数
main() {
    echo -e "${BLUE}🧹 ChromaDB清理工具${NC}"
    echo "======================="

    # 停止相关容器
    log_info "停止Chroma相关容器..."
    docker stop llm_native_vector_db llm_native_chroma 2>/dev/null || true

    # 删除相关容器
    log_info "删除Chroma相关容器..."
    docker rm llm_native_vector_db llm_native_chroma 2>/dev/null || true

    # 删除相关镜像
    log_info "删除旧的Chroma镜像..."
    docker rmi chromadb/chroma:latest ghcr.nju.edu.cn/chroma-core/chroma:latest llm-native-chroma:latest 2>/dev/null || true

    # 清理源码目录（可选）
    echo ""
    read -p "是否删除Chroma源码目录（.chroma-repo）？(y/N): " -n 1 -r
    echo ""

    if [[ $REPLY =~ ^[Yy]$ ]]; then
        log_info "删除Chroma源码目录..."
        rm -rf .chroma-repo
        log_success "源码目录已删除"
    fi

    # 清理构建缓存
    log_info "清理Docker构建缓存..."
    docker builder prune -f >/dev/null 2>&1 || true

    log_success "ChromaDB清理完成！"
    echo ""
    echo "现在可以重新运行构建脚本："
    echo "  ./scripts/dev-manual.sh  # 手动模式"
    echo "  ./scripts/dev.sh         # Docker Compose模式"
}

# 执行主函数
main "$@"
