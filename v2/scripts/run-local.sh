#!/bin/bash

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

CHROMA_CONTAINER_NAME="llm_native_chroma"
CHROMA_PORT=8001
CHROMA_IMAGE="chromadb/chroma:latest"
CHROMA_VOLUME="llm_native_chroma_data"
DOCKER_CMD="docker"

info() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[OK]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }

init_docker_cmd() {
    if sudo -n true >/dev/null 2>&1; then
        DOCKER_CMD="sudo docker"
    fi
}

wait_for_docker() {
    local attempt
    for attempt in $(seq 1 15); do
        if $DOCKER_CMD info >/dev/null 2>&1; then
            return 0
        fi
        sleep 2
    done

    error "Docker 服务重启后未就绪"
    return 1
}

check_chroma_health() {
    local url
    for url in \
        "http://localhost:${CHROMA_PORT}/api/v2/heartbeat" \
        "http://localhost:${CHROMA_PORT}/api/v1/heartbeat" \
        "http://localhost:${CHROMA_PORT}/api/v2" \
        "http://localhost:${CHROMA_PORT}/"; do
        if curl -fsS --max-time 5 "$url" >/dev/null 2>&1; then
            return 0
        fi
    done
    return 1
}

show_help() {
    cat <<'EOF'
用法:
  ./run-local.sh
  ./run-local.sh --start-chroma
  ./run-local.sh --help

功能:
  1. 重启 Docker 服务
  2. 启动 ChromaDB 容器
  3. ChromaDB 就绪后自动执行知识库导入
EOF
}

restart_docker() {
    info "重启 Docker 服务..."
    init_docker_cmd

    if command -v systemctl >/dev/null 2>&1; then
        sudo systemctl restart docker
    elif command -v service >/dev/null 2>&1; then
        sudo service docker restart
    else
        error "未找到 systemctl 或 service，无法重启 Docker"
        return 1
    fi

    wait_for_docker

    success "Docker 服务已重启"
}

start_chroma() {
    info "启动 ChromaDB 服务..."

    if ! command -v docker >/dev/null 2>&1; then
        error "未安装 Docker"
        return 1
    fi

    restart_docker
    init_docker_cmd

    if $DOCKER_CMD ps -a --format '{{.Names}}' | grep -q "^${CHROMA_CONTAINER_NAME}$"; then
        $DOCKER_CMD rm -f "$CHROMA_CONTAINER_NAME" >/dev/null 2>&1 || true
    fi

    $DOCKER_CMD run -d \
        --name "$CHROMA_CONTAINER_NAME" \
        -p "$CHROMA_PORT:8000" \
        -v "$CHROMA_VOLUME:/chroma/chroma" \
        "$CHROMA_IMAGE" >/dev/null

    local attempt
    for attempt in $(seq 1 20); do
        if check_chroma_health; then
            success "ChromaDB 启动成功 (端口 ${CHROMA_PORT})"
            import_knowledge
            return 0
        fi
        sleep 2
    done

    error "ChromaDB 启动失败，请检查 Docker 日志"
    $DOCKER_CMD ps -a --filter "name=${CHROMA_CONTAINER_NAME}" --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}' || true
    $DOCKER_CMD logs --tail 100 "$CHROMA_CONTAINER_NAME" 2>&1 || true
    return 1
}

import_knowledge() {
    local project_root import_script
    project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    import_script="${project_root}/scripts/import_knowledge.py"

    if [[ ! -f "${import_script}" ]]; then
        error "知识库导入脚本不存在: ${import_script}"
        return 1
    fi

    info "执行知识库导入..."
    (
        cd "${project_root}"
        python3 "${import_script}"
    )
    success "知识库导入完成"
}

main() {
    case "${1:-}" in
        ""|--start-chroma|--start-chromadb)
            start_chroma
            ;;
        --help|-h)
            show_help
            ;;
        *)
            error "未知选项: $1"
            show_help
            return 1
            ;;
    esac
}

main "$@"
