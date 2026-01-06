#!/bin/bash
# Network diagnostics script for LLM-Native Framework
# 网络诊断脚本，帮助排查Docker构建时的网络问题
# 支持自动重启Docker服务，修复网络配置问题

# 设置信号处理
trap 'echo -e "\n\033[0;31m❌ 诊断被用户中断\033[0m"; exit 130' INT TERM

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

# 检查Docker状态
check_docker() {
    log_info "检查Docker状态..."
    if ! docker info >/dev/null 2>&1; then
        log_error "Docker未运行"

        echo ""
        read -p "是否要启动Docker服务？(y/N): " -n 1 -r
        echo ""

        if [[ $REPLY =~ ^[Yy]$ ]]; then
            log_info "正在启动Docker服务..."
            if sudo systemctl start docker; then
                log_success "Docker服务启动成功"

                # 等待Docker启动完成
                log_info "等待Docker初始化..."
                local count=0
                while [ $count -lt 10 ]; do
                    if docker info >/dev/null 2>&1; then
                        log_success "Docker初始化完成"
                        return 0
                    fi
                    sleep 1
                    ((count++))
                done

                log_error "Docker启动超时，请手动检查"
                return 1
            else
                log_error "Docker服务启动失败"
                log_info "请手动运行: sudo systemctl start docker"
                return 1
            fi
        else
            log_info "跳过Docker启动，请手动运行: sudo systemctl start docker"
            return 1
        fi
    fi
    log_success "Docker运行正常"
}

# 检查网络连接
check_network() {
    log_info "检查网络连接..."

    # 测试基本网络连接
    if ! ping -c 1 8.8.8.8 >/dev/null 2>&1; then
        log_error "无法连接到互联网"
        return 1
    fi
    log_success "基本网络连接正常"

    # 测试DNS解析
    if ! nslookup google.com >/dev/null 2>&1; then
        log_warning "DNS解析可能有问题"
    else
        log_success "DNS解析正常"
    fi

    # 测试Ubuntu软件源连接
    log_info "测试Ubuntu软件源连接..."
    if curl -s --connect-timeout 10 http://archive.ubuntu.com/ >/dev/null; then
        log_success "Ubuntu官方源可访问"
    else
        log_warning "Ubuntu官方源无法访问，Docker构建可能会失败"
    fi

    # 测试阿里云镜像源
    if curl -s --connect-timeout 10 http://mirrors.aliyun.com/ >/dev/null; then
        log_success "阿里云镜像源可访问"
    else
        log_warning "阿里云镜像源无法访问"
    fi

    # 测试清华大学镜像源
    if curl -s --connect-timeout 10 https://mirrors.tuna.tsinghua.edu.cn/ >/dev/null; then
        log_success "清华大学镜像源可访问"
    else
        log_warning "清华大学镜像源无法访问"
    fi

    # 测试Docker Hub连接
    if curl -s --connect-timeout 10 https://registry-1.docker.io/v2/ >/dev/null; then
        log_success "Docker Hub可访问"
    else
        log_warning "Docker Hub无法访问，镜像拉取可能会失败"
    fi

    # 测试Docker Hub认证服务
    if curl -s --connect-timeout 10 https://auth.docker.io/token >/dev/null; then
        log_success "Docker Hub认证服务可访问"
    else
        log_warning "Docker Hub认证服务无法访问"
    fi
}

# 检查Docker网络
check_docker_network() {
    log_info "检查Docker网络配置..."

    # 检查Docker网络驱动
    if docker network ls >/dev/null 2>&1; then
        log_success "Docker网络功能正常"
    else
        log_error "Docker网络功能异常"
        return 1
    fi

    # 尝试创建一个测试网络
    TEST_NETWORK="llm_native_test_network"
    if docker network create "$TEST_NETWORK" >/dev/null 2>&1; then
        log_success "可以创建Docker网络"
        docker network rm "$TEST_NETWORK" >/dev/null 2>&1
    else
        log_error "无法创建Docker网络"
        return 1
    fi
}

# 测试Docker构建
test_docker_build() {
    log_info "测试Docker镜像构建..."

    # 创建一个最简单的测试Dockerfile
    cat > Dockerfile.test << 'EOF'
FROM alpine:latest
RUN echo "Hello from Docker"
EOF

    # 尝试构建
    if docker build -f Dockerfile.test -t llm-native-test . >/dev/null 2>&1; then
        log_success "Docker构建功能正常"
        # 清理测试镜像
        docker rmi llm-native-test >/dev/null 2>&1
    else
        log_error "Docker构建功能异常"
        return 1
    fi

    # 清理测试文件
    rm -f Dockerfile.test
}

# 提供解决方案
provide_solutions() {
    echo ""
    log_info "🔧 网络问题解决方案："
    echo ""

    echo "1. 检查网络连接："
    echo "   ping 8.8.8.8"
    echo ""

    echo "2. 检查DNS配置："
    echo "   cat /etc/resolv.conf"
    echo "   如果DNS配置有问题，可以临时修改："
    echo "   echo 'nameserver 8.8.8.8' > /etc/resolv.conf"
    echo ""

    echo "3. 如果在中国大陆，尝试使用镜像源："
    echo "   脚本已经配置了自动回退机制"
    echo ""

    echo "4. 检查防火墙设置："
    echo "   sudo ufw status"
    echo "   或临时关闭防火墙测试：sudo ufw disable"
    echo ""

    echo "5. 手动指定DNS服务器："
    echo "   --dns 8.8.8.8 --dns 8.8.4.4"
    echo ""

    echo "6. 使用VPN或代理："
    echo "   如果网络环境受限，考虑使用VPN"
    echo ""

    echo "7. 离线构建："
    echo "   下载所需的包到本地，然后COPY到镜像中"
    echo ""

    log_info "💡 推荐的解决步骤："
    echo "1. 首先检查网络连接和DNS配置"
    echo "2. 如果网络正常但Ubuntu源无法访问，脚本会自动使用镜像源"
    echo "3. 如果所有方法都失败，可以考虑使用更简单的base镜像"
}

# 主函数
main() {
    echo -e "${BLUE}🔍 LLM-Native网络诊断工具${NC}"
    echo "=================================="
    echo "这个工具会自动检查和修复网络及Docker环境问题"
    echo ""
    echo -e "${BLUE}检查项目：${NC}"
    echo "  ✅ Docker运行状态（支持自动重启）"
    echo "  ✅ 网络连接情况"
    echo "  ✅ DNS解析功能"
    echo "  ✅ Ubuntu软件源可访问性"
    echo "  ✅ Docker网络功能"
    echo "  ✅ Docker构建功能"
    echo ""

    local all_passed=true

    # 执行各项检查
    check_docker && echo "" || all_passed=false
    check_network && echo "" || all_passed=false
    check_docker_network && echo "" || all_passed=false
    test_docker_build && echo "" || all_passed=false

    # 输出总结
    echo "=================================="
    if [[ "$all_passed" == true ]]; then
        log_success "所有检查通过！网络环境正常。"
        log_info "现在可以尝试运行：./scripts/dev-manual.sh"
    else
        log_warning "发现网络或Docker配置问题。"
        provide_solutions
    fi
}

# 检查是否在项目根目录
if [[ ! -f "Dockerfile" ]] || [[ ! -d "src" ]]; then
    log_error "请在LLM-Native项目根目录下运行此脚本"
    exit 1
fi

# 执行主函数
main "$@"
