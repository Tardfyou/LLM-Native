#!/bin/bash
# LLVM Checker Generator v2 - 环境设置脚本

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

INSTALL_CODEQL=false
CODEQL_VERSION="${CODEQL_VERSION:-2.23.5}"
CODEQL_INSTALL_DIR="${CODEQL_INSTALL_DIR:-/opt/codeql}"
CODEQL_LINK_PATH="${CODEQL_LINK_PATH:-/usr/local/bin/codeql}"

while [[ $# -gt 0 ]]; do
	case "$1" in
		--install-codeql)
			INSTALL_CODEQL=true
			shift
			;;
		-h|--help)
			echo "用法: $0 [--install-codeql]"
			echo ""
			echo "选项:"
			echo "  --install-codeql   自动下载安装 CodeQL CLI 到 $CODEQL_INSTALL_DIR，并链接到 $CODEQL_LINK_PATH"
			exit 0
			;;
		*)
			echo "未知参数: $1"
			exit 1
			;;
	esac
done

echo "=========================================="
echo "LLVM Checker Generator v2 - 环境设置"
echo "=========================================="
echo "项目目录: $PROJECT_DIR"

cd "$PROJECT_DIR"

get_compose_cmd() {
	if docker compose version >/dev/null 2>&1; then
		echo "docker compose"
	elif command -v docker-compose >/dev/null 2>&1; then
		echo "docker-compose"
	else
		echo ""
	fi
}

download_file() {
	local url="$1"
	local dest="$2"

	if command -v curl >/dev/null 2>&1; then
		curl -L --fail "$url" -o "$dest"
	elif command -v wget >/dev/null 2>&1; then
		wget -O "$dest" "$url"
	else
		echo "错误: 需要 curl 或 wget 之一来下载文件"
		exit 1
	fi
}

extract_zip() {
	local archive="$1"
	local dest="$2"

	if command -v unzip >/dev/null 2>&1; then
		unzip -q "$archive" -d "$dest"
	else
		python3 - <<'PY' "$archive" "$dest"
import sys
import zipfile

archive, dest = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(archive) as zf:
    zf.extractall(dest)
PY
	fi
}

require_sudo_if_needed() {
	local target_dir="$1"
	local target_link="$2"

	if [ -w "$(dirname "$target_dir")" ] && [ -w "$(dirname "$target_link")" ]; then
		return 0
	fi

	if ! command -v sudo >/dev/null 2>&1; then
		echo "错误: 需要 sudo 权限安装到 $target_dir 和 $target_link"
		exit 1
	fi

	if ! sudo -n true >/dev/null 2>&1; then
		echo "错误: 需要 sudo 权限，请先执行 sudo -v 后重试"
		exit 1
	fi
}

install_codeql_cli() {
	echo ""
	echo "安装 CodeQL CLI..."

	local archive_name="codeql-linux64.zip"
	local download_url="https://github.com/github/codeql-cli-binaries/releases/download/v${CODEQL_VERSION}/${archive_name}"
	local tmp_dir
	tmp_dir=$(mktemp -d)
	trap 'rm -rf "$tmp_dir"' RETURN

	require_sudo_if_needed "$CODEQL_INSTALL_DIR" "$CODEQL_LINK_PATH"

	echo " - 下载: $download_url"
	download_file "$download_url" "$tmp_dir/$archive_name"

	echo " - 解压安装包"
	rm -rf "$tmp_dir/extract"
	mkdir -p "$tmp_dir/extract"
	extract_zip "$tmp_dir/$archive_name" "$tmp_dir/extract"

	if [ ! -d "$tmp_dir/extract/codeql" ]; then
		echo "错误: 安装包中未找到 codeql 目录"
		exit 1
	fi

	echo " - 安装到 $CODEQL_INSTALL_DIR"
	sudo rm -rf "$CODEQL_INSTALL_DIR"
	sudo mv "$tmp_dir/extract/codeql" "$CODEQL_INSTALL_DIR"
	sudo chmod +x "$CODEQL_INSTALL_DIR/codeql"
	sudo ln -sf "$CODEQL_INSTALL_DIR/codeql" "$CODEQL_LINK_PATH"

	mkdir -p "$PROJECT_DIR/codeql_dbs" "$PROJECT_DIR/codeql_packs"
	if [ ! -f "$PROJECT_DIR/codeql_packs/qlpack.yml" ]; then
		cat > "$PROJECT_DIR/codeql_packs/qlpack.yml" <<'EOF'
name: local/custom-queries
version: 0.0.1
dependencies:
  codeql/cpp-all: '*'
extractor: cpp
EOF
	fi

	if command -v codeql >/dev/null 2>&1; then
		echo " - CodeQL 安装成功: $(codeql version | head -1)"
	else
		echo "错误: CodeQL 安装后仍不可用"
		exit 1
	fi
}

# 检查Python版本
PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
echo "Python版本: $PYTHON_VERSION"

# 安装依赖
echo ""
echo "安装 Python 依赖..."
python3 -m pip install -r requirements.txt

# 可选安装 CodeQL
if [ "$INSTALL_CODEQL" = true ]; then
	install_codeql_cli
fi

# 显示 CodeQL 状态
echo ""
echo "检查 CodeQL..."
if command -v codeql >/dev/null 2>&1; then
	echo " - CodeQL: $(codeql version | head -1)"
else
	echo " - CodeQL: 未安装"
	echo "   可执行安装命令:"
	echo "   $0 --install-codeql"
fi

# 启动 ChromaDB（可选）
echo ""
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
	if curl -s http://localhost:8001/api/v1/heartbeat >/dev/null 2>&1; then
		echo "检测到已有 ChromaDB 服务 (8001)，跳过启动"
	elif ss -lnt 2>/dev/null | grep -q ':8001 '; then
		echo "检测到 8001 端口已被占用，跳过启动 ChromaDB"
		echo "请释放端口后重试，或改用其它端口"
	else
		COMPOSE_CMD="$(get_compose_cmd)"
		if [ -z "$COMPOSE_CMD" ]; then
			echo "未检测到 docker compose/docker-compose，跳过 ChromaDB 启动"
		else
			echo "启动 ChromaDB 容器..."
			if ! $COMPOSE_CMD up -d; then
				echo "ChromaDB 启动失败（可能是端口冲突或容器异常）"
				echo "可先执行: $COMPOSE_CMD ps"
			else
				echo "等待 ChromaDB 启动..."
				sleep 5
				echo "检查 ChromaDB 状态..."
				curl -s http://localhost:8001/api/v1/heartbeat >/dev/null 2>&1 && \
					echo " - ChromaDB 运行正常" || echo " - ChromaDB 启动中..."
			fi
		fi
	fi
else
	echo "跳过 ChromaDB 启动（Docker 不可用或无权限）"
fi

# 创建输出目录
mkdir -p output logs codeql_dbs codeql_packs
if [ ! -f codeql_packs/qlpack.yml ]; then
	cat > codeql_packs/qlpack.yml <<'EOF'
name: local/custom-queries
version: 0.0.1
dependencies:
  codeql/cpp-all: '*'
extractor: cpp
EOF
fi

echo ""
echo "=========================================="
echo "环境设置完成!"
echo ""
echo "使用方法:"
echo "  python -m src.main generate --patch tests/example.patch"
echo "=========================================="
