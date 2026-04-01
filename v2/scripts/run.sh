#!/bin/bash
# LLVM Checker Generator v2 - 运行脚本

cd "$(dirname "$0")/.."

# 默认参数
PATCH_FILE="${1:-tests/example.patch}"
OUTPUT_DIR="${2:-output}"

echo "=========================================="
echo "LLVM Checker Generator v2"
echo "=========================================="
echo "补丁文件: $PATCH_FILE"
echo "输出目录: $OUTPUT_DIR"
echo "=========================================="

python -m src.main generate --patch "$PATCH_FILE" --output "$OUTPUT_DIR"
