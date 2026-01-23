#!/bin/bash
# 安装 clangd 和相关工具
echo "Installing clangd and LLVM tools..."
apt-get update
apt-get install -y clangd clang clang-tools llvm

# 验证安装
echo "=== Verifying installation ==="
which clangd && clangd --version
which clang && clang --version

echo "=== Creating symlinks ==="
ln -sf /usr/bin/clangd /usr/local/bin/clangd
which clangd
