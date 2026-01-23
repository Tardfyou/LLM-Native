#!/bin/bash
# Container entrypoint script - verify and fix clangd environment on startup

set -e

echo "========================================="
echo "LLM-Native Framework Container Startup"
echo "========================================="

# Verify and fix clangd symlinks
echo "[INIT] Checking clangd installation..."

if ! command -v clangd &> /dev/null; then
    echo "[WARN] clangd not found in PATH, attempting to fix..."

    # Detect clang version
    CLANG_VERSION=$(ls /usr/bin/clang-* 2>/dev/null | head -1 | sed 's/.*clang-//' || echo "14")
    echo "[INIT] Detected Clang version: $CLANG_VERSION"

    # Find actual clangd binary
    if [ -f "/usr/lib/llvm-$CLANG_VERSION/bin/clangd" ]; then
        CLANGD_BIN="/usr/lib/llvm-$CLANG_VERSION/bin/clangd"
    elif [ -f "/usr/bin/clangd-$CLANG_VERSION" ]; then
        CLANGD_BIN="/usr/bin/clangd-$CLANG_VERSION"
    else
        echo "[ERROR] clangd not found for version $CLANG_VERSION"
        echo "[INFO] Available LLVM versions:"
        ls -la /usr/lib/llvm-*/bin/clangd 2>/dev/null || echo "  None"
        exit 1
    fi

    echo "[INIT] Found clangd at: $CLANGD_BIN"

    # Create symlinks
    rm -f /usr/bin/clangd /usr/local/bin/clangd
    ln -sf "$CLANGD_BIN" /usr/bin/clangd
    ln -sf "$CLANGD_BIN" /usr/local/bin/clangd

    echo "[SUCCESS] clangd symlinks created"
else
    echo "[OK] clangd found in PATH"
fi

# Verify clangd works
echo "[INIT] Verifying clangd..."
if clangd --version &> /dev/null; then
    echo "[OK] clangd is working:"
    clangd --version | head -1
else
    echo "[ERROR] clangd is not working!"
    exit 1
fi

# Verify clang++
echo "[INIT] Verifying clang++..."
if ! command -v clang++ &> /dev/null; then
    echo "[WARN] clang++ not found, creating symlink..."
    CLANG_VERSION=$(ls /usr/bin/clang-* 2>/dev/null | head -1 | sed 's/.*clang-//' || echo "14")
    if [ -f "/usr/bin/clang++-$CLANG_VERSION" ]; then
        ln -sf "/usr/bin/clang++-$CLANG_VERSION" /usr/bin/clang++
        echo "[OK] clang++ symlink created"
    fi
fi

# Show final clangd path
echo "[INIT] Final clangd location: $(readlink -f /usr/bin/clangd)"

echo "========================================="
echo "Environment setup complete!"
echo "========================================="

# Execute the command passed to this script
exec "$@"
