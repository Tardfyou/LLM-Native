# Multi-stage Dockerfile for LLM-Native Static Analysis Framework
FROM ubuntu:22.04 AS base

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Configure DNS and package sources (following KNighter approach)
RUN echo 'nameserver 8.8.8.8' > /etc/resolv.conf && \
    echo 'nameserver 8.8.4.4' >> /etc/resolv.conf && \
    sed -i 's|http://archive.ubuntu.com|http://mirrors.tuna.tsinghua.edu.cn|g' /etc/apt/sources.list && \
    sed -i 's|http://security.ubuntu.com|http://mirrors.tuna.tsinghua.edu.cn|g' /etc/apt/sources.list && \
    apt-get update && apt-get install -y software-properties-common && \
    add-apt-repository universe -y

# Install system dependencies with retry mechanism
RUN apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get update --fix-missing && \
    apt-get install -y \
    build-essential \
    cmake \
    git \
    python3 \
    python3-pip \
    python3-dev \
    wget \
    unzip \
    curl \
    gnupg \
    lsb-release \
    software-properties-common \
    ninja-build \
    lld \
    libc6-dev \
    binutils \
    zlib1g-dev \
    libncurses5-dev \
    libncurses-dev \
    libxml2-dev \
    libedit-dev \
    libffi-dev \
    zsh \
    flex \
    bison \
    libssl-dev \
    libelf-dev \
    libdw-dev \
    dwarves \
    bc \
    vim \
    xz-utils \
    tar \
    cpio \
    openjdk-17-jdk \
    openjdk-11-jdk \
    openjdk-8-jdk \
    jq \
    && rm -rf /var/lib/apt/lists/*

# ============================================================================
# Install LLVM-21 (Same version as Knighter)
# ============================================================================
RUN wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add - && \
    echo "deb http://apt.llvm.org/$(lsb_release -cs)/ llvm-toolchain-$(lsb_release -cs)-21 main" > /etc/apt/sources.list.d/llvm21.list && \
    apt-get update && \
    apt-get install -y \
    clang-21 \
    clang-tools-21 \
    libclang-21-dev \
    libc++-21-dev \
    libc++abi-21-dev \
    libomp-21-dev \
    libmlir-21-dev \
    lld-21 && \
    rm -rf /var/lib/apt/lists/*

# Set LLVM-21 as default
RUN update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-21 100 && \
    update-alternatives --install /usr/bin/clang clang /usr/bin/clang-21 100 && \
    update-alternatives --install /usr/bin/clangd clangd /usr/bin/clangd-21 100 && \
    update-alternatives --install /usr/bin/llvm-config llvm-config /usr/bin/llvm-config-21 100

# Verify LLVM-21 installation
RUN clang --version && \
    clang++ --version && \
    llvm-config --version && \
    echo "LLVM-21 installation completed" && \
    ls -la /usr/lib/llvm-21/

# Install Oh My Zsh for prettier shell (following KNighter)
RUN sh -c "$(curl -fsSL https://raw.github.com/ohmyzsh/ohmyzsh/master/tools/install.sh)" "" --unattended

# Set zsh as default shell
RUN chsh -s $(which zsh)

# Configure Oh My Zsh with a theme that shows current directory and useful plugins
RUN sed -i 's/ZSH_THEME="robbyrussell"/ZSH_THEME="bira"/' ~/.zshrc \
    && sed -i 's/plugins=(git)/plugins=(git python pip docker docker-compose colored-man-pages command-not-found)/' ~/.zshrc

# Create working directory (following KNighter structure)
WORKDIR /app

# Install Python dependencies
FROM base AS python-deps
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

# LLVM Environment Stage
FROM python-deps AS llvm-env
# Fix clangd symlinks - detect actual installed version and create proper links
RUN apt-get update && \
    # Detect which clang version is actually installed
    CLANG_VERSION=$(ls /usr/bin/clang-* 2>/dev/null | head -1 | sed 's/.*clang-//' || echo "21") && \
    echo "Detected Clang version: $CLANG_VERSION" && \
    # Remove broken clangd symlinks
    rm -f /usr/bin/clangd /usr/local/bin/clangd && \
    # Find the actual clangd binary
    if [ -f "/usr/lib/llvm-$CLANG_VERSION/bin/clangd" ]; then \
        CLANGD_BIN="/usr/lib/llvm-$CLANG_VERSION/bin/clangd"; \
    elif [ -f "/usr/bin/clangd-$CLANG_VERSION" ]; then \
        CLANGD_BIN="/usr/bin/clangd-$CLANG_VERSION"; \
    else \
        echo "ERROR: clangd not found for version $CLANG_VERSION"; exit 1; \
    fi && \
    echo "Found clangd at: $CLANGD_BIN" && \
    # Create proper symlinks pointing to the actual binary
    ln -sf "$CLANGD_BIN" /usr/bin/clangd && \
    ln -sf "$CLANGD_BIN" /usr/local/bin/clangd && \
    # Verify installation
    which clangd && \
    clangd --version && \
    echo "Clangd configured at: $(readlink -f /usr/bin/clangd)" && \
    rm -rf /var/lib/apt/lists/*

# Set LLVM/Clang environment variables for clang-21 (Knighter compatible)
ENV LLVM_CONFIG=/usr/bin/llvm-config-21
ENV CLANG_INCLUDE_DIR=/usr/lib/llvm-21/include
ENV CLANG_LIBRARY_DIR=/usr/lib/llvm-21/lib
ENV LLVM_DIR=/usr/lib/llvm-21/lib/cmake/llvm

# Main Application Stage
FROM llvm-env AS app
WORKDIR /app

# Copy project files
COPY . .

# Copy entrypoint script
COPY scripts/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# Set up Python path
ENV PYTHONPATH=/app/src:$PYTHONPATH

# Create necessary directories
RUN mkdir -p /app/data/knowledge /app/data/benchmarks /app/logs /app/results

# Test Clang environment during build
RUN echo "Testing Clang-21 environment..." && \
    clang --version && \
    clang -print-search-dirs | head -10 && \
    echo "Clang Static Analyzer headers:" && \
    find /usr/lib/llvm-21/include/clang -name "*.h" | head -5 && \
    echo "Clang environment test completed"

# Use entrypoint script to verify/fix clangd on container startup
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

# Default command - can be overridden by docker-compose
CMD ["/bin/zsh"]
