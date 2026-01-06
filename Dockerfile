# Multi-stage Dockerfile for LLM-Native Static Analysis Framework
FROM ubuntu:22.04 AS base

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Configure DNS and package sources
RUN echo 'nameserver 8.8.8.8' > /etc/resolv.conf && \
    echo 'nameserver 8.8.4.4' >> /etc/resolv.conf && \
    sed -i 's|http://archive.ubuntu.com|http://mirrors.tuna.tsinghua.edu.cn|g' /etc/apt/sources.list && \
    sed -i 's|http://security.ubuntu.com|http://mirrors.tuna.tsinghua.edu.cn|g' /etc/apt/sources.list

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
    ninja-build \
    clang \
    llvm \
    llvm-dev \
    libclang-dev \
    openjdk-17-jdk \
    openjdk-11-jdk \
    openjdk-8-jdk \
    jq \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
FROM base AS python-deps
COPY requirements.txt .
RUN pip3 install --no-cache-dir --upgrade pip setuptools wheel && \
    pip3 install --no-cache-dir -r requirements.txt && \
    python3 -c "import sentence_transformers; print('sentence-transformers installed successfully')" || \
    (echo "Failed to install sentence-transformers, retrying..." && \
     pip3 install --no-cache-dir sentence-transformers && \
     python3 -c "import sentence_transformers; print('sentence-transformers installed successfully')")

# LLVM Environment Stage
FROM python-deps AS llvm-env
# Install additional LLVM/Clang tools
RUN apt-get update && apt-get install -y \
    lld \
    libc6-dev \
    binutils \
    && rm -rf /var/lib/apt/lists/*

# Main Application Stage
FROM llvm-env AS app
WORKDIR /app

# Copy project files
COPY . .

# Set up Python path
ENV PYTHONPATH=/app/src:$PYTHONPATH

# Create necessary directories
RUN mkdir -p /app/data/knowledge /app/data/benchmarks /app/logs /app/results

# Default command
CMD ["python3", "src/main.py", "--help"]
