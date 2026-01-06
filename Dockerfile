# Multi-stage Dockerfile for LLM-Native Static Analysis Framework
FROM ubuntu:22.04 AS base

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Install system dependencies
RUN apt-get update && apt-get install -y \
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
RUN pip3 install --no-cache-dir -r requirements.txt

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
