# LLM-Native: 面向缺陷检测的大预言模型原生静态分析框架

<p align="center">
    <img src="assets/framework-overview.svg" alt="Framework Overview" width="600">
</p>

## 🚀 最新特性

### 🧠 完整预训练模型生态系统
- **智能环境构建**: 一键下载和管理所有预训练模型
- **多模型支持**: 嵌入模型、生成模型、API模型全覆盖
- **自动配置**: 环境变量和路径自动配置，开箱即用
- **断点续传**: 支持网络中断后的智能恢复下载

**立即体验**:
```bash
git clone <repository-url>
cd LLM-Native
./scripts/dev-manual.sh  # 一键构建完整环境
```

**内置模型支持**:
| 类别 | 模型 | 大小 | 用途 |
|------|------|------|------|
| **嵌入模型** | microsoft/unixcoder-base | 500MB | 代码语义理解 |
| | BAAI/bge-m3 | 2.2GB | 多语言文本嵌入 |
| | paraphrase-MiniLM-L3-v2 | 90MB | 轻量级嵌入 |
| **生成模型** | distilbert-base-uncased | 250MB | 文本分类 |
| | DialoGPT-medium | 1.5GB | 对话生成 |
| **API模型** | DeepSeek Chat/Reasoner | 云端 | LLM推理 |

## 📖 项目概述

**LLM-Native** 是一个创新的静态分析检测器自动生成框架，旨在通过大语言模型（LLM）的原生能力，降低静态分析工具的开发门槛。该框架借鉴了 IRIS 和 KNighter 项目的优秀架构设计，专门针对学术研究和工业应用场景优化。

### 🎯 核心特性

- 🤖 **LLM 原生集成**: 深度集成多种主流大语言模型（GPT-4、Claude、Gemini、DeepSeek等）
- 🧠 **预训练模型生态**: 内置完整的嵌入模型和生成模型，支持本地推理和API调用
- 📚 **结构化知识库**: 基于向量检索的API知识库，支持混合检索和RAG
- 🔄 **自愈生成引擎**: 分阶段生成 + 闭环验证 + 自动修复的检测器生成流程
- ✅ **多层验证体系**: 编译验证、语义一致性验证、性能测试
- 📊 **自动化评估**: 支持基准测试和消融实验的完整评估体系
- 🐳 **容器化部署**: 基于Docker的一键环境构建和部署
- ⚡ **智能环境构建**: 自动下载和管理预训练模型，支持断点续传

### 🏗️ 架构设计

框架采用高度模块化的设计，各组件职责清晰：

```
LLM-Native Framework
├── 🎯 用户输入层: 漏洞描述、补丁文件
├── 🔍 前置处理: 漏洞特征提取
├── 🧠 核心认知: RAG知识库 + LLM生成引擎 + 预训练模型
│   ├── 📥 模型管理器: 自动下载和管理预训练模型
│   ├── 🔍 嵌入引擎: 代码和文本向量化
│   └── 🤖 LLM接口: 支持多种模型的后端适配
├── 🔧 中间件: 适配器、编排调度
├── ⚙️ 底层执行: 安全沙箱、静态分析后端
├── 📊 结果输出: 检测结果报告、自动评估统计
├── 🐳 环境构建: 一键部署和模型管理
```

## 🚀 快速开始

### 🐳 Docker 环境（推荐）

#### 🌐 代理配置（可选）

如果您在企业网络环境或需要加速模型下载，可以配置代理：

```bash
# 方式1：启动时启用代理（推荐）
./scripts/dev-manual.sh proxy

# 方式2：交互式选择代理
./scripts/dev-manual.sh
# 会提示："是否启用代理？(端口: 7897)"
# 选择 y 启用代理，选择 n 或回车跳过
```

**代理配置说明：**
- 默认代理端口：`7897`（适配 clash-verge 等主流代理工具）
- 支持的代理协议：HTTP/HTTPS
- 代理地址映射：`host.docker.internal:7897`

#### 📥 本地模型下载（推荐）

为了实现离线使用和加速启动，建议预先下载Embedding模型：

**⚠️ 重要：下载前需要配置终端代理**

由于HuggingFace模型托管在海外服务器，下载时需要网络代理支持：

```bash
# 配置终端代理（以clash-verge为例，默认混合代理端口7897）
export http_proxy="http://127.0.0.1:7897"
export https_proxy="http://127.0.0.1:7897"
export all_proxy="socks5://127.0.0.1:7897"

# 验证代理是否生效
curl https://www.google.com

# 如果验证失败，尝试其他常见端口
# export http_proxy="http://127.0.0.1:7890"  # clash默认端口
# export https_proxy="http://127.0.0.1:7890"
# export all_proxy="socks5://127.0.0.1:7890"
```

**💡 代理配置说明：**
- clash-verge 默认只代理浏览器，不代理终端
- 需要手动设置终端环境变量才能下载模型
- 混合代理端口通常是 `7897`，也可尝试 `7890`
- 设置后整个终端会话都使用代理

```bash
# 代理配置成功后，执行下载脚本
python3 scripts/download_models.py

# 检查下载状态
python3 scripts/check_models.py

# 验证模型功能
python3 scripts/test_environment_comprehensive.py
```

**核心预训练模型（按毕设需求精简）：**
| 模型 | 大小 | 用途 | 重要性 |
|------|------|------|----------|
| `microsoft/unixcoder-base` | 500MB | **代码语义嵌入** | ⭐⭐⭐⭐⭐ |
| `microsoft/codebert-base` | 400MB | **代码理解** | ⭐⭐⭐⭐⭐ |
| `BAAI/bge-m3` | 2.2GB | **多语言文本嵌入** | ⭐⭐⭐⭐⭐ |

**📊 总计大小：** ~3.1GB（比之前减少了70MB）

**模型缓存位置：** `./pretrained_models/`

**容器自动挂载：** 启动容器时会自动挂载本地模型缓存，实现离线使用。

**🔄 代理设置的持久化：**
```bash
# 临时设置（当前会话）
export http_proxy="http://127.0.0.1:7897"
export https_proxy="http://127.0.0.1:7897"

# 永久设置（添加到shell配置文件）
echo 'export http_proxy="http://127.0.0.1:7897"' >> ~/.bashrc
echo 'export https_proxy="http://127.0.0.1:7897"' >> ~/.bashrc
source ~/.bashrc
```

#### 选项1: 一键环境构建（推荐）

```bash
# 1. 克隆项目
git clone <repository-url>
cd LLM-Native

# 2. 配置API密钥
cp llm_keys.yaml.example llm_keys.yaml
# 编辑 llm_keys.yaml 添加你的API密钥

# 3. 一键构建完整环境（包含模型下载）
./scripts/dev-manual.sh

# 脚本会自动：
# - 创建必要的目录结构
# - 下载所有预训练模型
# - 构建Docker镜像
# - 启动开发容器
```

#### 选项2: 传统方式

```bash
# 1. 克隆项目
git clone <repository-url>
cd LLM-Native

# 2. 配置API密钥
cp llm_keys.yaml.example llm_keys.yaml
# 编辑 llm_keys.yaml 添加你的API密钥

# 3. 启动开发环境
docker-compose up dev

# 4. 在另一个终端中初始化环境
docker-compose exec dev bash
cd /app
python3 scripts/init_environment.py
```

### 🔧 手动安装（替代方案）

```bash
# 1. 安装系统依赖
sudo apt-get update
sudo apt-get install -y build-essential cmake clang llvm-dev

# 2. 安装Python依赖
pip install -r requirements.txt

# 3. 初始化环境
python3 scripts/init_environment.py
```

### 🧹 环境清理

当环境出现问题或需要重新开始时，可以使用清理脚本：

```bash
# 标准清理（推荐）
./scripts/cleanup.sh

# 深度清理（清理所有Docker资源）
./scripts/cleanup.sh --deep

# 查看清理帮助
./scripts/cleanup.sh --help
```

清理脚本会：
- ✅ 停止所有相关容器
- ✅ 删除数据卷和网络
- ✅ 清理临时文件
- ✅ 可选深度清理Docker系统资源

### 🔧 快速修复工具

如果遇到常见问题，可以使用快速修复脚本：

```bash
# 修复DNS网络问题
./scripts/quick_fix.sh dns

# 修复Docker权限问题
./scripts/quick_fix.sh docker

# 清理Docker资源
./scripts/quick_fix.sh cleanup

# 创建最小化Dockerfile（用于网络问题严重的环境）
./scripts/quick_fix.sh minimal

# 修复代理配置问题
./scripts/quick_fix.sh proxy

# 配置终端代理（用于模型下载）
./scripts/quick_fix.sh terminal_proxy

# 下载和管理预训练模型
./scripts/quick_fix.sh models

# 执行完整修复流程
./scripts/quick_fix.sh all
```

### 🔍 网络诊断工具

在启动环境前，建议先运行网络诊断：

```bash
# 全面诊断网络和Docker配置
./scripts/diagnose_network.sh
```

### 🤖 DeepSeek模型选择

根据您的使用场景选择合适的模型：

```bash
# 🚀 交互式模型选择（推荐）
python3 scripts/select_model.py

# 或直接运行（如果有执行权限）
./scripts/select_model.py
```

**可用模型：**
- **`deepseek-chat`** - 通用对话模型，适合日常对话和文本生成
- **`deepseek-reasoner`** - 推理增强模型，适合复杂推理和代码生成

### 🧪 环境测试工具

启动环境后，建议运行综合测试来验证所有组件：

```bash
# 🚀 快速测试（推荐）
./scripts/test_all.sh

# 或运行完整环境测试（Docker + API + 框架功能）
python3 scripts/test_environment_comprehensive.py

# 🧠 模型下载和配置测试
python3 scripts/download_models.py  # 下载模型
python3 scripts/check_models.py     # 检查模型状态
python3 scripts/test_models.py       # 验证模型功能

# 或者直接运行（如果有执行权限）
./scripts/test_environment_comprehensive.py
./scripts/test_models.py
```

**🔧 环境变量控制测试行为：**
```bash
# 启用代理测试（如果网络需要代理）
export HTTP_PROXY=http://127.0.0.1:7897
export HTTPS_PROXY=http://127.0.0.1:7897

# 跳过网络相关测试（适用于网络受限环境）
export SKIP_NETWORK_TESTS=true

# 运行测试
python3 scripts/test_environment_comprehensive.py
```

**🌐 代理配置故障排除：**
```bash
# 测试代理连接
curl -I https://huggingface.co

# 检查代理环境变量
echo $http_proxy $https_proxy $all_proxy

# 清除代理设置（如果不需要代理）
unset http_proxy https_proxy all_proxy
```

**🎯 智能环境检测：**
- **宿主机运行**：只测试Docker环境（API和框架功能需要在容器内测试）
- **容器内运行**：只测试API和框架功能（Docker环境测试在容器内无意义）

**测试包含三大模块：**

#### **环境变量控制**
```bash
# 跳过网络相关测试（适用于网络受限环境）
export SKIP_NETWORK_TESTS=true
python3 scripts/test_environment_comprehensive.py
```

#### **1. Docker环境测试**
- Docker版本和daemon状态
- 容器运行状态和端口映射
- 网络和数据卷配置
- 服务连通性验证

#### **2. DeepSeek API连接测试**
- API密钥有效性验证
- 网络连接测试
- 可用模型列表获取
- 基础文本生成功能测试

#### **3. 框架基础功能测试**
- ✅ **Python环境** - 版本和运行时检查
- ✅ **依赖包** - 关键库安装状态
- ✅ **ChromaDB连接** - 向量数据库功能
- ✅ **LLM客户端** - API客户端初始化（已修复导入问题）
- ✅ **向量运算** - 数学运算和嵌入功能
- 🧠 **预训练模型** - 模型文件完整性检查
- 🔄 **模型加载** - 嵌入模型和生成模型加载测试

**测试结果说明：**
- ✅ **成功**: 组件正常工作
- ⚠️ **警告**: 功能可正常使用，但可能存在非关键问题
- ❌ **失败**: 需要修复的问题
- ⏭️ **跳过**: 根据运行环境智能跳过不适用的测试

**环境化测试策略：**
- 🖥️ **宿主机测试**：专注Docker环境验证，确保容器化环境就绪
- 🐳 **容器内测试**：专注API和框架功能验证，确保应用逻辑正常

### 🐳 Docker镜像拉取问题

#### ChromaDB镜像专用优化

由于ChromaDB镜像较大（约500MB+），拉取特别慢的特殊解决方案：

> **💡 提示**: 所有脚本现在都支持 `Ctrl+C` 中断操作，无需强制终止进程。

```bash
# 🔍 先诊断网络问题
./scripts/optimize_chromadb.sh --diagnose

# 🚀 快速拉取模式（推荐，10分钟超时）
./scripts/optimize_chromadb.sh --fast

# 🆘 应急拉取模式（多种备用方案，20分钟超时）
./scripts/optimize_chromadb.sh --emergency

# ⚡ 后台下载模式（不阻塞当前工作）
./scripts/optimize_chromadb.sh --background

# 📦 分层下载策略（先拉取基础镜像）
./scripts/optimize_chromadb.sh --layered

# 🔍 查看下载进度
./scripts/optimize_chromadb.sh --progress

# 📏 检查镜像大小
./scripts/optimize_chromadb.sh --size

# 🏗️ 创建最小化Dockerfile（用于测试）
./scripts/optimize_chromadb.sh --minimal
```

**推荐使用顺序：**
1. 先运行网络诊断：`./scripts/optimize_chromadb.sh --diagnose`
2. 尝试快速拉取：`./scripts/optimize_chromadb.sh --fast`
3. 如果失败，使用应急方案：`./scripts/optimize_chromadb.sh --emergency`

#### 通用Docker镜像解决方案

如果遇到 `context deadline exceeded` 或无法拉取Docker镜像的问题：

```bash
# 方案1：配置镜像加速器（推荐）
./scripts/fix_docker_images.sh --mirror

# 方案2：手动下载镜像（尝试多个源，重试机制）
./scripts/fix_docker_images.sh --pull

# 方案3：配置代理（如果在企业网络环境）
./scripts/fix_docker_images.sh --proxy

# 方案4：测试网络连接
./scripts/fix_docker_images.sh --test

# 方案5：查看离线下载指导
./scripts/fix_docker_images.sh --offline
```

**自动修复机制：**
- 启动脚本会自动检测网络问题并尝试修复
- 如果所有镜像源都失败，会询问是否跳过向量数据库
- 跳过向量数据库后仍可使用其他功能

**手动解决方案：**
- 配置Docker镜像加速器到 `/etc/docker/daemon.json`
- 使用VPN或代理访问Docker Hub
- 离线下载镜像后导入到本地：`docker load < image.tar`

## 📋 使用指南

### 🔍 生成检测器

```bash
# 基本用法 - 从漏洞描述生成检测器
python3 src/main.py generate_detector \
  --vulnerability_desc "缓冲区溢出漏洞：数组越界访问" \
  --target_framework clang

# 指定输出目录
python3 src/main.py generate_detector \
  --vulnerability_desc "CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer" \
  --target_framework codeql \
  --output_dir ./results/buffer_overflow_detector
```

### ✅ 验证检测器

```bash
# 验证生成的检测器
python3 src/main.py validate_detector \
  --detector_path ./results/detector.cpp \
  --test_cases_dir ./data/benchmarks/test_cases
```

### 📊 评估框架

```bash
# 在基准数据集上评估框架性能
python3 src/main.py evaluate_framework \
  --benchmark_name juliet_suite \
  --output_dir ./evaluation_results
```

### 🔎 知识库搜索

```bash
# 在API知识库中搜索相关信息
python3 src/main.py knowledge_search \
  --query "如何在Clang Static Analyzer中检测数组越界" \
  --top_k 5
```

## 🛠️ 核心模块

### 1. 预训练模型管理器 (`pretrained_models/`)

**功能**: 自动下载、管理和配置预训练模型
- **智能下载**: 支持优先级控制和断点续传
- **代理支持**: 自动检测和配置网络代理
- **离线使用**: 本地缓存优先，网络回退机制
- **模型分类**: 嵌入模型、生成模型、API模型分类管理
- **环境集成**: 自动配置HuggingFace环境变量和容器挂载

**支持的模型**:
- **嵌入模型**: microsoft/unixcoder-base, BAAI/bge-m3, paraphrase-MiniLM-L3-v2
- **生成模型**: distilbert-base-uncased, DialoGPT-medium
- **API模型**: DeepSeek系列模型

**📥 下载和管理命令：**
```bash
# 1. 配置终端代理（重要：clash默认不代理终端）
export http_proxy="http://127.0.0.1:7897"
export https_proxy="http://127.0.0.1:7897"
export all_proxy="socks5://127.0.0.1:7897"

# 2. 验证代理连接
curl https://www.google.com

# 3. 下载所有推荐模型
python3 scripts/download_models.py

# 4. 检查下载状态
python3 scripts/check_models.py

# 5. 查看已下载模型详情
cat pretrained_models/model_inventory.txt

# 6. 测试模型配置和功能
python3 scripts/test_models.py
```

**🌐 代理配置说明：**
- **本机下载**：需要在终端设置代理环境变量
- **容器代理**：容器内自动配置代理环境变量
- **支持工具**：clash-verge等主流代理工具（默认端口7897）
- **代理映射**：容器内地址自动映射为`host.docker.internal:7897`
- **启动命令**：`./scripts/dev-manual.sh proxy`

**⚠️ 注意事项：**
- clash-verge默认只代理浏览器，不代理终端命令
- 下载模型前必须配置终端代理环境变量
- 代理端口可能因clash配置而异（常见：7890/7897）

### 2. 知识库子系统 (`src/knowledge_base/`)

**功能**: 构建和管理结构化的API知识库
- **向量数据库**: 支持ChromaDB、Milvus等
- **混合检索**: 结合稠密检索和稀疏检索
- **数据源**: Clang/LLVM文档、CodeQL查询示例、CWE漏洞模式

```python
from knowledge_base.manager import KnowledgeBaseManager

kb = KnowledgeBaseManager(config)
kb.search("DataFlow::PathGraph API usage")
```

### 2. 生成引擎 (`src/generator/`)

**功能**: 基于LLM的检测器自动生成
- **分阶段生成**: 模式提取 → 计划制定 → 代码生成
- **自愈机制**: 编译错误检测和自动修复
- **多框架支持**: Clang Static Analyzer、CodeQL

```python
from generator.engine import GeneratorEngine

engine = GeneratorEngine(config, knowledge_base)
result = engine.generate_detector(vuln_desc, "clang")
```

### 3. 验证体系 (`src/validator/`)

**功能**: 多层次检测器验证
- **编译验证**: 确保代码语法正确
- **语义验证**: 功能正确性测试
- **性能验证**: 误报率和召回率评估

### 4. 评估模块 (`src/evaluator/`)

**功能**: 框架性能评估和基准测试
- **基准数据集**: Juliet Test Suite、自定义数据集
- **指标计算**: 准确率、精确率、召回率、F1分数
- **消融实验**: 组件影响分析

## 📊 支持的漏洞类型

框架目前支持以下典型漏洞类型的检测器生成：

| CWE ID | 漏洞类型 | 支持状态 |
|--------|----------|----------|
| CWE-119 | 缓冲区溢出 | ✅ |
| CWE-125 | 越界读取 | ✅ |
| CWE-416 | 释放后使用 | ✅ |
| CWE-476 | 空指针解引用 | ✅ |
| CWE-22 | 路径遍历 | 🚧 |
| CWE-78 | 命令注入 | 🚧 |

## 🔧 配置说明

### 主要配置文件

- `config/config.yaml`: 框架核心配置
- `config/models-config.yaml`: 预训练模型下载配置
- `config/models-paths.yaml`: 模型路径映射配置
- `llm_keys.yaml`: LLM API密钥配置
- `docker-compose.yml`: 容器编排配置

### 配置示例

```yaml
# config/config.yaml
project:
  name: "LLM-Native Static Analysis Framework"
  version: "0.1.0"

llm:
  primary_model: "deepseek-chat"
  fallback_models: ["deepseek-reasoner"]
  generation:
    temperature: 0.1
    max_tokens: 4096

knowledge_base:
  vector_db:
    type: "chromadb"
    collection: "api_knowledge"
  embedding_model: "microsoft/unixcoder-base"
```

```yaml
# config/models-config.yaml
embedding_models:
  - name: "microsoft/unixcoder-base"
    priority: "high"
    size: "500MB"
  - name: "BAAI/bge-m3"
    priority: "high"
    size: "2.2GB"

generation_models:
  - name: "distilbert-base-uncased"
    priority: "medium"
    size: "250MB"

download:
  network:
    timeout: 600
    retries: 3
  filter:
    by_priority: ["high", "medium"]
```

## 🧪 实验评估

### 预期性能指标

- **编译成功率**: ≥70%
- **功能正确率**: ≥65%
- **误报率降低**: ≥30%
- **生成时间**: <10分钟/检测器

### 基准测试

```bash
# 运行完整评估流程
python3 scripts/run_evaluation.py --benchmark juliet_suite --iterations 5
```

## 📚 文档和示例

- [预训练模型下载指南](docs/MODEL_DOWNLOAD_README.md) - 模型下载、管理和代理配置指南
- [预训练模型设置指南](docs/models-setup.md) - 模型配置和管理指南
- [架构设计文档](docs/architecture.md)
- [API参考](docs/api_reference.md)
- [使用示例](examples/)
- [开发指南](docs/development.md)

## 🤝 贡献指南

我们欢迎社区贡献！请查看[贡献指南](CONTRIBUTING.md)了解如何参与项目开发。

### 开发环境设置

```bash
# 1. Fork项目并克隆
git clone https://github.com/your-username/LLM-Native.git
cd LLM-Native

# 2. 创建开发分支
git checkout -b feature/your-feature

# 3. 安装开发依赖
pip install -r requirements-dev.txt

# 4. 运行测试
pytest tests/
```

## 📄 许可证

本项目采用 [MIT License](LICENSE) 开源许可证。

## 🙏 致谢

本项目的设计和实现深受以下开源项目的启发：
- [IRIS](https://github.com/iris-sast/iris): LLM辅助的静态分析框架
- [KNighter](https://github.com/ise-uiuc/KNighter): LLM合成的静态分析检查器

### 🤖 模型生态支持

框架集成的预训练模型来自以下优秀开源项目：
- [microsoft/unixcoder-base](https://huggingface.co/microsoft/unixcoder-base): Microsoft代码理解模型
- [BAAI/bge-m3](https://huggingface.co/BAAI/bge-m3): 北京智源多语言嵌入模型
- [sentence-transformers](https://huggingface.co/sentence-transformers): 句子变换器库
- [DeepSeek](https://platform.deepseek.com/): 深度求索大语言模型

感谢所有开源贡献者为AI和软件安全领域做出的卓越贡献！

## 📞 联系我们

如有问题或建议，请通过以下方式联系：
- 提交 [GitHub Issue](https://github.com/Tardfyou/LLM-Native/issues)
- 发送邮件至: your-email@example.com

---

**⭐ 如果这个项目对你有帮助，请给我们一个star！**
