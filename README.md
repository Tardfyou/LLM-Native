# LLM-Native: 面向缺陷检测的大语言模型原生静态分析框架

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
| | sentence-transformers/all-MiniLM-L6-v2 | 90MB | 轻量级嵌入 |
| | microsoft/codebert-base | 400MB | 代码理解 |
| **API模型** | DeepSeek Chat/Reasoner | 云端 | LLM推理 |
| | GLM-4.7 | 云端 | 智谱AI模型 |

### 🔗 KNighter深度集成
- **完整集成**: KNightly框架完整代码库集成
- **知识库共享**: 访问KNightly的预构建检测器数据库
- **范式参考**: 基于KNightly优秀设计的生成范式
- **增强验证**: 集成KNightly的多层验证机制

## 📖 项目概述

**LLM-Native** 是一个创新的静态分析检测器自动生成框架，旨在通过大语言模型（LLM）的原生能力，降低静态分析工具的开发门槛。该框架借鉴了 IRIS 和 KNighter 项目的优秀架构设计，专门针对学术研究和工业应用场景优化。

### 🎯 核心特性

- 🤖 **LLM 原生集成**: 深度集成多种主流大语言模型（DeepSeek、GLM-4.7、GPT-4、Claude等）
- 🧠 **预训练模型生态**: 内置完整的嵌入模型和生成模型，支持本地推理和API调用
- 📚 **结构化知识库**: 基于ChromaDB向量检索的API知识库，支持混合检索和RAG
- 🔄 **自愈生成引擎**: 分阶段生成 + 闭环验证 + 自动修复的检测器生成流程
- ✅ **多层验证体系**: 编译验证、语义一致性验证、LSP验证、性能测试
- 📊 **自动化评估**: 支持基准测试和消融实验的完整评估体系
- 🐳 **容器化部署**: 基于Docker的一键环境构建和部署
- ⚡ **智能环境构建**: 自动下载和管理预训练模型，支持断点续传
- 🔗 **KNightly集成**: 完整集成KNightly框架，共享知识库和检测器范式

### 🏗️ 架构设计

框架采用高度模块化的设计，各组件职责清晰：

```
LLM-Native Framework
├── 🎯 用户输入层: 漏洞描述、补丁文件
├── 🔍 前置处理: 漏洞特征提取、模式分析
├── 🧠 核心认知: RAG知识库 + LLM生成引擎 + 预训练模型
│   ├── 📥 模型管理器: 自动下载和管理预训练模型
│   ├── 🔍 嵌入引擎: 代码和文本向量化
│   ├── 🤖 LLM接口: 支持多种模型的后端适配
│   └── 🔗 KNightly集成: 共享知识和检测范式
├── 🔧 中间件: 适配器、编排调度
├── ⚙️ 底层执行: 安全沙箱、静态分析后端
├── 📊 结果输出: 检测结果报告、自动评估统计
└── 🐳 环境构建: 一键部署和模型管理
```

### 🔄 生成工作流

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         检测器生成工作流                                     │
└─────────────────────────────────────────────────────────────────────────────┘

  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
  │   Stage 1   │ -> │   Stage 2   │ -> │  Stage 2.5  │ -> │   Stage 3   │
  │  Patch/Desc │    │   Knowledge │    │  Plan/      │    │    Code     │
  │   Analysis  │    │  Retrieval  │    │  Pattern    │    │ Generation  │
  └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
         │                   │                   │                   │
         ▼                   ▼                   ▼                   ▼
  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
  │ Analysis    │    │ RAG Search  │    │ LLM-based   │    │ Template +  │
  │ Agent       │    │ ChromaDB    │    │ Refinement  │    │ LLM Hybrid  │
  │             │    │ Top-K=3     │    │             │    │             │
  └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
                                                                           │
  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐                   ▼
  │   Stage 5   │ <- │   Stage 4   │ <- │ Validation  │           ┌─────────────┐
  │ Final       │    │  Self-      │    │   & Repair  │           │ Generated   │
  │ Optimization│    │  Healing    │    │   Loop      │           │ Checker.cpp │
  │             │    │  (Max 3)    │    │             │           └─────────────┘
  └─────────────┘    └─────────────┘    └─────────────┘
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

**核心预训练模型：**
| 模型 | 大小 | 用途 | 重要性 |
|------|------|------|----------|
| `microsoft/unixcoder-base` | 500MB | **代码语义嵌入** | ⭐⭐⭐⭐⭐ |
| `microsoft/codebert-base` | 400MB | **代码理解** | ⭐⭐⭐⭐⭐ |
| `BAAI/bge-m3` | 2.2GB | **多语言文本嵌入** | ⭐⭐⭐⭐⭐ |
| `sentence-transformers/all-MiniLM-L6-v2` | 90MB | 轻量级嵌入 | ⭐⭐⭐ |

**📊 总计大小：** ~3.2GB

**模型缓存位置：** `./pretrained_models/`

**容器自动挂载：** 启动容器时会自动挂载本地模型缓存，实现离线使用。

**🔄 代理设置的持久化：**
```bash
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

```bash
# 标准清理（推荐）
./scripts/cleanup.sh

# 深度清理（清理所有Docker资源）
./scripts/cleanup.sh --deep
```

### 🔧 快速修复工具

```bash
# 修复DNS网络问题
./scripts/quick_fix.sh dns

# 修复Docker权限问题
./scripts/quick_fix.sh docker

# 清理Docker资源
./scripts/quick_fix.sh cleanup

# 配置终端代理（用于模型下载）
./scripts/quick_fix.sh terminal_proxy

# 下载和管理预训练模型
./scripts/quick_fix.sh models
```

## 📋 使用指南

### 🔍 生成检测器

```bash
# 基本用法 - 从漏洞描述生成检测器
python3 src/main.py generate_detector \
  --vulnerability_desc "buffer overflow" \
  --target_framework clang

# 完整示例 - 指定输出目录和详细日志
python3 src/main.py generate_detector \
  --vulnerability_desc "null pointer dereference" \
  --target_framework clang \
  --output_dir ./results \
  --verbose

# 从补丁文件生成检测器
python3 src/main.py generate_detector \
  --patch_file examples/use_after_free.patch \
  --target_framework clang
```

**生成流程说明：**
1. **Stage 1**: 分析补丁或漏洞描述，提取漏洞模式
2. **Stage 2**: 从ChromaDB知识库检索相关范例（RAG）
3. **Stage 2.5**: 基于LLM生成检测策略和漏洞模式
4. **Stage 3**: 生成检测器代码（模板 + LLM混合）
5. **Stage 4**: 自愈循环 - 验证和自动修复（最多3次迭代）
6. **Stage 5**: 最终优化

### ✅ 验证检测器

```bash
# 验证生成的检测器
python3 src/main.py validate_detector \
  --detector_path ./results/run_YYYYMMDD_HHMMSS/checker.cpp \
  --test_cases_dir ./tests/simple
```

### 🔎 知识库搜索

```bash
# 在API知识库中搜索相关信息
python3 src/main.py knowledge_search \
  --query "Clang Static Analyzer checker for buffer overflow" \
  --top_k 5
```

### 🎯 报告分类

```bash
# 对检测报告进行真/假阳性分类
python3 src/main.py triage_report \
  --report_content "Null pointer dereference at line 37..." \
  --pattern "null pointer dereference"
```

### ✨ 检测器精炼

```bash
# 精炼检测器以减少误报
python3 src/main.py refine_detector \
  --checker_path ./results/run_YYYYMMDD_HHMMSS/checker.cpp \
  --pattern "buffer overflow" \
  --fp_reports_file ./reports/false_positives.json
```

### 🚀 启动API服务

```bash
# 启动FastAPI服务器
python3 src/main.py api_server --host 0.0.0.0 --port 8000
```

## 🧪 检测器验证

### 使用Clang Static Analyzer运行生成的Checker

```bash
# 1. 编译checker为共享库插件
clang++ -shared -fPIC -std=c++20 \
    -I/usr/lib/llvm-21/include \
    -L/usr/lib/llvm-21/lib \
    -o /tmp/NullPointerChecker.so \
    /app/tests/simple/results/run_20260131_104754/checker.cpp \
    -lclangStaticAnalyzerCore -lclangStaticAnalyzerFrontend \
    -lclangAnalysis -lclangAST -lclangBasic -lclangLex

# 2. 使用插件分析测试用例
clang++ --analyze \
    -Xclang -load -Xclang /tmp/NullPointerChecker.so \
    -Xclang -analyzer-checker -Xclang null.NullPointerChecker \
    -std=c++20 \
    /app/tests/simple/null_ptr_dereference.cpp
```

## 🛠️ 核心模块

### 1. LLM客户端 (`src/model/`)

**功能**: 统一的LLM接口，支持多种模型提供商

- **支持模型**:
  - DeepSeek (chat, reasoner)
  - 智谱AI (GLM-4.7, GLM-4, GLM-4-air, GLM-4-flash)
  - OpenAI (GPT-4o, GPT-4, o1, o3-mini)
  - Anthropic (Claude-3.5-sonnet, Claude-3.5-haiku)
  - 通用兼容 (Ollama, vLLM, LocalAI)

- **增强特性**:
  - 6次自动重试机制
  - 推理模型支持（自动移除`<|think|>`标签）
  - 分阶段温度配置
  - 统一错误处理

```python
from src.model import LLMClientWrapper

client = LLMClientWrapper(config)
response = client.generate("你的问题", temperature=0.7)
```

### 2. 生成编排器 (`src/generator/core/`)

**功能**: 协调各Agent完成5阶段代码生成

- **阶段管理**:
  1. 补丁/漏洞描述分析
  2. 知识检索（RAG）
  3. Plan/Pattern生成
  4. 代码生成
  5. 验证与修复循环

```python
from generator.core.orchestrator import GeneratorOrchestrator

orchestrator = GeneratorOrchestrator(config)
result = await orchestrator.generate_checker(input_data)
```

### 3. Agent系统 (`src/generator/agents/`)

**功能**: 专业化Agent处理不同生成任务

| Agent | 职责 |
|-------|------|
| `AnalysisAgent` | 分析补丁/漏洞描述，提取模式 |
| `GenerationAgent` | 生成检测器代码、plan和pattern |
| `ValidationAgent` | 验证代码编译、LSP和功能 |
| `RepairAgent` | 修复编译错误和问题 |
| `KnowledgeAgent` | 管理知识库检索 |

### 4. 知识库系统 (`src/knowledge_base/`)

**功能**: 基于ChromaDB的向量知识库

- **向量数据库**: ChromaDB持久化存储
- **混合检索**: 稠密检索 + 稀疏检索 + 重排序
- **数据源**:
  - Framework APIs (Clang/LLVM, CodeQL)
  - CWE Patterns
  - Code Examples
  - Expert Knowledge

```python
from knowledge_base.manager import KnowledgeBaseManager

kb = KnowledgeBaseManager(config)
results = kb.search("buffer overflow checker", top_k=5)
```

### 5. 验证体系 (`src/validator/`)

**功能**: 多层次检测器验证

- **编译验证**: 语法检查和插件构建
- **LSP验证**: clangd实时代码检查
- **功能验证**: 测试用例执行
- **性能验证**: 执行效率和资源使用

### 6. 精炼系统 (`src/generator/refinement/`)

**功能**: 检测器优化和误报减少

- **报告Triage**: TP/FP自动分类
- **反馈学习**: 从误报中学习改进
- **迭代优化**: 多轮精炼提升准确率

### 7. KNightly集成 (`KNighter/`)

**功能**: 完整的KNightly框架集成

- **检测器数据库**: 预构建的检测器库
- **知识库共享**: 访问KNightly的知识和范式
- **参考实现**: 优秀的检测器设计参考

## 📊 支持的漏洞类型

| CWE ID | 漏洞类型 | 支持状态 | 检测能力 |
|--------|----------|----------|----------|
| CWE-119 | 缓冲区溢出 | ✅ | 高 |
| CWE-125 | 越界读取 | ✅ | 高 |
| CWE-416 | 释放后使用 | ✅ | 高 |
| CWE-476 | 空指针解引用 | ✅ | 高 |
| CWE-22 | 路径遍历 | 🚧 | 中 |
| CWE-78 | 命令注入 | 🚧 | 中 |

## 🔧 配置说明

### 主要配置文件

| 文件 | 说明 |
|------|------|
| `config/config.yaml` | 框架核心配置 |
| `config/models-config.yaml` | 预训练模型配置 |
| `llm_keys.yaml` | LLM API密钥 |
| `docker-compose.yml` | 容器编排配置 |

### 配置示例

```yaml
# config/config.yaml
llm:
  primary_model: "deepseek-reasoner"
  fast_model: "deepseek-chat"
  keys:
    deepseek_key: "sk-xxx"
    glm_key: "your-glm-key"

knowledge_base:
  vector_db:
    type: "chromadb"
    collection: "llm_native_knowledge"
    persist_directory: "/app/data/knowledge/vector_cache"

generator:
  max_iterations: 3
  pipeline:
    - "pattern_extraction"
    - "plan_generation"
    - "code_generation"
    - "syntax_repair"
    - "validation"
```

## 📁 项目结构

```
LLM-Native/
├── config/                    # 配置文件
├── src/                       # 源代码
│   ├── main.py               # 主入口
│   ├── api.py                # FastAPI服务
│   ├── generator/            # 生成引擎
│   ├── knowledge_base/       # 知识库
│   ├── model/                # LLM客户端
│   ├── validator/            # 验证系统
│   └── frameworks/           # 框架适配器
├── scripts/                   # 工具脚本
├── tests/                     # 测试用例
├── pretrained_models/        # 预训练模型缓存
├── KNighter/                  # KNightly集成
├── data/                      # 数据目录
├── results/                   # 生成结果
├── docker-compose.yml         # 容器编排
└── Dockerfile                 # 容器定义
```

## 🧪 测试与评估

### 运行测试

```bash
# 综合测试
./scripts/test_all.sh

# 环境测试
python3 scripts/test_environment_comprehensive.py

# 模型测试
python3 scripts/test_models.py
```

### 性能指标

- **编译成功率**: ≥70%
- **功能正确率**: ≥65%
- **误报率降低**: ≥30%
- **生成时间**: <10分钟/检测器

## 🔗 相关项目

本项目深受以下优秀开源项目启发：

- [IRIS](https://github.com/iris-sast/iris) - LLM辅助的静态分析框架
- [KNighter](https://github.com/ise-uiuc/KNighter) - LLM合成的静态分析检查器

## 📄 许可证

本项目采用 [MIT License](LICENSE) 开源许可证。

## 🙏 致谢

感谢所有开源贡献者为AI和软件安全领域做出的卓越贡献！

---

**⭐ 如果这个项目对你有帮助，请给我们一个star！**
