# LLM-Native: 面向缺陷检测的大预言模型原生静态分析框架

<p align="center">
    <img src="assets/framework-overview.svg" alt="Framework Overview" width="600">
</p>

## 📖 项目概述

**LLM-Native** 是一个创新的静态分析检测器自动生成框架，旨在通过大语言模型（LLM）的原生能力，降低静态分析工具的开发门槛。该框架借鉴了 IRIS 和 KNighter 项目的优秀架构设计，专门针对学术研究和工业应用场景优化。

### 🎯 核心特性

- 🤖 **LLM 原生集成**: 深度集成多种主流大语言模型（GPT-4、Claude、Gemini等）
- 📚 **结构化知识库**: 基于向量检索的API知识库，支持混合检索和RAG
- 🔄 **自愈生成引擎**: 分阶段生成 + 闭环验证 + 自动修复的检测器生成流程
- ✅ **多层验证体系**: 编译验证、语义一致性验证、性能测试
- 📊 **自动化评估**: 支持基准测试和消融实验的完整评估体系
- 🐳 **容器化部署**: 基于Docker的完整开发和部署环境

### 🏗️ 架构设计

框架采用高度模块化的设计，各组件职责清晰：

```
LLM-Native Framework
├── 🎯 用户输入层: 漏洞描述、补丁文件
├── 🔍 前置处理: 漏洞特征提取
├── 🧠 核心认知: RAG知识库 + LLM生成引擎
├── 🔧 中间件: 适配器、编排调度
├── ⚙️ 底层执行: 安全沙箱、静态分析后端
├── 📊 结果输出: 检测结果报告、自动评估统计
```

## 🚀 快速开始

### 🐳 Docker 环境（推荐）

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

### 1. 知识库子系统 (`src/knowledge_base/`)

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
- `llm_keys.yaml`: LLM API密钥配置
- `docker-compose.yml`: 容器编排配置

### 配置示例

```yaml
# config/config.yaml
project:
  name: "LLM-Native Static Analysis Framework"
  version: "0.1.0"

llm:
  primary_model: "gpt-4o"
  fallback_models: ["claude-3-5-sonnet-20241022"]
  generation:
    temperature: 0.1
    max_tokens: 4096

knowledge_base:
  vector_db:
    type: "chromadb"
    collection: "api_knowledge"
  embedding_model: "microsoft/unixcoder-base"
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

## 📞 联系我们

如有问题或建议，请通过以下方式联系：
- 提交 [GitHub Issue](https://github.com/your-repo/LLM-Native/issues)
- 发送邮件至: your-email@example.com

---

**⭐ 如果这个项目对你有帮助，请给我们一个star！**
