# LLVM Checker Generator v2

基于补丁文件自动生成 Clang-18 静态分析检测器的框架，支持 CSA (Clang Static Analyzer) 和 CodeQL 两种分析器。

## 功能特性

- **补丁驱动生成**: 从安全补丁自动提取漏洞模式，生成对应的检测器
- **双分析器支持**: 同时支持 CSA 插件和 CodeQL 查询
- **RAG 知识增强**: 内置知识库，包含常见漏洞族的检测模式
- **智能修复循环**: LSP 验证 + 代码审查 + 编译验证，自动修复语法和语义问题
- **Refine 精炼系统**: 对已生成的检测器进行迭代优化

## 支持的漏洞类型

| 漏洞族 | CSA | CodeQL |
|--------|-----|--------|
| Buffer Overflow | ✅ | ✅ |
| Use After Free | ✅ | ✅ |
| Null Pointer Dereference | ✅ | ✅ |
| Double Free | ✅ | - |
| Memory Leak | ✅ | - |
| Integer Overflow | - | ✅ |

## 快速开始

### 环境要求

- Python 3.10+
- Clang 18 (用于 CSA 编译)
- CodeQL CLI (可选，用于 CodeQL 分析)
- ChromaDB (用于 RAG 知识检索)

### 安装

```bash
cd v2
pip install -r requirements.txt
```

### 配置

1. 复制配置文件:
```bash
cp config/config.yaml.example config/config.yaml
```

2. 设置 LLM API 密钥:
```bash
export DEEPSEEK_API_KEY=your_api_key
```

### 使用

**生成检测器**:
```bash
python3 -m src.main generate \
    --patch ./tests/patchweaver_uaf_lab/session_lifetime.patch \
    --output ./output \
    --validate-path ./tests/patchweaver_uaf_lab \
    --analyzer both
```

**精炼检测器**:
```bash
python3 -m src.main refine \
    --input ./output \
    --validate-path ./tests/patchweaver_uaf_lab \
    --analyzer csa
```

**验证检测器**:
```bash
python3 -m src.main validate \
    --checker ./output/csa/UseAfterFreeChecker.so \
    --target ./tests/patchweaver_uaf_lab
```

## 项目结构

```
v2/
├── src/
│   ├── agent/           # 智能体核心 (LangGraph)
│   ├── generate/        # 生成器工作流
│   ├── refine/          # 精炼器
│   ├── core/            # 编排器 + 分析器
│   ├── tools/           # 工具集
│   ├── prompts/         # Prompt 管理
│   ├── knowledge/       # RAG 知识库
│   └── llm/             # LLM 集成
├── prompts/             # 分层 Prompt 定义
├── config/              # 配置文件
├── data/                # 知识库数据
├── tests/               # 测试用例
└── docs/                # 文档
```

## 工作流程

```
补丁输入 -> 分析器选择 -> 补丁分析 -> RAG检索 -> 生成检测器 -> 验证 -> 修复循环 -> 输出
```

### CSA 工作流
```
补丁分析 -> RAG检索 -> RAG符合性判断 -> 生成checker -> LSP验证 -> 代码审查 -> 编译 -> 功能测试
```

### CodeQL 工作流
```
补丁分析 -> RAG检索 -> RAG符合性判断 -> 生成query -> 代码审查 -> analyse验证
```

## 输出目录结构

```
output/
├── refinement_input.json   # Refine 输入契约
├── final_report.json       # 整合报告
├── patchweaver_plan.json   # 共享分析
├── csa/
│   ├── result.json         # CSA 结果
│   ├── {checker}.cpp       # 源代码
│   ├── {checker}.so        # 编译产物
│   └── evidence_bundle.json
└── codeql/
    ├── result.json
    ├── {query}.ql
    └── evidence_bundle.json
```

## 开发规范

详见 [DEVELOPMENT_STANDARDS.md](v2/docs/DEVELOPMENT_STANDARDS.md)

- Prompt 与代码分离，通过 manifest 注册
- 漏洞族知识进知识库，不硬编码
- 新旧实现不并存，及时清理死代码

## 许可证

MIT License