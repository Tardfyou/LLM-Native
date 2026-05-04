# LLM-Native v2

LLM-Native v2 是一个面向安全补丁的静态分析检测器生成与精炼框架。系统从补丁中提取漏洞语义，自动生成 CSA checker 或 CodeQL query，并通过证据收集、验证反馈和 refine 循环提升检测器质量。

## 核心能力

- 补丁驱动生成：从安全补丁分析漏洞模式、修复意图和目标代码上下文。
- 多后端支持：支持 CSA、CodeQL、both 和 auto 分析器选择。
- 证据系统：独立收集源码片段、补丁定位、CodeQL flow、CSA path 等 refine 证据。
- 精炼循环：基于 generate/evidence 输出继续修复检测器语法、语义和验证问题。
- LLM 配置分层：支持按 generate/refine 阶段配置模型、token 和 provider。
- 实验管理：内置 v2 毕设实验样本审查、批量运行和结果汇总流程。

## 目录结构

```text
.
├── Readme.md
├── qlpack.yml
├── v2/
│   ├── config/              # 主配置和阶段参数
│   ├── prompts/             # 生成、精炼、分析提示词和 manifest
│   ├── scripts/             # 样本物化、审查、批量生成等脚本
│   ├── src/
│   │   ├── app/             # CLI 和命令处理
│   │   ├── core/            # 编排、分析器、证据规划
│   │   ├── evidence/        # refine 证据收集
│   │   ├── experiments/     # 实验 runner 和样本环境
│   │   ├── generate/        # detector/query 生成流程
│   │   ├── llm/             # LLM provider、stream、usage
│   │   ├── refine/          # refine agent 和工具
│   │   ├── tools/           # patch、CodeQL、knowledge 等工具
│   │   └── validation/      # CodeQL/语义验证支持
│   └── tests/               # 单元测试和小型测试夹具
└── v2_experiments/
    ├── audits/              # 样本人工审查记录
    ├── figures/figures/     # 画图脚本
    ├── manifests/           # 样本清单
    ├── support/             # 实验辅助查询
    └── tables/              # 实验汇总表
```

## 环境要求

- Python 3.10+
- Clang/LLVM 18，用于 CSA checker 编译与验证
- CodeQL CLI，用于 CodeQL query 生成和分析
- 可用的 LLM provider API key

安装依赖：

```bash
cd /path/to/LLM-Native
python3 -m pip install -r v2/requirements.txt
```

## 配置

`v2/config/config.yaml` 包含 provider、模型、路径、生成和精炼参数。配置中的 API key 字段默认留空：

```yaml
llm:
  api_keys:
    deepseek: ""
    xty: ""
    packyapi: ""
```

运行前按所选 provider 填入本地 API key，或按团队约定接入环境变量/本地配置。

## CLI 使用

从仓库根目录运行：

```bash
PYTHONPATH=v2 python3 v2/src/main.py --help
```

生成检测器：

```bash
PYTHONPATH=v2 python3 v2/src/main.py generate \
  --patch path/to/fix.patch \
  --output output/generate_case \
  --validate-path path/to/project \
  --analyzer auto
```

独立收集 refine 证据：

```bash
PYTHONPATH=v2 python3 v2/src/main.py evidence \
  --patch path/to/fix.patch \
  --evidence-dir path/to/project \
  --output output/evidence_case \
  --analyzer both
```

基于已有输出精炼：

```bash
PYTHONPATH=v2 python3 v2/src/main.py refine \
  --input output/generate_case \
  --evidence-input output/evidence_case \
  --validate-path path/to/project \
  --analyzer csa
```

验证检测器：

```bash
PYTHONPATH=v2 python3 v2/src/main.py validate \
  --checker output/generate_case/codeql/PatchGuidedQuery.ql \
  --target path/to/project \
  --analyzer codeql \
  --database path/to/codeql-db
```

## 实验流程

实验资产位于 `v2_experiments/`，包含样本清单、审查记录、汇总表和图表生成脚本。

```bash
PYTHONPATH=v2 python3 v2/src/main.py experiment init --root v2_experiments
PYTHONPATH=v2 python3 v2/src/main.py experiment audit --root v2_experiments --all
PYTHONPATH=v2 python3 v2/src/main.py experiment run --root v2_experiments --all
PYTHONPATH=v2 python3 v2/src/main.py experiment summarize --root v2_experiments
```

样本物化脚本：

```bash
PYTHONPATH=v2 python3 v2/scripts/materialize_vul4c_samples.py
PYTHONPATH=v2 python3 v2/scripts/materialize_git_commit_samples.py
```

## 测试

轻量回归测试：

```bash
PYTHONPATH=v2 python3 -m pytest \
  v2/tests/test_llm_stage_config.py \
  v2/tests/test_refinement_session_loader.py
```

完整测试按需运行：

```bash
PYTHONPATH=v2 python3 -m pytest v2/tests
```
