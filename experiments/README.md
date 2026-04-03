# PATCHWEAVER 实验环境

> 本目录包含用于评估 PATCHWEAVER 系统的完整实验框架
> 完全独立，不影响项目主代码

## 目录结构

```
experiments/
├── EXPERIMENT_DESIGN.md    # 详细实验设计文档
├── setup.sh               # 环境初始化脚本
├── README.md              # 本文件
│
├── scripts/
│   ├── setup_targets.py   # 下载目标项目
│   ├── prepare_patches.py # 准备 CVE 补丁
│   ├── run_experiment.py  # 单个实验运行
│   ├── run_all_experiments.py # 批量实验运行
│   └── analyze_results.py # 结果分析
│
├── configs/
│   ├── baseline.yaml      # 基线配置
│   ├── with_evidence.yaml # 证据系统配置
│   └── full_pipeline.yaml # 完整流程配置
│
├── targets/               # 目标项目源码
│   ├── sqlite/
│   ├── libxml2/
│   └── curl/
│
├── outputs/               # 实验输出
│
└── results/               # 分析结果
    ├── raw_data/
    ├── tables/
    ├── figures/
    └── paper/
```

## 快速开始

### 1. 初始化环境

```bash
cd /home/spa/LLM-Native/experiments
chmod +x setup.sh
./setup.sh
```

### 2. 下载目标项目

```bash
# 下载所有项目
python3 scripts/setup_targets.py --all

# 或单个项目
python3 scripts/setup_targets.py --project sqlite
```

### 3. 准备补丁

```bash
# 准备所有补丁
python3 scripts/prepare_patches.py --all

# 或单个 CVE
python3 scripts/prepare_patches.py --cve CVE-2022-35737
```

### 4. 运行实验

```bash
# 单个实验
python3 scripts/run_experiment.py \
  -c configs/full_pipeline.yaml \
  -p sqlite \
  --cve CVE-2022-35737 \
  -a both

# 批量实验 (消融实验)
python3 scripts/run_all_experiments.py --groups G1 G2 G4

# 所有实验
python3 scripts/run_all_experiments.py --all
```

### 5. 分析结果

```bash
python3 scripts/analyze_results.py
```

## 实验组

| 组 | 配置 | 描述 |
|----|------|------|
| G1 | baseline.yaml | 仅 Generate (基线) |
| G2 | with_evidence.yaml | Generate + 证据系统 |
| G3 | baseline.yaml + refine | Generate + Refine |
| G4 | full_pipeline.yaml | 完整流程 |

## 目标项目

| 项目 | 版本 | CVE 数量 |
|------|------|----------|
| SQLite | 3.39.0 | 3 |
| libxml2 | 2.10.0 | 3 |
| curl | 8.3.0 | 4 |

## CVE 列表

### SQLite
- CVE-2022-35737: Integer Overflow
- CVE-2023-7104: Buffer Overflow
- CVE-2021-20227: Use-After-Free

### libxml2
- CVE-2022-40303: Integer Overflow
- CVE-2022-40304: Buffer Overflow
- CVE-2023-45322: Use-After-Free

### curl
- CVE-2023-38545: Buffer Overflow (SOCKS5)
- CVE-2023-27533: Integer Overflow
- CVE-2022-27782: Use-After-Free
- CVE-2022-22576: Double Free

## 评估指标

- **Precision**: TP / (TP + FP)
- **Recall**: TP / (TP + FN)
- **F1-Score**: 2 × P × R / (P + R)
- **Generation Success Rate**: 成功生成检测器的比例

## 依赖

- Python 3.8+
- Clang 14+
- CodeQL 2.15+ (可选)
- cppcheck (基线对比)
- Infer (基线对比，可选)

## 输出

实验完成后，结果保存在：

- `outputs/`: 原始实验输出
- `results/raw_data/`: 统计数据
- `results/tables/`: LaTeX 表格
- `results/figures/`: PNG 图表
- `results/paper/`: 论文素材

## 参考文献

详细实验设计见 [EXPERIMENT_DESIGN.md](EXPERIMENT_DESIGN.md)