# PATCHWEAVER 顶会标准实验设计

> 版本: 1.0
> 日期: 2026-04-02
> 目标: 评估检测器生成系统在真实C项目上的效果

---

## 1. 实验目标

### 1.1 研究问题

| RQ | 描述 |
|----|------|
| RQ1 | 生成的检测器能否在真实项目中检测到与补丁同类的漏洞？ |
| RQ2 | 证据系统对检测器质量的影响如何？ |
| RQ3 | Refine 阶段能否有效改善检测器？ |
| RQ4 | 与现有静态分析工具相比效果如何？ |

### 1.2 评估指标

| 指标 | 定义 | 公式 |
|------|------|------|
| **Precision** | 检测器报告的真实漏洞比例 | TP / (TP + FP) |
| **Recall** | 检测器找到的真实漏洞比例 | TP / (TP + FN) |
| **F1-Score** | 精确率和召回率的调和平均 | 2 × P × R / (P + R) |
| **Generation Success Rate** | 成功生成通过编译的检测器比例 | N_success / N_total |
| **Refinement Improvement** | Refine 后检测器改善比例 | (F1_after - F1_before) / F1_before |

---

## 2. 实验对象选择

### 2.1 目标项目

选择标准：
- 知名开源 C 项目
- 有历史 CVE 记录
- 代码规模适中（10K-500K LOC）
- 支持静态分析（有编译系统）

| 项目 | 领域 | 规模 | CVE 数量 | 选择理由 |
|------|------|------|----------|----------|
| **sqlite** | 数据库 | ~250K LOC | 50+ | 高质量代码，边界检查漏洞多 |
| **libxml2** | XML解析 | ~150K LOC | 40+ | 解析器漏洞典型（缓冲区溢出、UAF） |
| **curl** | 网络库 | ~180K LOC | 60+ | 网络安全漏洞多样 |
| **openssl** | 加密库 | ~400K LOC | 100+ | 安全敏感，漏洞类型丰富 |
| **redis** | 数据库 | ~120K LOC | 20+ | 内存管理漏洞典型 |

### 2.2 漏洞选择

从每个项目选择 3-5 个代表性 CVE：

#### SQLite (3 个)

| CVE | 类型 | 年份 | 描述 |
|-----|------|------|------|
| CVE-2022-35737 | Integer Overflow | 2022 | `sqlite3_str_vappendf` 中的整数溢出 |
| CVE-2023-7104 | Buffer Overflow | 2023 | `sessionReadRecord` 中的缓冲区越界 |
| CVE-2021-20227 | UAF | 2021 | `sqlite3WindowRewrite` 中的释放后使用 |

#### libxml2 (3 个)

| CVE | 类型 | 年份 | 描述 |
|-----|------|------|------|
| CVE-2022-40303 | Integer Overflow | 2022 | XML 解析整数溢出 |
| CVE-2022-40304 | Buffer Overflow | 2022 | `xmlParseName` 缓冲区越界 |
| CVE-2023-45322 | UAF | 2023 | `libxml2` 解析器释放后使用 |

#### curl (4 个)

| CVE | 类型 | 年份 | 描述 |
|-----|------|------|------|
| CVE-2023-38545 | Buffer Overflow | 2023 | SOCKS5 堆缓冲区溢出 |
| CVE-2023-27533 | Integer Overflow | 2023 | URL 解析整数溢出 |
| CVE-2022-27782 | UAF | 2022 | TLS 连接释放后使用 |
| CVE-2022-22576 | Double Free | 2022 | 连接复用双重释放 |

---

## 3. 实验环境设计

### 3.1 目录结构

```
/home/spa/LLM-Native/experiments/           # 独立实验目录，不影响项目
├── README.md                               # 实验说明
├── setup.sh                                # 环境初始化脚本
├── run_experiment.py                       # 实验执行脚本
├── analyze_results.py                      # 结果分析脚本
│
├── targets/                                # 目标项目
│   ├── sqlite/                             # SQLite
│   │   ├── src/                            # 源码（从官方下载）
│   │   ├── patches/                        # 补丁文件
│   │   │   ├── CVE-2022-35737.patch
│   │   │   ├── CVE-2023-7104.patch
│   │   │   └── CVE-2021-20227.patch
│   │   └── ground_truth/                   # 真实漏洞位置
│   │       ├── CVE-2022-35737.json
│   │       ├── CVE-2023-7104.json
│   │       └── CVE-2021-20227.json
│   │
│   ├── libxml2/
│   │   ├── src/
│   │   ├── patches/
│   │   └── ground_truth/
│   │
│   ├── curl/
│   │   ├── src/
│   │   ├── patches/
│   │   └── ground_truth/
│   │
│   ├── openssl/
│   │   ├── src/
│   │   ├── patches/
│   │   └── ground_truth/
│   │
│   └── redis/
│       ├── src/
│       ├── patches/
│       └── ground_truth/
│
├── outputs/                                # 实验输出
│   ├── sqlite_CVE-2022-35737/
│   │   ├── csa/
│   │   │   ├── generated/                  # 生成的检测器
│   │   │   ├── refined/                    # 精炼后的检测器
│   │   │   └── reports/                    # 报告
│   │   ├── codeql/
│   │   │   ├── generated/
│   │   │   ├── refined/
│   │   │   └── reports/
│   │   └── baseline/                       # 基线工具结果
│   │       ├── scan-build/
│   │       ├── cppcheck/
│   │       └── infer/
│   │
│   └── ... (其他实验)
│
├── configs/                                # 实验配置
│   ├── baseline.yaml                       # 基线配置
│   ├── with_evidence.yaml                  # 使用证据系统
│   └── without_evidence.yaml               # 不使用证据系统
│
└── results/                                # 最终结果
    ├── raw_data/                           # 原始数据
    ├── tables/                             # 表格
    ├── figures/                            # 图表
    └── paper/                              # 论文素材
```

### 3.2 Ground Truth 格式

```json
{
  "cve_id": "CVE-2022-35737",
  "project": "sqlite",
  "vulnerability_type": "integer_overflow",
  "affected_files": ["sqlite3.c"],
  "affected_functions": ["sqlite3_str_vappendf"],
  "vulnerable_lines": [37421, 37422],
  "description": "Integer overflow in sqlite3_str_vappendf allows attacker to cause heap buffer overflow",
  "severity": "HIGH",
  "cwe": "CWE-190",
  "fix_commit": "a6c4bfc97e67e75e47b6aab5a1d6e9ce",
  "references": [
    "https://nvd.nist.gov/vuln/detail/CVE-2022-35737",
    "https://sqlite.org/forum/forumpost/6359"
  ],
  "test_cases": [
    {
      "file": "test_overflow.c",
      "should_trigger": true,
      "description": "Trigger integer overflow with large precision value"
    },
    {
      "file": "test_normal.c", 
      "should_trigger": false,
      "description": "Normal usage should not trigger"
    }
  ]
}
```

---

## 4. 实验配置

### 4.1 基线对比

| 工具 | 版本 | 说明 |
|------|------|------|
| **scan-build** | 14.0 | Clang 静态分析器 |
| **cppcheck** | 2.12 | 开源静态分析工具 |
| **Infer** | 1.1.0 | Facebook 静态分析器 |
| **CodeQL** | 2.15 | GitHub 代码查询 |
| **CSA** | 14.0 | Clang 静态分析器内置检查器 |

### 4.2 实验组设置

| 组 | 配置 | 目的 |
|----|------|------|
| **G1** | 仅 Generate，无证据系统 | 基线 |
| **G2** | Generate + 证据系统 | 评估证据系统价值 |
| **G3** | Generate + Refine，无证据 | 评估 Refine 价值 |
| **G4** | Generate + 证据 + Refine | 完整流程 |
| **G5** | 仅基线工具 | 对比 |

### 4.3 配置文件示例

```yaml
# configs/with_evidence.yaml
experiment:
  name: "with_evidence"
  description: "Generate with evidence system enabled"

patchweaver:
  enabled: true
  preflight_analysis: true
  max_planned_requirements: 8

evidence:
  types:
    - patch_fact
    - semantic_slice
    - dataflow_candidate
    - call_chain
    - allocation_lifecycle
    - state_transition
    - path_guard
    - context_summary
    - validation_outcome

generate:
  max_iterations: 12
  max_knowledge_search_calls: 2
  temperature: 0.15

refine:
  enabled: true
  max_iterations: 8
  structural_candidate:
    enabled: true

quality_gates:
  artifact_review:
    enabled: true
  lsp_validation:
    enabled: true
```

---

## 5. 实验流程

### 5.1 准备阶段

```bash
# 1. 初始化实验环境
cd /home/spa/LLM-Native/experiments
./setup.sh

# 2. 下载目标项目
python3 setup_targets.py --project sqlite --version 3.39.0
python3 setup_targets.py --project libxml2 --version 2.10.3
python3 setup_targets.py --project curl --version 7.88.0

# 3. 准备补丁
python3 prepare_patches.py --project sqlite --cve CVE-2022-35737
```

### 5.2 执行阶段

```bash
# 运行完整实验
python3 run_experiment.py \
  --config configs/with_evidence.yaml \
  --project sqlite \
  --cve CVE-2022-35737 \
  --analyzer both \
  --output outputs/sqlite_CVE-2022-35737

# 批量运行
python3 run_all_experiments.py --config-dir configs/
```

### 5.3 评估阶段

```bash
# 运行检测器
python3 run_detectors.py \
  --output-dir outputs/sqlite_CVE-2022-35737 \
  --target-dir targets/sqlite/src \
  --ground-truth targets/sqlite/ground_truth/CVE-2022-35737.json

# 分析结果
python3 analyze_results.py \
  --output-dir outputs/ \
  --result-dir results/

# 生成表格和图表
python3 generate_paper_materials.py --result-dir results/
```

---

## 6. 脚本实现

### 6.1 setup.sh

```bash
#!/bin/bash
# experiments/setup.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== PATCHWEAVER Experiment Setup ==="

# 检查依赖
echo "[1/5] Checking dependencies..."
command -v python3 >/dev/null 2>&1 || { echo "Python3 required"; exit 1; }
command -v clang >/dev/null 2>&1 || { echo "Clang required"; exit 1; }
command -v codeql >/dev/null 2>&1 || { echo "CodeQL required"; exit 1; }

# 创建目录结构
echo "[2/5] Creating directory structure..."
mkdir -p targets outputs configs results/{raw_data,tables,figures,paper}

# 安装 Python 依赖
echo "[3/5] Installing Python dependencies..."
pip3 install -r requirements.txt 2>/dev/null || pip3 install \
    pyyaml \
    pandas \
    matplotlib \
    seaborn \
    jinja2 \
    tqdm

# 准备基线工具
echo "[4/5] Setting up baseline tools..."
# cppcheck
if ! command -v cppcheck &> /dev/null; then
    echo "Installing cppcheck..."
    sudo apt-get install -y cppcheck 2>/dev/null || echo "Please install cppcheck manually"
fi

# Infer
if [ ! -d "$HOME/infer" ]; then
    echo "Downloading Infer..."
    cd /tmp
    curl -sSL https://github.com/facebook/infer/releases/download/v1.1.0/infer-linux64-v1.1.0.tar.xz | tar xJ
    mv infer-linux64-v1.1.0 "$HOME/infer"
    cd "$SCRIPT_DIR"
fi

echo "[5/5] Setup complete!"
echo ""
echo "Next steps:"
echo "1. Download target projects: python3 setup_targets.py --all"
echo "2. Prepare patches: python3 prepare_patches.py --all"
echo "3. Run experiments: python3 run_all_experiments.py"
```

### 6.2 setup_targets.py

```python
#!/usr/bin/env python3
"""
下载并准备目标项目
"""
import argparse
import subprocess
import urllib.request
import tarfile
import zipfile
import shutil
from pathlib import Path
from typing import Dict, Optional


TARGETS: Dict[str, Dict] = {
    "sqlite": {
        "versions": {
            "CVE-2022-35737": "3.39.0",
            "CVE-2023-7104": "3.43.0",
            "CVE-2021-20227": "3.35.0",
        },
        "download_url": "https://www.sqlite.org/2022/sqlite-autoconf-3390000.tar.gz",
        "src_dir": "sqlite-autoconf-3390000",
    },
    "libxml2": {
        "versions": {
            "CVE-2022-40303": "2.10.0",
            "CVE-2022-40304": "2.10.0",
            "CVE-2023-45322": "2.11.0",
        },
        "download_url": "https://gitlab.gnome.org/GNOME/libxml2/-/archive/v2.10.0/libxml2-v2.10.0.tar.gz",
        "src_dir": "libxml2-v2.10.0",
    },
    "curl": {
        "versions": {
            "CVE-2023-38545": "8.3.0",
            "CVE-2023-27533": "8.0.0",
            "CVE-2022-27782": "7.83.0",
            "CVE-2022-22576": "7.82.0",
        },
        "download_url": "https://curl.se/download/curl-8.3.0.tar.gz",
        "src_dir": "curl-8.3.0",
    },
}


def download_file(url: str, dest: Path) -> bool:
    """下载文件"""
    print(f"  Downloading {url}...")
    try:
        urllib.request.urlretrieve(url, dest)
        return True
    except Exception as e:
        print(f"  Download failed: {e}")
        return False


def extract_archive(archive: Path, dest: Path) -> bool:
    """解压文件"""
    print(f"  Extracting {archive.name}...")
    try:
        if archive.suffix == ".gz":
            with tarfile.open(archive, "r:gz") as tf:
                tf.extractall(dest.parent)
        elif archive.suffix == ".zip":
            with zipfile.ZipFile(archive) as zf:
                zf.extractall(dest.parent)
        return True
    except Exception as e:
        print(f"  Extract failed: {e}")
        return False


def setup_project(
    project: str,
    version: Optional[str] = None,
    targets_dir: Path = Path("targets"),
    force: bool = False,
):
    """设置单个项目"""
    if project not in TARGETS:
        print(f"Unknown project: {project}")
        return False

    config = TARGETS[project]
    target_dir = targets_dir / project

    if target_dir.exists() and not force:
        print(f"[{project}] Already exists, use --force to overwrite")
        return True

    print(f"\n=== Setting up {project} ===")

    # 创建目录
    target_dir.mkdir(parents=True, exist_ok=True)
    tmp_dir = Path("/tmp") / f"patchweaver_{project}"
    tmp_dir.mkdir(exist_ok=True)

    # 下载
    archive = tmp_dir / f"{project}.tar.gz"
    if not download_file(config["download_url"], archive):
        return False

    # 解压
    if not extract_archive(archive, tmp_dir):
        return False

    # 移动源码
    src_path = tmp_dir / config["src_dir"]
    if src_path.exists():
        # 合并到目标目录
        if (target_dir / "src").exists():
            shutil.rmtree(target_dir / "src")
        shutil.move(str(src_path), str(target_dir / "src"))
        print(f"  Source code ready: {target_dir / 'src'}")
    else:
        print(f"  Source directory not found: {src_path}")
        return False

    # 创建补丁目录
    (target_dir / "patches").mkdir(exist_ok=True)
    (target_dir / "ground_truth").mkdir(exist_ok=True)

    # 清理
    shutil.rmtree(tmp_dir, ignore_errors=True)

    print(f"[{project}] Setup complete!")
    return True


def main():
    parser = argparse.ArgumentParser(description="Setup target projects")
    parser.add_argument("--project", "-p", help="Project name (sqlite, libxml2, curl, all)")
    parser.add_argument("--version", "-v", help="Specific version")
    parser.add_argument("--all", "-a", action="store_true", help="Setup all projects")
    parser.add_argument("--force", "-f", action="store_true", help="Force overwrite")
    parser.add_argument("--targets-dir", default="targets", help="Target directory")
    args = parser.parse_args()

    targets_dir = Path(args.targets_dir)

    if args.all:
        for project in TARGETS:
            setup_project(project, targets_dir=targets_dir, force=args.force)
    elif args.project:
        setup_project(args.project, args.version, targets_dir=targets_dir, force=args.force)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
```

### 6.3 run_experiment.py

```python
#!/usr/bin/env python3
"""
运行单个实验
"""
import argparse
import json
import subprocess
import sys
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional
import yaml


@dataclass
class ExperimentResult:
    """实验结果"""
    experiment_id: str
    project: str
    cve: str
    analyzer: str
    config: str
    
    # 生成阶段
    generate_success: bool = False
    generate_iterations: int = 0
    generate_time: float = 0.0
    
    # 精炼阶段
    refine_attempted: bool = False
    refine_success: bool = False
    refine_iterations: int = 0
    refine_time: float = 0.0
    
    # 检测效果
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0
    
    # 元数据
    error_message: str = ""
    checker_path: str = ""
    output_path: str = ""


def run_generate(
    patch_path: str,
    output_dir: str,
    validate_path: str,
    analyzer: str,
    config_path: str,
) -> Dict[str, Any]:
    """运行 Generate 阶段"""
    cmd = [
        sys.executable,
        "-m", "v2.cli",
        "generate",
        "--patch", patch_path,
        "--output", output_dir,
        "--analyzer", analyzer,
        "--config", config_path,
    ]
    if validate_path:
        cmd.extend(["--validate", validate_path])
    
    start_time = time.time()
    result = subprocess.run(cmd, capture_output=True, text=True)
    elapsed = time.time() - start_time
    
    # 解析结果
    output_dir_path = Path(output_dir)
    result_file = output_dir_path / "final_report.json"
    
    if result_file.exists():
        with open(result_file) as f:
            report = json.load(f)
        return {
            "success": report.get("meta", {}).get("success", False),
            "iterations": report.get("meta", {}).get("total_iterations", 0),
            "time": elapsed,
            "checker_path": report.get(analyzer, {}).get("output_path", ""),
            "report": report,
        }
    else:
        return {
            "success": False,
            "iterations": 0,
            "time": elapsed,
            "error": result.stderr,
        }


def run_refine(
    input_dir: str,
    validate_path: str,
    analyzer: str,
    config_path: str,
) -> Dict[str, Any]:
    """运行 Refine 阶段"""
    cmd = [
        sys.executable,
        "-m", "v2.cli",
        "refine",
        "--input", input_dir,
        "--analyzer", analyzer,
        "--config", config_path,
    ]
    if validate_path:
        cmd.extend(["--validate", validate_path])
    
    start_time = time.time()
    result = subprocess.run(cmd, capture_output=True, text=True)
    elapsed = time.time() - start_time
    
    # 解析结果
    result_file = Path(input_dir) / "refinements" / "latest" / "final_report.json"
    
    if result_file.exists():
        with open(result_file) as f:
            report = json.load(f)
        return {
            "success": report.get("meta", {}).get("success", False),
            "iterations": report.get("meta", {}).get("refinement_iterations", 0),
            "time": elapsed,
            "report": report,
        }
    else:
        return {
            "success": False,
            "iterations": 0,
            "time": elapsed,
            "error": result.stderr,
        }


def evaluate_detector(
    checker_path: str,
    target_src: str,
    ground_truth: Dict[str, Any],
    analyzer: str,
) -> Dict[str, Any]:
    """评估检测器效果"""
    # 运行检测器
    if analyzer == "csa":
        cmd = [
            "scan-build",
            "-enable-checker", "alpha.core.CustomChecker",  # 加载自定义检查器
            "--use-analyzer", Path(checker_path).parent.as_posix(),
            "make",
        ]
    else:  # codeql
        # 先创建数据库
        db_path = Path(target_src) / ".codeql-db"
        subprocess.run([
            "codeql", "database", "create",
            str(db_path),
            "--language=cpp",
            f"--source-root={target_src}",
            "--overwrite",
        ], capture_output=True)
        
        # 运行查询
        cmd = [
            "codeql", "database", "analyze",
            str(db_path),
            checker_path,
            "--format=csv",
            "--output=results.csv",
        ]
    
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=target_src)
    
    # 解析结果
    findings = parse_findings(result.stdout, analyzer)
    
    # 与 ground truth 对比
    gt_lines = set(ground_truth.get("vulnerable_lines", []))
    gt_files = set(ground_truth.get("affected_files", []))
    
    tp = 0
    fp = 0
    
    for finding in findings:
        if finding["file"] in gt_files and finding["line"] in gt_lines:
            tp += 1
        else:
            fp += 1
    
    fn = len(gt_lines) - tp  # 漏报
    
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    
    return {
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
        "findings": findings,
    }


def parse_findings(output: str, analyzer: str) -> List[Dict]:
    """解析检测器输出"""
    findings = []
    # 简化实现，实际需要根据 analyzer 解析格式
    for line in output.splitlines():
        if ":" in line and "error" in line.lower():
            parts = line.split(":")
            if len(parts) >= 2:
                findings.append({
                    "file": parts[0].strip(),
                    "line": int(parts[1].strip()) if parts[1].strip().isdigit() else 0,
                })
    return findings


def main():
    parser = argparse.ArgumentParser(description="Run PATCHWEAVER experiment")
    parser.add_argument("--config", "-c", required=True, help="Config file path")
    parser.add_argument("--project", "-p", required=True, help="Target project")
    parser.add_argument("--cve", required=True, help="CVE ID")
    parser.add_argument("--analyzer", "-a", default="csa", choices=["csa", "codeql", "both"])
    parser.add_argument("--output", "-o", required=True, help="Output directory")
    parser.add_argument("--skip-refine", action="store_true", help="Skip refinement")
    parser.add_argument("--evaluate", "-e", action="store_true", help="Run evaluation")
    args = parser.parse_args()

    # 加载配置
    with open(args.config) as f:
        config = yaml.safe_load(f)

    # 准备路径
    targets_dir = Path("targets")
    project_dir = targets_dir / args.project
    patch_path = project_dir / "patches" / f"{args.cve}.patch"
    ground_truth_path = project_dir / "ground_truth" / f"{args.cve}.json"
    target_src = project_dir / "src"
    
    if not patch_path.exists():
        print(f"Patch not found: {patch_path}")
        sys.exit(1)
    
    # 加载 ground truth
    ground_truth = {}
    if ground_truth_path.exists():
        with open(ground_truth_path) as f:
            ground_truth = json.load(f)
    
    # 创建输出目录
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    analyzers = ["csa", "codeql"] if args.analyzer == "both" else [args.analyzer]
    
    results = []
    
    for analyzer in analyzers:
        print(f"\n=== Running {analyzer.upper()} ===")
        
        analyzer_output = output_dir / analyzer
        analyzer_output.mkdir(exist_ok=True)
        
        result = ExperimentResult(
            experiment_id=f"{args.project}_{args.cve}_{analyzer}",
            project=args.project,
            cve=args.cve,
            analyzer=analyzer,
            config=args.config,
        )
        
        # Generate
        print("[1/3] Running generate...")
        gen_result = run_generate(
            str(patch_path),
            str(analyzer_output / "generated"),
            str(target_src),
            analyzer,
            args.config,
        )
        
        result.generate_success = gen_result.get("success", False)
        result.generate_iterations = gen_result.get("iterations", 0)
        result.generate_time = gen_result.get("time", 0.0)
        result.checker_path = gen_result.get("checker_path", "")
        
        if not result.generate_success:
            result.error_message = gen_result.get("error", "Generate failed")
            results.append(result)
            continue
        
        # Refine
        if not args.skip_refine and config.get("refine", {}).get("enabled", True):
            print("[2/3] Running refine...")
            result.refine_attempted = True
            refine_result = run_refine(
                str(analyzer_output / "generated"),
                str(target_src),
                analyzer,
                args.config,
            )
            result.refine_success = refine_result.get("success", False)
            result.refine_iterations = refine_result.get("iterations", 0)
            result.refine_time = refine_result.get("time", 0.0)
        
        # Evaluate
        if args.evaluate and result.checker_path:
            print("[3/3] Evaluating detector...")
            eval_result = evaluate_detector(
                result.checker_path,
                str(target_src),
                ground_truth,
                analyzer,
            )
            result.true_positives = eval_result["true_positives"]
            result.false_positives = eval_result["false_positives"]
            result.false_negatives = eval_result["false_negatives"]
            result.precision = eval_result["precision"]
            result.recall = eval_result["recall"]
            result.f1_score = eval_result["f1_score"]
        
        results.append(result)
    
    # 保存结果
    results_file = output_dir / "results.json"
    with open(results_file, "w") as f:
        json.dump([asdict(r) for r in results], f, indent=2, ensure_ascii=False)
    
    print(f"\n=== Results saved to {results_file} ===")
    
    # 打印摘要
    print("\n=== Summary ===")
    for r in results:
        print(f"{r.analyzer}: success={r.generate_success}, "
              f"P={r.precision:.2f}, R={r.recall:.2f}, F1={r.f1_score:.2f}")


if __name__ == "__main__":
    main()
```

---

## 7. 结果分析

### 7.1 结果表格

```python
# analyze_results.py

def generate_latex_table(results: List[Dict]) -> str:
    """生成 LaTeX 表格"""
    template = r"""
\begin{table}[t]
\centering
\caption{Detection Effectiveness on Real-World Vulnerabilities}
\label{tab:main_results}
\begin{tabular}{l|ccc|ccc|c}
\toprule
\textbf{Project} & \textbf{CVE} & \textbf{Type} & \textbf{Analyzer} & 
\textbf{Prec.} & \textbf{Recall} & \textbf{F1} & \textbf{Succ.} \\
\midrule
{% for r in results %}
{{ r.project }} & {{ r.cve }} & {{ r.type }} & {{ r.analyzer }} &
{{ "%.2f"|format(r.precision) }} & {{ "%.2f"|format(r.recall) }} & {{ "%.2f"|format(r.f1) }} & 
{% if r.success %}\checkmark{% else %}\texttimes{% endif %} \\
{% endfor %}
\bottomrule
\end{tabular}
\end{table}
"""
    from jinja2 import Template
    return Template(template).render(results=results)


def generate_comparison_figure(results: List[Dict], output_path: str):
    """生成对比图"""
    import matplotlib.pyplot as plt
    import seaborn as sns
    
    fig, axes = plt.subplots(1, 3, figsize=(12, 4))
    
    # Precision
    sns.barplot(data=results, x="project", y="precision", hue="config", ax=axes[0])
    axes[0].set_title("Precision")
    axes[0].set_ylim(0, 1)
    
    # Recall
    sns.barplot(data=results, x="project", y="recall", hue="config", ax=axes[1])
    axes[1].set_title("Recall")
    axes[1].set_ylim(0, 1)
    
    # F1
    sns.barplot(data=results, x="project", y="f1_score", hue="config", ax=axes[2])
    axes[2].set_title("F1-Score")
    axes[2].set_ylim(0, 1)
    
    plt.tight_layout()
    plt.savefig(output_path, dpi=300)
    plt.close()
```

### 7.2 论文表格模板

```latex
% Table 1: Main Results
\begin{table}[t]
\centering
\caption{Detection Effectiveness on Real-World Vulnerabilities}
\begin{tabular}{l|cc|cc|c}
\toprule
 & \multicolumn{2}{c|}{\textbf{CSA}} & \multicolumn{2}{c|}{\textbf{CodeQL}} & \\
\textbf{Project (CVEs)} & Prec. & Rec. & Prec. & Rec. & \textbf{Base.} \\
\midrule
sqlite (3) & 0.85 & 0.78 & 0.82 & 0.81 & 0.45 \\
libxml2 (3) & 0.80 & 0.72 & 0.78 & 0.75 & 0.38 \\
curl (4) & 0.83 & 0.76 & 0.80 & 0.79 & 0.42 \\
openssl (3) & 0.75 & 0.68 & 0.73 & 0.71 & 0.35 \\
redis (3) & 0.82 & 0.74 & 0.79 & 0.77 & 0.40 \\
\midrule
\textbf{Average} & \textbf{0.81} & \textbf{0.74} & \textbf{0.78} & \textbf{0.77} & \textbf{0.40} \\
\bottomrule
\end{tabular}
\end{table}

% Table 2: Ablation Study
\begin{table}[t]
\centering
\caption{Ablation Study: Impact of Evidence System and Refinement}
\begin{tabular}{l|cc|cc}
\toprule
\textbf{Configuration} & \multicolumn{2}{c|}{\textbf{CSA}} & \multicolumn{2}{c}{\textbf{CodeQL}} \\
 & Prec. & Rec. & Prec. & Rec. \\
\midrule
Generate only (baseline) & 0.65 & 0.58 & 0.62 & 0.60 \\
+ Evidence System & 0.78 & 0.70 & 0.75 & 0.73 \\
+ Refinement & 0.81 & 0.74 & 0.78 & 0.77 \\
\bottomrule
\end{tabular}
\end{table}
```

---

## 8. 实验执行清单

### 8.1 准备阶段 (Day 1-2)

- [ ] 创建实验目录结构
- [ ] 下载目标项目源码
- [ ] 准备 CVE 补丁文件
- [ ] 编写 Ground Truth
- [ ] 配置基线工具

### 8.2 执行阶段 (Day 3-5)

- [ ] 运行 G1: Generate only (baseline)
- [ ] 运行 G2: Generate + Evidence
- [ ] 运行 G3: Generate + Refine
- [ ] 运行 G4: Full pipeline
- [ ] 运行 G5: Baseline tools

### 8.3 分析阶段 (Day 6-7)

- [ ] 收集所有结果
- [ ] 计算统计指标
- [ ] 生成表格和图表
- [ ] 编写实验报告

---

## 变更历史

| 版本 | 日期 | 变更内容 |
|------|------|----------|
| 1.0 | 2026-04-02 | 初始设计 |