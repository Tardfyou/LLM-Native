#!/usr/bin/env python3
"""
分析实验结果，生成统计表格和图表
"""
import argparse
import json
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path
from typing import Dict, List, Any
from jinja2 import Template
import numpy as np


def load_results(outputs_dir: Path) -> List[Dict]:
    """加载所有实验结果"""
    results = []

    # 加载批量实验摘要
    summary_file = outputs_dir / "experiment_summary.json"
    if summary_file.exists():
        with open(summary_file) as f:
            summary = json.load(f)
            for exp in summary.get("results", []):
                for r in exp.get("results", []):
                    results.append({
                        "project": r["project"],
                        "cve": r["cve"],
                        "analyzer": r["analyzer"],
                        "config": r["config_name"],
                        "generate_success": r["generate_success"],
                        "generate_iterations": r["generate_iterations"],
                        "generate_time": r["generate_time_seconds"],
                        "refine_attempted": r["refine_attempted"],
                        "refine_success": r["refine_success"],
                        "refine_iterations": r["refine_iterations"],
                        "refine_time": r["refine_time_seconds"],
                        "precision": r.get("precision", 0.0),
                        "recall": r.get("recall", 0.0),
                        "f1_score": r.get("f1_score", 0.0),
                    })

    # 加载单个实验结果
    for result_file in outputs_dir.glob("**/results.json"):
        if result_file == summary_file:
            continue
        with open(result_file) as f:
            for r in json.load(f):
                results.append({
                    "project": r["project"],
                    "cve": r["cve"],
                    "analyzer": r["analyzer"],
                    "config": r["config_name"],
                    "generate_success": r["generate_success"],
                    "generate_iterations": r["generate_iterations"],
                    "generate_time": r["generate_time_seconds"],
                    "refine_attempted": r["refine_attempted"],
                    "refine_success": r["refine_success"],
                    "refine_iterations": r["refine_iterations"],
                    "refine_time": r["refine_time_seconds"],
                    "precision": r.get("precision", 0.0),
                    "recall": r.get("recall", 0.0),
                    "f1_score": r.get("f1_score", 0.0),
                })

    return results


def compute_statistics(results: List[Dict]) -> Dict[str, Any]:
    """计算统计指标"""
    df = pd.DataFrame(results)

    stats = {
        "total_experiments": len(results),
        "successful_generations": df["generate_success"].sum(),
        "generation_success_rate": df["generate_success"].mean(),
        "avg_generate_iterations": df[df["generate_success"]]["generate_iterations"].mean(),
        "avg_generate_time": df[df["generate_success"]]["generate_time"].mean(),
    }

    # 按配置分组
    by_config = df.groupby("config").agg({
        "generate_success": ["sum", "mean"],
        "generate_iterations": "mean",
        "precision": "mean",
        "recall": "mean",
        "f1_score": "mean",
    }).round(3)

    stats["by_config"] = by_config.to_dict()

    # 按分析器分组
    by_analyzer = df.groupby("analyzer").agg({
        "generate_success": ["sum", "mean"],
        "precision": "mean",
        "recall": "mean",
        "f1_score": "mean",
    }).round(3)

    stats["by_analyzer"] = by_analyzer.to_dict()

    # 按项目分组
    by_project = df.groupby("project").agg({
        "generate_success": ["sum", "mean"],
        "precision": "mean",
        "recall": "mean",
        "f1_score": "mean",
    }).round(3)

    stats["by_project"] = by_project.to_dict()

    # Refine 效果
    refine_df = df[df["refine_attempted"]]
    if len(refine_df) > 0:
        stats["refine_attempted"] = len(refine_df)
        stats["refine_success_rate"] = refine_df["refine_success"].mean()
        stats["avg_refine_iterations"] = refine_df["refine_iterations"].mean()

    return stats


def generate_latex_table(results: List[Dict], output_path: Path) -> str:
    """生成 LaTeX 表格"""
    df = pd.DataFrame(results)

    # 主结果表
    main_table = r"""
\begin{table}[t]
\centering
\caption{Detection Effectiveness on Real-World Vulnerabilities}
\label{tab:main_results}
\begin{tabular}{l|c|cc|cc|c}
\toprule
\textbf{Project} & \textbf{CVE} & \multicolumn{2}{c|}{\textbf{CSA}} & \multicolumn{2}{c|}{\textbf{CodeQL}} & \textbf{Status} \\
 & & Prec. & Rec. & Prec. & Rec. & \\
\midrule
"""

    for project in df["project"].unique():
        proj_df = df[df["project"] == project]
        for cve in proj_df["cve"].unique():
            cve_df = proj_df[proj_df["cve"] == cve]

            csa_row = cve_df[cve_df["analyzer"] == "csa"]
            codeql_row = cve_df[cve_df["analyzer"] == "codeql"]

            csa_prec = csa_row["precision"].mean() if len(csa_row) > 0 else 0
            csa_rec = csa_row["recall"].mean() if len(csa_row) > 0 else 0
            codeql_prec = codeql_row["precision"].mean() if len(codeql_row) > 0 else 0
            codeql_rec = codeql_row["recall"].mean() if len(codeql_row) > 0 else 0

            success = csa_row["generate_success"].any() or codeql_row["generate_success"].any()
            status = "\\checkmark" if success else "\\texttimes"

            main_table += f"{project} & {cve} & {csa_prec:.2f} & {csa_rec:.2f} & {codeql_prec:.2f} & {codeql_rec:.2f} & {status} \\\\\n"

    main_table += r"\bottomrule
\end{tabular}
\end{table}
"

    with open(output_path, "w") as f:
        f.write(main_table)

    return main_table


def generate_ablation_table(results: List[Dict], output_path: Path) -> str:
    """生成消融实验表格"""
    df = pd.DataFrame(results)

    ablation_table = r"""
\begin{table}[t]
\centering
\caption{Ablation Study: Impact of Evidence System and Refinement}
\label{tab:ablation}
\begin{tabular}{l|cc|cc}
\toprule
\textbf{Configuration} & \multicolumn{2}{c|}{\textbf{CSA}} & \multicolumn{2}{c}{\textbf{CodeQL}} \\
 & Prec. & Rec. & Prec. & Rec. \\
\midrule
"""

    configs = ["baseline", "with_evidence", "full_pipeline"]
    config_names = {
        "baseline": "Generate only (baseline)",
        "with_evidence": "+ Evidence System",
        "full_pipeline": "+ Refinement",
    }

    for config in configs:
        config_df = df[df["config"] == config]
        if len(config_df) == 0:
            continue

        csa_df = config_df[config_df["analyzer"] == "csa"]
        codeql_df = config_df[config_df["analyzer"] == "codeql"]

        csa_prec = csa_df["precision"].mean() if len(csa_df) > 0 else 0
        csa_rec = csa_df["recall"].mean() if len(csa_df) > 0 else 0
        codeql_prec = codeql_df["precision"].mean() if len(codeql_df) > 0 else 0
        codeql_rec = codeql_df["recall"].mean() if len(codeql_df) > 0 else 0

        ablation_table += f"{config_names.get(config, config)} & {csa_prec:.2f} & {csa_rec:.2f} & {codeql_prec:.2f} & {codeql_rec:.2f} \\\\\n"

    ablation_table += r"\bottomrule
\end{tabular}
\end{table}
"

    with open(output_path, "w") as f:
        f.write(ablation_table)

    return ablation_table


def generate_comparison_figure(results: List[Dict], output_path: Path):
    """生成对比图表"""
    df = pd.DataFrame(results)

    fig, axes = plt.subplots(1, 3, figsize=(14, 5))

    # 按配置分组
    config_df = df.groupby("config").agg({
        "precision": "mean",
        "recall": "mean",
        "f1_score": "mean",
        "generate_success": "mean",
    }).reset_index()

    # Precision
    sns.barplot(data=df, x="config", y="precision", hue="analyzer", ax=axes[0])
    axes[0].set_title("Precision by Configuration")
    axes[0].set_ylim(0, 1)
    axes[0].set_xlabel("Configuration")
    axes[0].set_ylabel("Precision")

    # Recall
    sns.barplot(data=df, x="config", y="recall", hue="analyzer", ax=axes[1])
    axes[1].set_title("Recall by Configuration")
    axes[1].set_ylim(0, 1)
    axes[1].set_xlabel("Configuration")
    axes[1].set_ylabel("Recall")

    # Success Rate
    sns.barplot(data=df, x="config", y="generate_success", hue="analyzer", ax=axes[2])
    axes[2].set_title("Generation Success Rate")
    axes[2].set_ylim(0, 1)
    axes[2].set_xlabel("Configuration")
    axes[2].set_ylabel("Success Rate")

    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()


def generate_project_figure(results: List[Dict], output_path: Path):
    """生成项目对比图"""
    df = pd.DataFrame(results)

    fig, axes = plt.subplots(1, 2, figsize=(12, 5))

    # 按项目分组
    project_df = df.groupby("project").agg({
        "generate_success": "mean",
        "f1_score": "mean",
    }).reset_index()

    # Success Rate by Project
    sns.barplot(data=df, x="project", y="generate_success", hue="analyzer", ax=axes[0])
    axes[0].set_title("Generation Success Rate by Project")
    axes[0].set_ylim(0, 1)
    axes[0].set_xlabel("Project")
    axes[0].set_ylabel("Success Rate")

    # F1 Score by Project
    sns.barplot(data=df, x="project", y="f1_score", hue="analyzer", ax=axes[1])
    axes[1].set_title("F1-Score by Project")
    axes[1].set_ylim(0, 1)
    axes[1].set_xlabel("Project")
    axes[1].set_ylabel("F1-Score")

    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()


def generate_summary_report(stats: Dict, results: List[Dict], output_path: Path):
    """生成摘要报告"""
    report = f"""# PATCHWEAVER 实验结果摘要

## 统计概览

- **总实验数**: {stats['total_experiments']}
- **成功生成**: {stats['successful_generations']} ({stats['generation_success_rate']:.1%})
- **平均生成迭代**: {stats['avg_generate_iterations']:.1f}
- **平均生成时间**: {stats['avg_generate_time']:.1f}s

## 按配置分组

| 配置 | 成功率 | 平均迭代 | Precision | Recall | F1 |
|------|--------|----------|-----------|--------|-----|
"""

    df = pd.DataFrame(results)
    for config in df["config"].unique():
        config_df = df[df["config"] == config]
        success_rate = config_df["generate_success"].mean()
        avg_iter = config_df["generate_iterations"].mean()
        prec = config_df["precision"].mean()
        rec = config_df["recall"].mean()
        f1 = config_df["f1_score"].mean()
        report += f"| {config} | {success_rate:.1%} | {avg_iter:.1f} | {prec:.2f} | {rec:.2f} | {f1:.2f} |\n"

    report += f"""
## 按分析器分组

| 分析器 | 成功率 | Precision | Recall | F1 |
|--------|--------|-----------|--------|-----|
"""

    for analyzer in df["analyzer"].unique():
        an_df = df[df["analyzer"] == analyzer]
        success_rate = an_df["generate_success"].mean()
        prec = an_df["precision"].mean()
        rec = an_df["recall"].mean()
        f1 = an_df["f1_score"].mean()
        report += f"| {analyzer} | {success_rate:.1%} | {prec:.2f} | {rec:.2f} | {f1:.2f} |\n"

    if stats.get("refine_attempted", 0) > 0:
        report += f"""
## Refine 效果

- **Refine 尝试数**: {stats['refine_attempted']}
- **Refine 成功率**: {stats['refine_success_rate']:.1%}
- **平均 Refine 迭代**: {stats['avg_refine_iterations']:.1f}
"""

    with open(output_path, "w") as f:
        f.write(report)


def main():
    parser = argparse.ArgumentParser(
        description="分析实验结果",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--outputs-dir", "-o",
        default=None,
        help="实验输出目录"
    )
    parser.add_argument(
        "--results-dir", "-r",
        default=None,
        help="结果输出目录"
    )
    parser.add_argument(
        "--format",
        choices=["latex", "markdown", "json"],
        default="all",
        help="输出格式"
    )
    args = parser.parse_args()

    script_dir = Path(__file__).parent
    experiments_dir = script_dir.parent
    outputs_dir = Path(args.outputs_dir) if args.outputs_dir else experiments_dir / "outputs"
    results_dir = Path(args.results_dir) if args.results_dir else experiments_dir / "results"

    # 创建结果目录
    results_dir.mkdir(parents=True, exist_ok=True)
    (results_dir / "tables").mkdir(exist_ok=True)
    (results_dir / "figures").mkdir(exist_ok=True)
    (results_dir / "paper").mkdir(exist_ok=True)

    print("="*60)
    print("  PATCHWEAVER 结果分析")
    print("="*60)

    # 加载结果
    results = load_results(outputs_dir)

    if not results:
        print("  错误: 没有找到实验结果")
        print(f"  请检查: {outputs_dir}")
        return

    print(f"  加载 {len(results)} 个实验结果")

    # 计算统计
    stats = compute_statistics(results)

    # 生成表格
    if args.format in ["all", "latex"]:
        print("\n  生成 LaTeX 表格...")
        generate_latex_table(results, results_dir / "tables" / "main_results.tex")
        generate_ablation_table(results, results_dir / "tables" / "ablation.tex")
        print(f"    ✓ {results_dir / 'tables' / 'main_results.tex'}")
        print(f"    ✓ {results_dir / 'tables' / 'ablation.tex'}")

    # 生成图表
    print("\n  生成图表...")
    generate_comparison_figure(results, results_dir / "figures" / "comparison.png")
    generate_project_figure(results, results_dir / "figures" / "by_project.png")
    print(f"    ✓ {results_dir / 'figures' / 'comparison.png'}")
    print(f"    ✓ {results_dir / 'figures' / 'by_project.png'}")

    # 生成报告
    print("\n  生成摘要报告...")
    generate_summary_report(stats, results, results_dir / "paper" / "summary.md")
    print(f"    ✓ {results_dir / 'paper' / 'summary.md'}")

    # 保存原始数据
    print("\n  保存原始数据...")
    with open(results_dir / "raw_data" / "statistics.json", "w") as f:
        json.dump(stats, f, indent=2)
    print(f"    ✓ {results_dir / 'raw_data' / 'statistics.json'}")

    # 打印摘要
    print("\n" + "="*60)
    print("  结果摘要")
    print("="*60)
    print(f"  总实验数: {stats['total_experiments']}")
    print(f"  成功生成: {stats['successful_generations']} ({stats['generation_success_rate']:.1%})")
    print(f"  平均迭代: {stats['avg_generate_iterations']:.1f}")
    print("="*60)


if __name__ == "__main__":
    main()