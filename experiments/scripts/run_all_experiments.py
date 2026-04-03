#!/usr/bin/env python3
"""
批量运行 PATCHWEAVER 实验
支持多种配置组合的消融实验
"""
import argparse
import json
import subprocess
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, List
import yaml


# 实验配置矩阵
EXPERIMENT_MATRIX = {
    "G1": {"config": "baseline.yaml", "refine": False, "description": "Generate only (baseline)"},
    "G2": {"config": "with_evidence.yaml", "refine": False, "description": "Generate + Evidence"},
    "G3": {"config": "baseline.yaml", "refine": True, "description": "Generate + Refine (no evidence)"},
    "G4": {"config": "full_pipeline.yaml", "refine": True, "description": "Full pipeline"},
}


def load_experiment_targets(targets_dir: Path) -> Dict[str, List[str]]:
    """加载实验目标"""
    targets = {}
    for project_dir in targets_dir.iterdir():
        if project_dir.is_dir():
            project = project_dir.name
            patches_dir = project_dir / "patches"
            if patches_dir.exists():
                cves = [
                    f.stem for f in patches_dir.glob("*.patch")
                    if f.stem.startswith("CVE-")
                ]
                if cves:
                    targets[project] = cves
    return targets


def run_single_experiment(
    project: str,
    cve: str,
    config_name: str,
    config_path: Path,
    refine: bool,
    analyzer: str,
    targets_dir: Path,
    outputs_dir: Path,
    v2_root: Path,
) -> Dict:
    """运行单个实验"""
    from run_experiment import run_generate, run_refine, ExperimentResult

    project_dir = targets_dir / project
    patch_path = project_dir / "patches" / f"{cve}.patch"
    validate_path = project_dir / "src"
    ground_truth_path = project_dir / "ground_truth" / f"{cve}.json"

    output_base = outputs_dir / f"{project}_{cve}_{config_name}"
    output_base.mkdir(parents=True, exist_ok=True)

    analyzers = ["csa", "codeql"] if analyzer == "both" else [analyzer]
    results = []

    for an in analyzers:
        result = ExperimentResult(
            experiment_id=f"{project}_{cve}_{an}_{config_name}",
            project=project,
            cve=cve,
            analyzer=an,
            config_name=config_name,
        )

        # Generate
        gen_result = run_generate(
            str(patch_path),
            str(output_base / an / "generated"),
            str(validate_path),
            an,
            str(config_path),
            v2_root,
        )

        result.generate_success = gen_result["success"]
        result.generate_iterations = gen_result["iterations"]
        result.generate_time_seconds = gen_result["time"]
        result.checker_source_path = gen_result.get("checker_path", "")

        if not result.generate_success:
            result.generate_error = gen_result.get("error", "")
            results.append(result)
            continue

        # Refine
        if refine:
            result.refine_attempted = True
            refine_result = run_refine(
                str(output_base / an / "generated"),
                str(validate_path),
                an,
                str(config_path),
                v2_root,
            )
            result.refine_success = refine_result["success"]
            result.refine_iterations = refine_result["iterations"]
            result.refine_time_seconds = refine_result["time"]

        result.report_path = str(output_base / an / "generated" / "final_report.json")
        results.append(result)

    return {
        "project": project,
        "cve": cve,
        "config": config_name,
        "results": results,
        "output_dir": str(output_base),
    }


def main():
    parser = argparse.ArgumentParser(
        description="批量运行 PATCHWEAVER 实验",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python3 run_all_experiments.py --groups G1 G2 G4
  python3 run_all_experiments.py --project sqlite --cve CVE-2022-35737
  python3 run_all_experiments.py --all
        """
    )
    parser.add_argument(
        "--groups", "-g",
        nargs="+",
        choices=list(EXPERIMENT_MATRIX.keys()),
        help="实验组 (G1-G4)"
    )
    parser.add_argument(
        "--project", "-p",
        help="特定项目"
    )
    parser.add_argument(
        "--cve", "-c",
        help="特定 CVE"
    )
    parser.add_argument(
        "--all", "-a",
        action="store_true",
        help="运行所有实验组合"
    )
    parser.add_argument(
        "--analyzer",
        default="both",
        choices=["csa", "codeql", "both"],
        help="分析器"
    )
    parser.add_argument(
        "--targets-dir",
        default=None,
        help="目标目录"
    )
    parser.add_argument(
        "--outputs-dir",
        default=None,
        help="输出目录"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="仅打印计划，不执行"
    )
    args = parser.parse_args()

    script_dir = Path(__file__).parent
    experiments_dir = script_dir.parent
    v2_root = experiments_dir.parent / "v2"
    targets_dir = Path(args.targets_dir) if args.targets_dir else experiments_dir / "targets"
    outputs_dir = Path(args.outputs_dir) if args.outputs_dir else experiments_dir / "outputs"
    configs_dir = experiments_dir / "configs"

    # 加载目标
    targets = load_experiment_targets(targets_dir)

    if not targets:
        print("错误: 没有找到实验目标")
        print("请先运行: python3 scripts/setup_targets.py --all")
        print("然后运行: python3 scripts/prepare_patches.py --all")
        sys.exit(1)

    # 确定实验组
    if args.all:
        groups = list(EXPERIMENT_MATRIX.keys())
    elif args.groups:
        groups = args.groups
    else:
        groups = ["G4"]  # 默认完整流程

    # 确定项目和 CVE
    if args.project and args.cve:
        targets = {args.project: [args.cve]}
    elif args.project:
        targets = {args.project: targets.get(args.project, [])}

    # 打印计划
    print("="*70)
    print("  PATCHWEAVER 批量实验计划")
    print("="*70)
    print(f"  实验组: {', '.join(groups)}")
    print(f"  分析器: {args.analyzer}")
    print(f"  目标项目: {len(targets)} 个")
    print("="*70)

    total_experiments = 0
    plan = []

    for project, cves in targets.items():
        for cve in cves:
            for group in groups:
                config_info = EXPERIMENT_MATRIX[group]
                config_path = configs_dir / config_info["config"]
                if not config_path.exists():
                    print(f"  ! 配置文件不存在: {config_path}")
                    continue

                plan.append({
                    "project": project,
                    "cve": cve,
                    "group": group,
                    "config": config_info["config"],
                    "refine": config_info["refine"],
                    "description": config_info["description"],
                })
                total_experiments += 1

    print(f"\n  总实验数: {total_experiments}")
    print("  每个实验:")

    for p in plan[:10]:  # 只显示前 10 个
        print(f"    - {p['project']} / {p['cve']} / {p['group']} ({p['description']})")

    if len(plan) > 10:
        print(f"    ... 还有 {len(plan) - 10} 个实验")

    if args.dry_run:
        print("\n  [DRY RUN] 不执行实验")
        return

    # 执行
    print("\n" + "="*70)
    print("  开始执行")
    print("="*70)

    start_time = datetime.now()
    all_results = []
    completed = 0
    failed = 0

    for p in plan:
        print(f"\n[{completed+1}/{total_experiments}] {p['project']} / {p['cve']} / {p['group']}")

        config_path = configs_dir / p["config"]

        try:
            result = run_single_experiment(
                p["project"],
                p["cve"],
                p["group"],
                config_path,
                p["refine"],
                args.analyzer,
                targets_dir,
                outputs_dir,
                v2_root,
            )
            all_results.append(result)
            completed += 1

            # 打印结果摘要
            for r in result["results"]:
                status = "✓" if r.generate_success else "✗"
                print(f"  {r.analyzer}: {status}")

        except Exception as e:
            print(f"  ✗ 错误: {e}")
            failed += 1
            completed += 1

    elapsed = datetime.now() - start_time

    # 保存总结果
    summary_file = outputs_dir / "experiment_summary.json"
    summary = {
        "timestamp": start_time.isoformat(),
        "total_experiments": total_experiments,
        "completed": completed,
        "failed": failed,
        "elapsed_seconds": elapsed.total_seconds(),
        "groups": groups,
        "analyzer": args.analyzer,
        "results": all_results,
    }

    with open(summary_file, "w") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)

    # 打印总结
    print("\n" + "="*70)
    print("  实验完成")
    print("="*70)
    print(f"  成功: {completed - failed}")
    print(f"  失败: {failed}")
    print(f"  耗时: {elapsed}")
    print(f"  结果: {summary_file}")
    print("="*70)


if __name__ == "__main__":
    main()