#!/usr/bin/env python3
"""
运行 PATCHWEAVER 实验
"""
import argparse
import json
import subprocess
import sys
import time
import yaml
from pathlib import Path
from dataclasses import dataclass, asdict, field
from typing import Any, Dict, List, Optional


@dataclass
class ExperimentResult:
    """实验结果"""
    # 元信息
    experiment_id: str
    project: str
    cve: str
    analyzer: str
    config_name: str

    # Generate 阶段
    generate_success: bool = False
    generate_iterations: int = 0
    generate_time_seconds: float = 0.0
    generate_error: str = ""

    # Refine 阶段
    refine_attempted: bool = False
    refine_success: bool = False
    refine_iterations: int = 0
    refine_time_seconds: float = 0.0

    # 检测效果 (需要单独评估)
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0

    # 文件路径
    checker_source_path: str = ""
    checker_binary_path: str = ""
    report_path: str = ""


def run_command(cmd: List[str], cwd: str = None, timeout: int = 600) -> Dict[str, Any]:
    """运行命令并返回结果"""
    start_time = time.time()
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=cwd,
            timeout=timeout,
        )
        elapsed = time.time() - start_time
        return {
            "success": result.returncode == 0,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
            "elapsed_seconds": elapsed,
        }
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "stdout": "",
            "stderr": f"Timeout after {timeout} seconds",
            "returncode": -1,
            "elapsed_seconds": timeout,
        }
    except Exception as e:
        return {
            "success": False,
            "stdout": "",
            "stderr": str(e),
            "returncode": -1,
            "elapsed_seconds": 0,
        }


def run_generate(
    patch_path: str,
    output_dir: str,
    validate_path: str,
    analyzer: str,
    config_path: str,
    v2_root: Path,
) -> Dict[str, Any]:
    """运行 generate 命令"""
    cmd = [
        sys.executable,
        "-m", "v2.cli",
        "generate",
        "--patch", str(patch_path),
        "--output", str(output_dir),
        "--analyzer", analyzer,
        "--config", str(config_path),
    ]

    if validate_path:
        cmd.extend(["--validate", str(validate_path)])

    result = run_command(cmd, cwd=str(v2_root))

    # 解析结果
    output_path = Path(output_dir)
    result_file = output_path / "final_report.json"

    parsed = {
        "success": False,
        "iterations": 0,
        "time": result["elapsed_seconds"],
        "checker_path": "",
        "error": "",
    }

    if result["success"]:
        if result_file.exists():
            with open(result_file) as f:
                report = json.load(f)
            meta = report.get("meta", {})
            analyzer_report = report.get(analyzer, {})

            parsed["success"] = meta.get("success", False)
            parsed["iterations"] = meta.get("total_iterations", 0)
            parsed["checker_path"] = analyzer_report.get("source_path", "") or analyzer_report.get("output_path", "")
    else:
        parsed["error"] = result["stderr"][:500] if result["stderr"] else "Unknown error"

    return parsed


def run_refine(
    input_dir: str,
    validate_path: str,
    analyzer: str,
    config_path: str,
    v2_root: Path,
) -> Dict[str, Any]:
    """运行 refine 命令"""
    cmd = [
        sys.executable,
        "-m", "v2.cli",
        "refine",
        "--input", str(input_dir),
        "--analyzer", analyzer,
        "--config", str(config_path),
    ]

    if validate_path:
        cmd.extend(["--validate", str(validate_path)])

    result = run_command(cmd, cwd=str(v2_root))

    parsed = {
        "success": False,
        "iterations": 0,
        "time": result["elapsed_seconds"],
        "error": "",
    }

    # 查找最新的精炼结果
    refinements_dir = Path(input_dir) / "refinements"
    if refinements_dir.exists():
        refinement_dirs = sorted(refinements_dir.iterdir(), key=lambda p: p.name, reverse=True)
        if refinement_dirs:
            result_file = refinement_dirs[0] / "final_report.json"
            if result_file.exists():
                with open(result_file) as f:
                    report = json.load(f)
                meta = report.get("meta", {})
                parsed["success"] = meta.get("success", False)
                parsed["iterations"] = meta.get("refinement_iterations", 0)
    else:
        parsed["error"] = result["stderr"][:500] if result["stderr"] else "No refinements"

    return parsed


def main():
    parser = argparse.ArgumentParser(
        description="运行 PATCHWEAVER 实验",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python3 run_experiment.py -c configs/full_pipeline.yaml -p sqlite --cve CVE-2022-35737
  python3 run_experiment.py -c configs/baseline.yaml -p libxml2 --cve CVE-2022-40303 -a codeql
        """
    )
    parser.add_argument(
        "--config", "-c",
        required=True,
        help="配置文件路径"
    )
    parser.add_argument(
        "--project", "-p",
        required=True,
        choices=["sqlite", "libxml2", "curl"],
        help="目标项目"
    )
    parser.add_argument(
        "--cve",
        required=True,
        help="CVE ID"
    )
    parser.add_argument(
        "--analyzer", "-a",
        default="csa",
        choices=["csa", "codeql", "both"],
        help="分析器类型"
    )
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="输出目录"
    )
    parser.add_argument(
        "--no-refine",
        action="store_true",
        help="跳过精炼阶段"
    )
    parser.add_argument(
        "--targets-dir",
        default=None,
        help="目标项目目录"
    )
    args = parser.parse_args()

    # 路径设置
    script_dir = Path(__file__).parent
    experiments_dir = script_dir.parent
    v2_root = experiments_dir.parent / "v2"
    targets_dir = Path(args.targets_dir) if args.targets_dir else experiments_dir / "targets"
    outputs_dir = experiments_dir / "outputs"

    # 项目和补丁路径
    project_dir = targets_dir / args.project
    patch_path = project_dir / "patches" / f"{args.cve}.patch"
    validate_path = project_dir / "src"
    ground_truth_path = project_dir / "ground_truth" / f"{args.cve}.json"

    # 检查文件存在
    if not patch_path.exists():
        print(f"错误: 补丁文件不存在: {patch_path}")
        print("请先运行: python3 scripts/prepare_patches.py --cve " + args.cve)
        sys.exit(1)

    if not validate_path.exists():
        print(f"错误: 项目源码不存在: {validate_path}")
        print("请先运行: python3 scripts/setup_targets.py --project " + args.project)
        sys.exit(1)

    # 加载配置
    with open(args.config) as f:
        config = yaml.safe_load(f)
    config_name = config.get("experiment", {}).get("name", "unknown")

    # 输出目录
    output_base = Path(args.output) if args.output else outputs_dir / f"{args.project}_{args.cve}"
    output_base.mkdir(parents=True, exist_ok=True)

    # 分析器列表
    analyzers = ["csa", "codeql"] if args.analyzer == "both" else [args.analyzer]

    print("="*60)
    print(f"  PATCHWEAVER 实验")
    print("="*60)
    print(f"  项目: {args.project}")
    print(f"  CVE: {args.cve}")
    print(f"  配置: {config_name}")
    print(f"  分析器: {', '.join(analyzers)}")
    print("="*60)

    results = []

    for analyzer in analyzers:
        print(f"\n{'='*60}")
        print(f"  [{analyzer.upper()}]")
        print("="*60)

        analyzer_output = output_base / analyzer
        analyzer_output.mkdir(exist_ok=True)

        result = ExperimentResult(
            experiment_id=f"{args.project}_{args.cve}_{analyzer}_{config_name}",
            project=args.project,
            cve=args.cve,
            analyzer=analyzer,
            config_name=config_name,
        )

        # Generate 阶段
        print("\n[1/2] Generate 阶段...")
        gen_result = run_generate(
            str(patch_path),
            str(analyzer_output / "generated"),
            str(validate_path),
            analyzer,
            args.config,
            v2_root,
        )

        result.generate_success = gen_result["success"]
        result.generate_iterations = gen_result["iterations"]
        result.generate_time_seconds = gen_result["time"]
        result.generate_error = gen_result.get("error", "")
        result.checker_source_path = gen_result.get("checker_path", "")

        if result.generate_success:
            print(f"  ✓ 成功 (迭代: {result.generate_iterations}, 耗时: {result.generate_time_seconds:.1f}s)")
        else:
            print(f"  ✗ 失败: {result.generate_error[:100]}")
            results.append(result)
            continue

        # Refine 阶段
        do_refine = not args.no_refine and config.get("refine", {}).get("enabled", True)

        if do_refine:
            print("\n[2/2] Refine 阶段...")
            result.refine_attempted = True

            refine_result = run_refine(
                str(analyzer_output / "generated"),
                str(validate_path),
                analyzer,
                args.config,
                v2_root,
            )

            result.refine_success = refine_result["success"]
            result.refine_iterations = refine_result["iterations"]
            result.refine_time_seconds = refine_result["time"]

            if result.refine_success:
                print(f"  ✓ 成功 (迭代: {result.refine_iterations}, 耗时: {result.refine_time_seconds:.1f}s)")
            else:
                print(f"  ✗ 失败")
        else:
            print("\n[2/2] Refine 阶段: 跳过 (配置禁用)")

        result.report_path = str(analyzer_output / "generated" / "final_report.json")
        results.append(result)

    # 保存结果
    results_file = output_base / "results.json"
    with open(results_file, "w") as f:
        json.dump([asdict(r) for r in results], f, indent=2, ensure_ascii=False)

    print(f"\n{'='*60}")
    print(f"  结果保存到: {results_file}")
    print("="*60)

    # 打印摘要
    print("\n摘要:")
    for r in results:
        status = "✓" if r.generate_success else "✗"
        refine_status = ""
        if r.refine_attempted:
            refine_status = f" -> {'✓' if r.refine_success else '✗'} refine"
        print(f"  {r.analyzer}: {status} generate{refine_status}")


if __name__ == "__main__":
    main()