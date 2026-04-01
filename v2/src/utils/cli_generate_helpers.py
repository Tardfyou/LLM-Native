"""
生成命令相关的 CLI 辅助函数。

目标：
- 降低 main.py 体积
- 保持输出行为一致
"""

import re
from pathlib import Path
from typing import Any, Dict, List


def analyzer_count(choice: str) -> int:
    """统计分析器选择中包含的分析器数量。"""
    if not choice:
        return 1

    c = str(choice).lower().strip()
    if c in {"both", "all"}:
        return 2

    tokens = [t.strip() for t in re.split(r"[,+|\s]+", c) if t.strip()]
    selected = set()
    for t in tokens:
        if t in {"both", "all"}:
            selected.update({"csa", "codeql"})
        elif t == "auto":
            continue
        else:
            selected.add(t)
    return len(selected) if selected else 1


def should_use_live_table(
    analyzer_choice: str,
    auto_selected: bool,
    verbose: bool,
    no_live: bool,
) -> bool:
    """判断是否启用 rich 实时表格。"""
    return (auto_selected or analyzer_count(analyzer_choice) > 1) and verbose and not no_live


def print_validation_result(vr: Any, analyzer_choice: str):
    """打印验证结果摘要（成功/失败分支共用）。"""
    if not vr:
        return

    # 多分析器并行场景：CSA 验证成功信息与上方生成成功信息重复，跳过展示
    if analyzer_count(analyzer_choice) > 1:
        vr_analyzer = getattr(getattr(vr, "analyzer", None), "value", "unknown")
        if vr_analyzer == "csa":
            return

    print(f"\n{'─' * 40}")
    print("📊 验证结果:")
    if hasattr(vr, "summary"):
        print(vr.summary)
        return

    status = "✅ 成功" if getattr(vr, "success", False) else "❌ 失败"
    stage = getattr(getattr(vr, "stage", None), "value", "semantic")
    vr_analyzer_name = getattr(getattr(vr, "analyzer", None), "value", "unknown")
    diagnostics = getattr(vr, "diagnostics", []) or []
    error_message = getattr(vr, "error_message", "")
    execution_time = getattr(vr, "execution_time", 0.0)

    print(f"阶段: {stage}")
    print(f"分析器: {vr_analyzer_name}")
    print(f"状态: {status}")
    print(f"诊断数: {len(diagnostics)}")
    print(f"耗时: {execution_time:.2f}秒")
    if error_message:
        print(f"错误: {error_message}")

    if getattr(vr, "success", False) and len(diagnostics) == 0:
        if vr_analyzer_name == "codeql":
            print("提示: 查询执行成功但未命中结果。请优先检查目标数据库是否包含未修复漏洞样本，以及当前语义约束是否过窄。")
        else:
            print("提示: 检测器执行成功但未命中结果。请优先检查功能验证样本是否覆盖未修复漏洞，以及当前规则是否过窄。")


def build_generate_followup_lines(result: Any, output_dir: str) -> List[str]:
    """在 generate 成功但 0 命中时，提示先检查功能验证样本与规则范围。"""
    if str(getattr(result, "workflow_mode", "generate") or "generate").strip() != "generate":
        return []

    analyzer_results = getattr(result, "analyzer_results", {}) or {}
    zero_hit_analyzers: List[str] = []
    for analyzer_name, analyzer_info in analyzer_results.items():
        if not isinstance(analyzer_info, dict):
            continue
        validation = analyzer_info.get("validation", {}) if isinstance(analyzer_info.get("validation"), dict) else {}
        if not validation:
            continue
        if validation.get("success") and int(validation.get("diagnostics_count", 0) or 0) == 0:
            zero_hit_analyzers.append(analyzer_name)

    if not zero_hit_analyzers:
        return []

    analyzers = ", ".join(zero_hit_analyzers)
    return [
        f"  提示: {analyzers} 执行成功，但当前样本未命中漏洞目标。",
        f"  建议: 先检查验证样本、补丁根因建模和知识检索结果是否足够贴近当前漏洞机制。",
    ]


def build_generation_summary_lines(result: Any, output_dir: str) -> List[str]:
    """构建更紧凑、可扫描的生成成功摘要。"""
    output_root = Path(output_dir or "./output")
    report_path = output_root / "final_report.json"
    analyzer_output_dirs = getattr(result, "analyzer_output_dirs", {}) or {}
    csa_dir = Path(str(analyzer_output_dirs.get("csa", "") or "")).expanduser() if analyzer_output_dirs.get("csa") else (output_root / "csa")
    codeql_dir = Path(str(analyzer_output_dirs.get("codeql", "") or "")).expanduser() if analyzer_output_dirs.get("codeql") else (output_root / "codeql")
    lines = [
        f"  检测器名称: {getattr(result, 'checker_name', '') or '-'}",
        f"  输出文件: {getattr(result, 'output_path', '') or '-'}",
        f"  迭代次数: {getattr(result, 'total_iterations', 0)}",
        f"  编译尝试: {getattr(result, 'repair_iterations', 0)}",
        f"  整合报告: {report_path}",
        f"  CSA 目录: {csa_dir}",
        f"  CodeQL 目录: {codeql_dir}",
    ]

    portfolio = getattr(result, "portfolio_decision", {}) or {}
    if portfolio.get("preferred_analyzer"):
        lines.append(f"  首选分析器: {portfolio.get('preferred_analyzer')}")
    if portfolio.get("summary"):
        lines.append(f"  组合决策: {portfolio.get('summary')}")

    run_metrics = getattr(result, "run_metrics", {}) or {}
    if isinstance(run_metrics, dict) and run_metrics.get("summary"):
        lines.append(f"  运行摘要: {run_metrics.get('summary')}")
        analyzer_metrics = run_metrics.get("analyzers", {}) if isinstance(run_metrics.get("analyzers"), dict) else {}
        for analyzer_name in ("csa", "codeql"):
            info = analyzer_metrics.get(analyzer_name)
            if not isinstance(info, dict) or not info:
                continue
            parts: List[str] = []
            for key, label in (
                ("evidence_seconds", "evidence"),
                ("agent_seconds", "agent"),
                ("validation_seconds", "validation"),
            ):
                value = info.get(key)
                if isinstance(value, (int, float)):
                    parts.append(f"{label}={value:.1f}s")
            if isinstance(info.get("first_material_action_seconds"), (int, float)):
                parts.append(f"first_action={info['first_material_action_seconds']:.1f}s")
            if parts:
                lines.append(f"    - {analyzer_name}: {', '.join(parts)}")

    analyzer_results = getattr(result, "analyzer_results", {}) or {}
    overview_lines = _build_analyzer_overview_lines(analyzer_results)
    if overview_lines:
        lines.append("  分析器概览:")
        lines.extend(overview_lines)

    feedback_lines = _build_feedback_lines(analyzer_results)
    if feedback_lines:
        lines.append("  验证反馈:")
        lines.extend(feedback_lines)

    return lines


def build_failure_context_lines(result: Any) -> List[str]:
    """在失败分支补充每个分析器的状态，避免只看到总失败。"""
    analyzer_results = getattr(result, "analyzer_results", {}) or {}
    lines = _build_analyzer_overview_lines(analyzer_results)
    if not lines:
        return []
    return ["  分析器概览:", *lines]


def _build_analyzer_overview_lines(analyzer_results: Dict[str, Any]) -> List[str]:
    lines: List[str] = []
    for analyzer_name in ("csa", "codeql"):
        analyzer_info = analyzer_results.get(analyzer_name)
        if not isinstance(analyzer_info, dict) or not analyzer_info:
            continue
        validation = analyzer_info.get("validation", {}) if isinstance(analyzer_info.get("validation"), dict) else {}
        diagnostics_count = validation.get("diagnostics_count", 0) if validation else 0
        artifact_name = analyzer_info.get("artifact_display_name") or analyzer_info.get("checker_name") or analyzer_name
        headline = (
            f"    - {analyzer_name}: {artifact_name}"
            f" | 生成{_status_label(analyzer_info.get('success'))}"
            f" | 验证={_validation_state_label(analyzer_info.get('validation_state'))}"
            f" | 诊断={diagnostics_count}"
        )
        lines.append(headline)

        note = _first_highlight(analyzer_info)
        if note:
            lines.append(f"      关键点: {note}")
    return lines


def _build_feedback_lines(analyzer_results: Dict[str, Any]) -> List[str]:
    lines: List[str] = []
    for analyzer_name in ("csa", "codeql"):
        analyzer_info = analyzer_results.get(analyzer_name)
        if not isinstance(analyzer_info, dict) or not analyzer_info:
            continue
        records = int(analyzer_info.get("validation_feedback_records", 0) or 0)
        summary = str(analyzer_info.get("validation_feedback_summary", "") or "").strip()
        evidence_effectiveness = analyzer_info.get("evidence_effectiveness", {}) if isinstance(analyzer_info.get("evidence_effectiveness"), dict) else {}
        if records <= 0 and not summary:
            if not evidence_effectiveness.get("summary"):
                continue
        lines.append(f"    - {analyzer_name}: records={records}")
        if evidence_effectiveness.get("summary"):
            lines.append(f"      证据成效: {evidence_effectiveness.get('summary')}")
        if summary:
            first_line = summary.splitlines()[0].strip()
            if first_line:
                lines.append(f"      {first_line}")
    return lines


def _status_label(value: Any) -> str:
    if value is True:
        return "✅"
    if value is False:
        return "❌"
    return "—"


def _validation_state_label(state: Any) -> str:
    normalized = str(state or "").strip()
    labels = {
        "target_hit": "命中目标",
        "executed_no_hit": "仅执行成功",
        "execution_failed": "执行失败",
        "not_requested": "未验证",
        "generation_failed": "未生成",
        "no_result": "无结果",
    }
    return labels.get(normalized, "—")


def _first_highlight(analyzer_info: Dict[str, Any]) -> str:
    feedback_summary = str(analyzer_info.get("validation_feedback_summary", "") or "").strip()
    for line in feedback_summary.splitlines():
        cleaned = line.strip()
        if cleaned:
            return cleaned.removeprefix("- ")[:140]

    semantic_summary = str(analyzer_info.get("semantic_acceptance_summary", "") or "").strip()
    if semantic_summary:
        return semantic_summary[:140]

    error = str(analyzer_info.get("error", "") or "").strip()
    if error:
        return error.replace("\n", " ")[:140]

    return ""
