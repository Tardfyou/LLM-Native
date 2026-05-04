from __future__ import annotations

import csv
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from loguru import logger

from ..core import Orchestrator
from .sample_env import prepare_sample_environment
from ..llm.usage import merge_usages, normalize_usage
from ..validation.semantic_validator import SemanticValidator


MANIFEST_HEADERS = [
    "sample_id",
    "project",
    "cwe_id",
    "vulnerability_type",
    "patch_path",
    "vulnerable_path",
    "fixed_path",
    "evidence_path",
    "preferred_analyzer",
    "run_generate",
    "run_refine",
    "run_backend_compare",
    "quality_status",
    "reviewer",
    "reviewed_at",
    "selection_reason",
    "quality_notes",
]

SAMPLE_REGISTRY_HEADERS = [
    "sample_id",
    "project",
    "cwe_id",
    "vulnerability_type",
    "preferred_analyzer",
    "run_generate",
    "run_refine",
    "run_backend_compare",
    "quality_status",
    "reviewer",
    "reviewed_at",
    "manual_review_ok",
    "review_requirements_missing",
    "preflight_ok",
    "run_eligible",
    "patch_exists",
    "vulnerable_exists",
    "fixed_exists",
    "evidence_exists",
    "distinct_versions",
    "patch_target_count",
    "patch_targets_present",
    "patch_targets_missing",
    "auto_findings",
    "audit_report",
]

GENERATE_RESULT_HEADERS = [
    "sample_id",
    "project",
    "cwe_id",
    "vulnerability_type",
    "analyzer",
    "run_started_at",
    "output_root",
    "report_path",
    "success",
    "generation_success",
    "semantic_success",
    "vuln_validation_blocked",
    "vuln_validation_block_reason",
    "vuln_validation_target",
    "vuln_hit",
    "vuln_diagnostics",
    "fixed_validation_success",
    "fixed_validation_blocked",
    "fixed_validation_block_reason",
    "fixed_validation_target",
    "fixed_silent",
    "fixed_diagnostics",
    "pds",
    "checker_name",
    "iterations",
    "compile_attempts",
    "artifact_total_lines",
    "artifact_nonempty_lines",
    "agent_prompt_tokens",
    "agent_completion_tokens",
    "agent_total_tokens",
    "pipeline_prompt_tokens",
    "pipeline_completion_tokens",
    "pipeline_total_tokens",
    "llm_calls",
    "total_seconds",
    "agent_seconds",
    "validation_seconds",
    "error_message",
]

REFINE_RESULT_HEADERS = [
    "sample_id",
    "project",
    "cwe_id",
    "vulnerability_type",
    "analyzer",
    "run_started_at",
    "input_root",
    "report_path",
    "baseline_success",
    "refine_success",
    "baseline_vuln_hit",
    "refine_vuln_hit",
    "baseline_vuln_diagnostics",
    "refine_vuln_diagnostics",
    "baseline_fixed_silent",
    "refine_fixed_silent",
    "baseline_fixed_diagnostics",
    "refine_fixed_diagnostics",
    "baseline_pds",
    "refine_pds",
    "baseline_nonempty_lines",
    "refined_nonempty_lines",
    "delta_nonempty_lines",
    "growth_ratio",
    "refinement_attempted",
    "refinement_adopted",
    "refinement_rounds",
    "iterations",
    "compile_attempts",
    "agent_prompt_tokens",
    "agent_completion_tokens",
    "agent_total_tokens",
    "pipeline_prompt_tokens",
    "pipeline_completion_tokens",
    "pipeline_total_tokens",
    "llm_calls",
    "total_seconds",
    "agent_seconds",
    "validation_seconds",
    "error_message",
]

BACKEND_RESULT_HEADERS = [
    "sample_id",
    "project",
    "cwe_id",
    "vulnerability_type",
    "run_started_at",
    "csa_success",
    "csa_vuln_hit",
    "csa_fixed_silent",
    "csa_pds",
    "csa_total_tokens",
    "csa_total_seconds",
    "codeql_success",
    "codeql_vuln_hit",
    "codeql_fixed_silent",
    "codeql_pds",
    "codeql_total_tokens",
    "codeql_total_seconds",
    "notes",
]

PERFORMANCE_RESULT_HEADERS = [
    "sample_id",
    "project",
    "cwe_id",
    "vulnerability_type",
    "primary_analyzer",
    "generate_total_seconds",
    "generate_agent_seconds",
    "generate_validation_seconds",
    "generate_agent_prompt_tokens",
    "generate_agent_completion_tokens",
    "generate_agent_total_tokens",
    "generate_pipeline_total_tokens",
    "generate_llm_calls",
    "generate_iterations",
    "generate_compile_attempts",
    "refine_total_seconds",
    "refine_agent_seconds",
    "refine_validation_seconds",
    "refine_agent_prompt_tokens",
    "refine_agent_completion_tokens",
    "refine_agent_total_tokens",
    "refine_pipeline_total_tokens",
    "refine_llm_calls",
    "refine_iterations",
    "refine_compile_attempts",
    "artifact_nonempty_lines_before",
    "artifact_nonempty_lines_after",
    "artifact_nonempty_delta",
]


@dataclass
class ExperimentSample:
    sample_id: str
    project: str
    cwe_id: str
    vulnerability_type: str
    patch_path: str
    vulnerable_path: str
    fixed_path: str
    evidence_path: str
    preferred_analyzer: str
    run_generate: bool
    run_refine: bool
    run_backend_compare: bool
    quality_status: str
    reviewer: str
    reviewed_at: str
    selection_reason: str
    quality_notes: str

    @classmethod
    def from_row(cls, row: Dict[str, str]) -> "ExperimentSample":
        sample_id = str(row.get("sample_id", "") or "").strip()
        if not sample_id:
            raise ValueError("sample_id 不能为空")
        return cls(
            sample_id=sample_id,
            project=str(row.get("project", "") or "").strip(),
            cwe_id=str(row.get("cwe_id", "") or "").strip(),
            vulnerability_type=str(row.get("vulnerability_type", "") or "").strip(),
            patch_path=str(row.get("patch_path", "") or "").strip(),
            vulnerable_path=str(row.get("vulnerable_path", "") or "").strip(),
            fixed_path=str(row.get("fixed_path", "") or "").strip(),
            evidence_path=str(row.get("evidence_path", "") or "").strip(),
            preferred_analyzer=str(row.get("preferred_analyzer", "") or "csa").strip() or "csa",
            run_generate=_parse_bool(row.get("run_generate", "true"), default=True),
            run_refine=_parse_bool(row.get("run_refine", "false"), default=False),
            run_backend_compare=_parse_bool(row.get("run_backend_compare", "false"), default=False),
            quality_status=str(row.get("quality_status", "") or "draft").strip() or "draft",
            reviewer=str(row.get("reviewer", "") or "").strip(),
            reviewed_at=str(row.get("reviewed_at", "") or "").strip(),
            selection_reason=str(row.get("selection_reason", "") or "").strip(),
            quality_notes=str(row.get("quality_notes", "") or "").strip(),
        )

    @property
    def evidence_root(self) -> str:
        return self.evidence_path or self.vulnerable_path

    @property
    def approved(self) -> bool:
        return self.quality_status.lower() == "approved"

    def to_manifest_row(self) -> Dict[str, str]:
        return {
            "sample_id": self.sample_id,
            "project": self.project,
            "cwe_id": self.cwe_id,
            "vulnerability_type": self.vulnerability_type,
            "patch_path": self.patch_path,
            "vulnerable_path": self.vulnerable_path,
            "fixed_path": self.fixed_path,
            "evidence_path": self.evidence_path,
            "preferred_analyzer": self.preferred_analyzer,
            "run_generate": _bool_text(self.run_generate),
            "run_refine": _bool_text(self.run_refine),
            "run_backend_compare": _bool_text(self.run_backend_compare),
            "quality_status": self.quality_status,
            "reviewer": self.reviewer,
            "reviewed_at": self.reviewed_at,
            "selection_reason": self.selection_reason,
            "quality_notes": self.quality_notes,
        }


@dataclass
class ExperimentLayout:
    root: Path
    manifest_path: Path
    tables_dir: Path
    audits_dir: Path
    runs_dir: Path

    @classmethod
    def from_root(cls, root: Optional[str] = None) -> "ExperimentLayout":
        resolved_root = Path(root).expanduser().resolve() if root else default_experiment_root()
        return cls(
            root=resolved_root,
            manifest_path=resolved_root / "manifests" / "samples.csv",
            tables_dir=resolved_root / "tables",
            audits_dir=resolved_root / "audits",
            runs_dir=resolved_root / "runs",
        )

    def ensure(self):
        (self.root / "manifests").mkdir(parents=True, exist_ok=True)
        self.tables_dir.mkdir(parents=True, exist_ok=True)
        self.audits_dir.mkdir(parents=True, exist_ok=True)
        self.runs_dir.mkdir(parents=True, exist_ok=True)

    def relpath(self, path_value: Any) -> str:
        raw = str(path_value or "").strip()
        if not raw:
            return ""
        path = Path(raw).expanduser()
        try:
            return str(path.resolve().relative_to(self.root))
        except Exception:
            return str(path.resolve())


def default_experiment_root() -> Path:
    return Path(__file__).resolve().parents[3] / "v2_experiments"


def init_experiment_root(root: Optional[str] = None, force: bool = False) -> ExperimentLayout:
    layout = ExperimentLayout.from_root(root)
    layout.ensure()

    _ensure_csv(layout.manifest_path, MANIFEST_HEADERS, force=force)
    _ensure_csv(layout.tables_dir / "sample_registry.csv", SAMPLE_REGISTRY_HEADERS, force=force)
    _ensure_csv(layout.tables_dir / "generate_results.csv", GENERATE_RESULT_HEADERS, force=force)
    _ensure_csv(layout.tables_dir / "refine_results.csv", REFINE_RESULT_HEADERS, force=force)
    _ensure_csv(layout.tables_dir / "backend_results.csv", BACKEND_RESULT_HEADERS, force=force)
    _ensure_csv(layout.tables_dir / "performance_results.csv", PERFORMANCE_RESULT_HEADERS, force=force)

    readme_path = layout.root / "README.md"
    if force or not readme_path.exists():
        readme_path.write_text(_experiment_readme(), encoding="utf-8")

    _refresh_markdown_tables(layout)
    return layout


def audit_manifest(root: Optional[str] = None, manifest_path: Optional[str] = None, sample_id: Optional[str] = None) -> Dict[str, Any]:
    layout = init_experiment_root(root=root, force=False)
    active_manifest_path = manifest_path or str(layout.manifest_path)
    samples = load_samples(active_manifest_path)
    selected = [sample for sample in samples if not sample_id or sample.sample_id == sample_id]
    if sample_id and not selected:
        raise ValueError(f"未找到样本: {sample_id}")

    audited = 0
    for sample in selected:
        audit = audit_sample(sample)
        _write_audit_report(layout, sample, audit)
        _upsert_row(
            layout.tables_dir / "sample_registry.csv",
            SAMPLE_REGISTRY_HEADERS,
            "sample_id",
            {
                **{key: sample.to_manifest_row().get(key, "") for key in SAMPLE_REGISTRY_HEADERS},
                "sample_id": sample.sample_id,
                "preferred_analyzer": sample.preferred_analyzer,
                "run_generate": _bool_text(sample.run_generate),
                "run_refine": _bool_text(sample.run_refine),
                "run_backend_compare": _bool_text(sample.run_backend_compare),
                "quality_status": sample.quality_status,
                "reviewer": sample.reviewer,
                "reviewed_at": sample.reviewed_at,
                "manual_review_ok": _bool_text(audit["manual_review_ok"]),
                "review_requirements_missing": " | ".join(audit["review_requirements_missing"]),
                "preflight_ok": _bool_text(audit["preflight_ok"]),
                "run_eligible": _bool_text(audit["run_eligible"]),
                "patch_exists": _bool_text(audit["patch_exists"]),
                "vulnerable_exists": _bool_text(audit["vulnerable_exists"]),
                "fixed_exists": _bool_text(audit["fixed_exists"]),
                "evidence_exists": _bool_text(audit["evidence_exists"]),
                "distinct_versions": _bool_text(audit["distinct_versions"]),
                "patch_target_count": str(audit["patch_target_count"]),
                "patch_targets_present": str(audit["patch_targets_present"]),
                "patch_targets_missing": "; ".join(audit["missing_patch_targets"]),
                "auto_findings": " | ".join(audit["findings"]),
                "audit_report": layout.relpath(audit["audit_report"]),
            },
        )
        audited += 1

    _refresh_markdown_tables(layout)
    return {
        "root": str(layout.root),
        "manifest": str(active_manifest_path),
        "audited": audited,
    }


def run_experiments(
    *,
    root: Optional[str] = None,
    manifest_path: Optional[str] = None,
    config_path: Optional[str] = None,
    sample_id: Optional[str] = None,
    run_all: bool = False,
    generate_only: bool = False,
) -> Dict[str, Any]:
    layout = init_experiment_root(root=root, force=False)
    active_manifest_path = manifest_path or str(layout.manifest_path)
    samples = load_samples(active_manifest_path)
    selected = _select_samples(samples, sample_id=sample_id, run_all=run_all, generate_only=generate_only)
    if not selected:
        raise ValueError("没有可运行的样本，请检查 manifest 或 sample_id。")

    audit_manifest(root=str(layout.root), manifest_path=active_manifest_path, sample_id=sample_id if not run_all else None)

    ineligible = []
    for sample in selected:
        audit = audit_sample(sample)
        gate = _sample_run_gate(sample, audit)
        if not gate["run_eligible"]:
            ineligible.append((sample.sample_id, gate))
    if ineligible:
        details = "; ".join(
            f"{sample_id}: {', '.join(gate['missing']) or '未通过样本审查'}"
            for sample_id, gate in ineligible
        )
        raise ValueError(
            "选中样本未全部通过审查，实验已停止。"
            "请先执行 experiment audit，逐样本确认后在 manifest 中填写 "
            "quality_status=approved、reviewer、reviewed_at、selection_reason。"
            f" 未通过样本: {details}"
        )

    executed = 0
    for sample in selected:
        audit = audit_sample(sample)

        primary_result = None
        refine_payload = None
        primary_analyzer = sample.preferred_analyzer
        if sample.run_generate:
            primary_result = _run_generate_pipeline(
                layout=layout,
                sample=sample,
                analyzer=primary_analyzer,
                config_path=config_path,
                bucket="primary",
            )
            _update_generate_tables(layout, sample, primary_result)
            executed += 1

        if sample.run_backend_compare and not generate_only:
            backend_notes: List[str] = []
            backend_payload: Dict[str, Any] = {
                "sample_id": sample.sample_id,
                "project": sample.project,
                "cwe_id": sample.cwe_id,
                "vulnerability_type": sample.vulnerability_type,
                "run_started_at": _now_text(),
            }
            for analyzer in ("csa", "codeql"):
                if primary_result and analyzer == primary_result["analyzer"]:
                    payload = primary_result
                    backend_notes.append(f"{analyzer} 复用 primary 结果")
                else:
                    payload = _run_generate_pipeline(
                        layout=layout,
                        sample=sample,
                        analyzer=analyzer,
                        config_path=config_path,
                        bucket="backend_compare",
                    )
                backend_payload.update({
                    f"{analyzer}_success": _bool_text(bool(payload["row"].get("success", False))),
                    f"{analyzer}_vuln_hit": _bool_text(bool(payload["row"].get("vuln_hit", False))),
                    f"{analyzer}_fixed_silent": _bool_text(bool(payload["row"].get("fixed_silent", False))),
                    f"{analyzer}_pds": _bool_text(bool(payload["row"].get("pds", False))),
                    f"{analyzer}_total_tokens": str(payload["row"].get("pipeline_total_tokens", "")),
                    f"{analyzer}_total_seconds": str(payload["row"].get("total_seconds", "")),
                })
            backend_payload["notes"] = " | ".join(backend_notes)
            _upsert_row(layout.tables_dir / "backend_results.csv", BACKEND_RESULT_HEADERS, "sample_id", backend_payload)

        if sample.run_refine and not generate_only:
            if primary_result is None:
                primary_result = _run_generate_pipeline(
                    layout=layout,
                    sample=sample,
                    analyzer=primary_analyzer,
                    config_path=config_path,
                    bucket="primary",
                )
                _update_generate_tables(layout, sample, primary_result)
                executed += 1
            refine_result = _run_refine_pipeline(
                layout=layout,
                sample=sample,
                primary_result=primary_result,
                config_path=config_path,
            )
            refine_payload = refine_result
            _update_refine_tables(layout, sample, primary_result, refine_result)

        if primary_result is not None and refine_payload is None:
            _update_performance_table(layout, sample, primary_result)

    _refresh_markdown_tables(layout)
    return {
        "root": str(layout.root),
        "manifest": str(active_manifest_path),
        "selected": len(selected),
        "executed": executed,
    }


def rebuild_table_exports(root: Optional[str] = None) -> Dict[str, Any]:
    layout = init_experiment_root(root=root, force=False)
    _refresh_markdown_tables(layout)
    return {"root": str(layout.root)}


def load_samples(manifest_path: str) -> List[ExperimentSample]:
    path = Path(manifest_path).expanduser().resolve()
    if not path.exists():
        raise FileNotFoundError(f"样本清单不存在: {path}")
    rows = _read_csv_rows(path, MANIFEST_HEADERS)
    samples: List[ExperimentSample] = []
    for row in rows:
        if not any(str(value or "").strip() for value in row.values()):
            continue
        samples.append(ExperimentSample.from_row(row))
    return samples


def audit_sample(sample: ExperimentSample) -> Dict[str, Any]:
    patch_path = Path(sample.patch_path).expanduser()
    vuln_path = Path(sample.vulnerable_path).expanduser()
    fixed_path = Path(sample.fixed_path).expanduser()
    evidence_path = Path(sample.evidence_root).expanduser()

    patch_exists = patch_path.exists() and patch_path.is_file()
    vulnerable_exists = vuln_path.exists()
    fixed_exists = fixed_path.exists()
    evidence_exists = evidence_path.exists()
    distinct_versions = str(vuln_path.resolve()) != str(fixed_path.resolve()) if vulnerable_exists and fixed_exists else False

    touched_files = _extract_patch_targets(patch_path) if patch_exists else []
    missing_targets = [
        rel
        for rel in touched_files
        if not _path_contains_patch_target(vuln_path, rel) and not _path_contains_patch_target(fixed_path, rel)
    ]

    findings: List[str] = []
    if not patch_exists:
        findings.append("patch 文件不存在")
    if not vulnerable_exists:
        findings.append("漏洞版本路径不存在")
    if not fixed_exists:
        findings.append("修复版本路径不存在")
    if not evidence_exists:
        findings.append("证据路径不存在")
    if not distinct_versions:
        findings.append("漏洞版本与修复版本路径相同或无法区分")
    if touched_files and missing_targets:
        findings.append("补丁涉及文件未在漏洞/修复版本中找到")
    if not touched_files:
        findings.append("补丁未解析出有效目标文件")

    preflight_ok = not findings[:]
    gate = _sample_run_gate(
        sample,
        {
            "preflight_ok": preflight_ok,
            "findings": findings,
        },
    )
    return {
        "sample_id": sample.sample_id,
        "patch_exists": patch_exists,
        "vulnerable_exists": vulnerable_exists,
        "fixed_exists": fixed_exists,
        "evidence_exists": evidence_exists,
        "distinct_versions": distinct_versions,
        "patch_target_count": len(touched_files),
        "patch_targets_present": len(touched_files) - len(missing_targets),
        "missing_patch_targets": missing_targets,
        "findings": findings,
        "preflight_ok": preflight_ok,
        "manual_review_ok": gate["manual_review_ok"],
        "review_requirements_missing": gate["missing"],
        "run_eligible": gate["run_eligible"],
        "audit_report": "",
    }


def _run_generate_pipeline(
    *,
    layout: ExperimentLayout,
    sample: ExperimentSample,
    analyzer: str,
    config_path: Optional[str],
    bucket: str,
) -> Dict[str, Any]:
    timestamp = _timestamp()
    output_root = layout.runs_dir / sample.sample_id / bucket / analyzer / timestamp
    output_root.mkdir(parents=True, exist_ok=True)
    event_log_path = output_root / "run_events.jsonl"
    prepare_sample_environment(sample)
    validate_target = _resolve_validation_target(
        sample=sample,
        version_root=Path(sample.vulnerable_path).expanduser().resolve(),
    )

    orchestrator = Orchestrator(config_path=config_path, analyzer=analyzer)
    on_progress = _event_logger(event_log_path, echo=True)
    result = orchestrator.generate(
        patch_path=str(Path(sample.patch_path).expanduser().resolve()),
        output_dir=str(output_root),
        validate_path=str(validate_target),
        on_progress=on_progress,
    )
    orchestrator.save_result(result, str(output_root))

    report_path = Path(getattr(result, "report_output_dir", "") or output_root) / "final_report.json"
    report_data = _read_json(report_path)
    analyzer_id = _resolve_report_analyzer_id(report_data, preferred=analyzer)
    fixed_validation = _validate_on_fixed(
        sample=sample,
        analyzer_id=analyzer_id,
        report_data=report_data,
        fixed_path=str(Path(sample.fixed_path).expanduser().resolve()),
        output_root=output_root,
        semantic_config=_semantic_config(config_path),
    )
    fixed_validation_path = output_root / "fixed_validation.json"
    fixed_validation_path.write_text(
        json.dumps(fixed_validation, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    row = _build_generate_row(
        sample=sample,
        analyzer_id=analyzer_id,
        report_data=report_data,
        fixed_validation=fixed_validation,
        output_root=output_root,
        report_path=report_path,
    )
    return {
        "analyzer": analyzer_id,
        "output_root": output_root,
        "report_path": report_path,
        "report_data": report_data,
        "fixed_validation": fixed_validation,
        "row": row,
    }


def _run_refine_pipeline(
    *,
    layout: ExperimentLayout,
    sample: ExperimentSample,
    primary_result: Dict[str, Any],
    config_path: Optional[str],
) -> Dict[str, Any]:
    input_root = Path(primary_result["output_root"]).resolve()
    analyzer_id = primary_result["analyzer"]
    prepare_sample_environment(sample)
    validate_target = _resolve_validation_target(
        sample=sample,
        version_root=Path(sample.vulnerable_path).expanduser().resolve(),
    )

    orchestrator = Orchestrator(config_path=config_path, analyzer=analyzer_id)
    _event_logger(input_root / "evidence_run_events.jsonl")
    evidence_result = orchestrator.collect_evidence(
        patch_path=str(Path(sample.patch_path).expanduser().resolve()),
        evidence_dir=str(Path(sample.evidence_root).expanduser().resolve()),
        output_dir=str(input_root),
        analyzer=analyzer_id,
        on_progress=_event_logger(input_root / "evidence_run_events.jsonl"),
    )
    if not evidence_result.success:
        raise RuntimeError(f"证据收集失败: {evidence_result.error_message}")

    refine_run_id = _timestamp()
    refine_event_log = input_root / "refinements" / refine_run_id / "run_events.jsonl"
    result = orchestrator.refine(
        input_dir=str(input_root),
        validate_path=str(validate_target),
        patch_path=str(Path(sample.patch_path).expanduser().resolve()),
        evidence_input_dir=str(input_root),
        analyzer=analyzer_id,
        on_progress=_event_logger(refine_event_log),
        run_id=refine_run_id,
    )
    orchestrator.save_result(result, str(input_root))
    report_root = Path(getattr(result, "report_output_dir", "") or input_root)
    report_path = report_root / "final_report.json"
    report_data = _read_json(report_path)
    fixed_validation = _validate_on_fixed(
        sample=sample,
        analyzer_id=analyzer_id,
        report_data=report_data,
        fixed_path=str(Path(sample.fixed_path).expanduser().resolve()),
        output_root=report_root,
        semantic_config=_semantic_config(config_path),
    )
    (report_root / "fixed_validation.json").write_text(
        json.dumps(fixed_validation, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return {
        "analyzer": analyzer_id,
        "input_root": input_root,
        "report_root": report_root,
        "report_path": report_path,
        "report_data": report_data,
        "fixed_validation": fixed_validation,
    }


def _update_generate_tables(layout: ExperimentLayout, sample: ExperimentSample, payload: Dict[str, Any]):
    _upsert_row_by_keys(layout.tables_dir / "generate_results.csv", GENERATE_RESULT_HEADERS, ("sample_id", "analyzer"), payload["row"])


def _update_refine_tables(
    layout: ExperimentLayout,
    sample: ExperimentSample,
    primary_result: Dict[str, Any],
    refine_result: Dict[str, Any],
):
    baseline_row = primary_result["row"]
    report_data = refine_result["report_data"]
    analyzer_id = refine_result["analyzer"]
    analyzer_info = report_data.get(analyzer_id, {}) if isinstance(report_data.get(analyzer_id), dict) else {}
    fixed_validation = refine_result["fixed_validation"]
    refine_artifact_delta = analyzer_info.get("artifact_delta", {}) if isinstance(analyzer_info.get("artifact_delta"), dict) else {}
    refine_usage = _pipeline_usage(report_data, analyzer_id)
    refine_metrics = _report_run_metrics(report_data, analyzer_id)
    checker_name = str(analyzer_info.get("checker_name", "") or "").strip()
    patch_targets = _extract_patch_targets(Path(sample.patch_path).expanduser())
    refine_validation = analyzer_info.get("validation", {}) if isinstance(analyzer_info.get("validation"), dict) else {}
    refine_vuln_diagnostics = _experiment_diagnostics_count(
        analyzer_id,
        refine_validation,
        checker_name,
        patch_targets,
    )
    refine_fixed_diagnostics = int((fixed_validation or {}).get("diagnostics_count", 0) or 0)
    baseline_nonempty_lines = int(str(baseline_row.get("artifact_nonempty_lines", "") or 0) or 0)
    refined_nonempty_lines = int(((analyzer_info.get("artifact_metrics", {}) or {}).get("nonempty_lines", 0) or 0))
    delta_nonempty_lines = str(refine_artifact_delta.get("delta_nonempty_lines", "") or "").strip()
    growth_ratio = str(refine_artifact_delta.get("growth_ratio", "") or "").strip()
    if (
        refined_nonempty_lines > 0
        and baseline_nonempty_lines >= 0
        and (
            not delta_nonempty_lines
            or delta_nonempty_lines == "0"
            and refined_nonempty_lines != baseline_nonempty_lines
        )
    ):
        computed_delta = refined_nonempty_lines - baseline_nonempty_lines
        delta_nonempty_lines = str(computed_delta)
        if baseline_nonempty_lines > 0:
            growth_ratio = str(round(refined_nonempty_lines / baseline_nonempty_lines, 6))
        else:
            growth_ratio = ""

    row = {
        "sample_id": sample.sample_id,
        "project": sample.project,
        "cwe_id": sample.cwe_id,
        "vulnerability_type": sample.vulnerability_type,
        "analyzer": analyzer_id,
        "run_started_at": _now_text(),
        "input_root": layout.relpath(refine_result["input_root"]),
        "report_path": layout.relpath(refine_result["report_path"]),
        "baseline_success": baseline_row.get("success", ""),
        "refine_success": _bool_text(bool(analyzer_info.get("success", False))),
        "baseline_vuln_hit": baseline_row.get("vuln_hit", ""),
        "refine_vuln_hit": _bool_text(bool(analyzer_info.get("semantic_target_hit", False))),
        "baseline_vuln_diagnostics": baseline_row.get("vuln_diagnostics", ""),
        "refine_vuln_diagnostics": str(refine_vuln_diagnostics),
        "baseline_fixed_silent": baseline_row.get("fixed_silent", ""),
        "refine_fixed_silent": _bool_text(_is_fixed_silent(fixed_validation)),
        "baseline_fixed_diagnostics": baseline_row.get("fixed_diagnostics", ""),
        "refine_fixed_diagnostics": str(refine_fixed_diagnostics),
        "baseline_pds": baseline_row.get("pds", ""),
        "refine_pds": _bool_text(bool(analyzer_info.get("semantic_target_hit", False)) and _is_fixed_silent(fixed_validation)),
        "baseline_nonempty_lines": baseline_row.get("artifact_nonempty_lines", ""),
        "refined_nonempty_lines": str(refined_nonempty_lines or ""),
        "delta_nonempty_lines": delta_nonempty_lines,
        "growth_ratio": growth_ratio,
        "refinement_attempted": _bool_text(bool(analyzer_info.get("refinement_attempted", False))),
        "refinement_adopted": _bool_text(bool(analyzer_info.get("refinement_adopted", False))),
        "refinement_rounds": str(analyzer_info.get("refinement_iterations_attempted", "")),
        "iterations": str(analyzer_info.get("iterations", "")),
        "compile_attempts": str(_extract_compile_attempts(report_data, analyzer_id)),
        "agent_prompt_tokens": str(refine_usage["agent"].get("prompt_tokens", 0)),
        "agent_completion_tokens": str(refine_usage["agent"].get("completion_tokens", 0)),
        "agent_total_tokens": str(refine_usage["agent"].get("total_tokens", 0)),
        "pipeline_prompt_tokens": str(refine_usage["total"].get("prompt_tokens", 0)),
        "pipeline_completion_tokens": str(refine_usage["total"].get("completion_tokens", 0)),
        "pipeline_total_tokens": str(refine_usage["total"].get("total_tokens", 0)),
        "llm_calls": str(refine_usage["total"].get("call_count", 0)),
        "total_seconds": str(refine_metrics.get("total_seconds", "")),
        "agent_seconds": str(refine_metrics.get("agent_seconds", "")),
        "validation_seconds": str(refine_metrics.get("validation_seconds", "")),
        "error_message": str((report_data.get("meta", {}) or {}).get("error_message", "") or analyzer_info.get("error", "") or ""),
    }
    _upsert_row_by_keys(
        layout.tables_dir / "refine_results.csv",
        REFINE_RESULT_HEADERS,
        ("sample_id", "analyzer"),
        row,
    )
    _update_performance_table(layout, sample, primary_result, refine_result=refine_result)


def _update_performance_table(
    layout: ExperimentLayout,
    sample: ExperimentSample,
    primary_result: Dict[str, Any],
    refine_result: Optional[Dict[str, Any]] = None,
):
    generate_row = primary_result["row"]
    row = {
        "sample_id": sample.sample_id,
        "project": sample.project,
        "cwe_id": sample.cwe_id,
        "vulnerability_type": sample.vulnerability_type,
        "primary_analyzer": primary_result["analyzer"],
        "generate_total_seconds": generate_row.get("total_seconds", ""),
        "generate_agent_seconds": generate_row.get("agent_seconds", ""),
        "generate_validation_seconds": generate_row.get("validation_seconds", ""),
        "generate_agent_prompt_tokens": generate_row.get("agent_prompt_tokens", ""),
        "generate_agent_completion_tokens": generate_row.get("agent_completion_tokens", ""),
        "generate_agent_total_tokens": generate_row.get("agent_total_tokens", ""),
        "generate_pipeline_total_tokens": generate_row.get("pipeline_total_tokens", ""),
        "generate_llm_calls": generate_row.get("llm_calls", ""),
        "generate_iterations": generate_row.get("iterations", ""),
        "generate_compile_attempts": generate_row.get("compile_attempts", ""),
        "refine_total_seconds": "",
        "refine_agent_seconds": "",
        "refine_validation_seconds": "",
        "refine_agent_prompt_tokens": "",
        "refine_agent_completion_tokens": "",
        "refine_agent_total_tokens": "",
        "refine_pipeline_total_tokens": "",
        "refine_llm_calls": "",
        "refine_iterations": "",
        "refine_compile_attempts": "",
        "artifact_nonempty_lines_before": generate_row.get("artifact_nonempty_lines", ""),
        "artifact_nonempty_lines_after": "",
        "artifact_nonempty_delta": "",
    }
    if refine_result is not None:
        refine_report = refine_result["report_data"]
        analyzer_id = refine_result["analyzer"]
        analyzer_info = refine_report.get(analyzer_id, {}) if isinstance(refine_report.get(analyzer_id), dict) else {}
        refine_usage = _pipeline_usage(refine_report, analyzer_id)
        refine_metrics = _report_run_metrics(refine_report, analyzer_id)
        delta = analyzer_info.get("artifact_delta", {}) if isinstance(analyzer_info.get("artifact_delta"), dict) else {}
        row.update({
            "refine_total_seconds": str(refine_metrics.get("total_seconds", "")),
            "refine_agent_seconds": str(refine_metrics.get("agent_seconds", "")),
            "refine_validation_seconds": str(refine_metrics.get("validation_seconds", "")),
            "refine_agent_prompt_tokens": str(refine_usage["agent"].get("prompt_tokens", 0)),
            "refine_agent_completion_tokens": str(refine_usage["agent"].get("completion_tokens", 0)),
            "refine_agent_total_tokens": str(refine_usage["agent"].get("total_tokens", 0)),
            "refine_pipeline_total_tokens": str(refine_usage["total"].get("total_tokens", 0)),
            "refine_llm_calls": str(refine_usage["total"].get("call_count", 0)),
            "refine_iterations": str(analyzer_info.get("iterations", "")),
            "refine_compile_attempts": str(_extract_compile_attempts(refine_report, analyzer_id)),
            "artifact_nonempty_lines_after": str(((analyzer_info.get("artifact_metrics", {}) or {}).get("nonempty_lines", ""))),
            "artifact_nonempty_delta": str(delta.get("delta_nonempty_lines", "")),
        })
    _upsert_row(layout.tables_dir / "performance_results.csv", PERFORMANCE_RESULT_HEADERS, "sample_id", row)


def _build_generate_row(
    *,
    sample: ExperimentSample,
    analyzer_id: str,
    report_data: Dict[str, Any],
    fixed_validation: Dict[str, Any],
    output_root: Path,
    report_path: Path,
) -> Dict[str, str]:
    analyzer_info = report_data.get(analyzer_id, {}) if isinstance(report_data.get(analyzer_id), dict) else {}
    meta = report_data.get("meta", {}) if isinstance(report_data.get("meta"), dict) else {}
    validation = analyzer_info.get("validation", {}) if isinstance(analyzer_info.get("validation"), dict) else {}
    artifact_metrics = analyzer_info.get("artifact_metrics", {}) if isinstance(analyzer_info.get("artifact_metrics"), dict) else {}
    pipeline_usage = _pipeline_usage(report_data, analyzer_id)
    run_metrics = _report_run_metrics(report_data, analyzer_id)
    checker_name = str(analyzer_info.get("checker_name", "") or "")
    patch_targets = _extract_patch_targets(Path(sample.patch_path).expanduser())
    vuln_diagnostics = _experiment_diagnostics_count(analyzer_id, validation, checker_name, patch_targets)
    fixed_diagnostics = _experiment_diagnostics_count(analyzer_id, fixed_validation, checker_name, patch_targets)
    vuln_hit = vuln_diagnostics > 0
    fixed_silent = _is_fixed_silent(fixed_validation)
    vuln_blocked = bool(validation.get("environment_blocked", False))
    fixed_blocked = bool(fixed_validation.get("environment_blocked", False))
    experiment_semantic_success = (not vuln_blocked) and vuln_hit
    success = experiment_semantic_success
    error_message = str(meta.get("error_message", "") or analyzer_info.get("error", "") or "")
    if (
        not success
        and not vuln_blocked
        and bool(meta.get("generation_success", analyzer_info.get("success", False)))
        and not error_message
    ):
        error_message = "检测器已生成，但未通过功能验证"
    return {
        "sample_id": sample.sample_id,
        "project": sample.project,
        "cwe_id": sample.cwe_id,
        "vulnerability_type": sample.vulnerability_type,
        "analyzer": analyzer_id,
        "run_started_at": _now_text(),
        "output_root": str(output_root),
        "report_path": str(report_path),
        "success": _bool_text(success),
        "generation_success": _bool_text(bool(meta.get("generation_success", analyzer_info.get("success", False)))),
        "semantic_success": _bool_text(experiment_semantic_success),
        "vuln_validation_blocked": _bool_text(vuln_blocked),
        "vuln_validation_block_reason": str(validation.get("environment_block_reason", "") or ""),
        "vuln_validation_target": str(validation.get("validation_target", "") or ""),
        "vuln_hit": "" if vuln_blocked else _bool_text(vuln_hit),
        "vuln_diagnostics": "" if vuln_blocked else str(vuln_diagnostics),
        "fixed_validation_success": _bool_text(bool(fixed_validation.get("success", False))),
        "fixed_validation_blocked": _bool_text(fixed_blocked),
        "fixed_validation_block_reason": str(fixed_validation.get("environment_block_reason", "") or ""),
        "fixed_validation_target": str(fixed_validation.get("validation_target", "") or ""),
        "fixed_silent": "" if fixed_blocked else _bool_text(fixed_silent),
        "fixed_diagnostics": "" if fixed_blocked else str(fixed_diagnostics),
        "pds": "" if vuln_blocked or fixed_blocked else _bool_text(vuln_hit and fixed_silent),
        "checker_name": checker_name,
        "iterations": str(analyzer_info.get("iterations", "")),
        "compile_attempts": str(_extract_compile_attempts(report_data, analyzer_id)),
        "artifact_total_lines": str(artifact_metrics.get("total_lines", "")),
        "artifact_nonempty_lines": str(artifact_metrics.get("nonempty_lines", "")),
        "agent_prompt_tokens": str(pipeline_usage["agent"].get("prompt_tokens", 0)),
        "agent_completion_tokens": str(pipeline_usage["agent"].get("completion_tokens", 0)),
        "agent_total_tokens": str(pipeline_usage["agent"].get("total_tokens", 0)),
        "pipeline_prompt_tokens": str(pipeline_usage["total"].get("prompt_tokens", 0)),
        "pipeline_completion_tokens": str(pipeline_usage["total"].get("completion_tokens", 0)),
        "pipeline_total_tokens": str(pipeline_usage["total"].get("total_tokens", 0)),
        "llm_calls": str(pipeline_usage["total"].get("call_count", 0)),
        "total_seconds": str(run_metrics.get("total_seconds", "")),
        "agent_seconds": str(run_metrics.get("agent_seconds", "")),
        "validation_seconds": str(run_metrics.get("validation_seconds", "")),
        "error_message": error_message,
    }


def _validate_on_fixed(
    *,
    sample: ExperimentSample,
    analyzer_id: str,
    report_data: Dict[str, Any],
    fixed_path: str,
    output_root: Path,
    semantic_config: Dict[str, Any],
) -> Dict[str, Any]:
    analyzer_info = report_data.get(analyzer_id, {}) if isinstance(report_data.get(analyzer_id), dict) else {}
    validator = SemanticValidator(semantic_config)
    fixed_target = _resolve_validation_target(
        sample=sample,
        version_root=Path(fixed_path).expanduser().resolve(),
    )
    if analyzer_id == "csa":
        so_path = str(analyzer_info.get("output_path", "") or "").strip()
        checker_name = str(analyzer_info.get("checker_name", "") or "").strip()
        result = validator.validate_csa_checker(
            checker_so_path=so_path,
            checker_name=f"custom.{checker_name}" if checker_name else "custom.Checker",
            target_path=str(fixed_target),
        )
    else:
        query_path = str(analyzer_info.get("output_path", "") or "").strip()
        database_dir = output_root / "fixed_version_codeql_db"
        result = validator.validate_codeql_query(
            query_path=query_path,
            database_path=str(database_dir),
            target_path=str(fixed_target),
        )
    diagnostics = getattr(result, "diagnostics", []) or []
    checker_name = str(analyzer_info.get("checker_name", "") or "").strip()
    patch_targets = _extract_patch_targets(Path(sample.patch_path).expanduser())
    diagnostics_count = _count_generated_diagnostics(analyzer_id, diagnostics, checker_name, patch_targets)
    generated_diagnostics_count = _count_generated_diagnostics(analyzer_id, diagnostics, checker_name)
    return {
        "success": bool(getattr(result, "success", False)),
        "error_message": str(getattr(result, "error_message", "") or ""),
        "diagnostics_count": diagnostics_count,
        "generated_diagnostics_count": generated_diagnostics_count,
        "all_diagnostics_count": len(diagnostics),
        "execution_time": float(getattr(result, "execution_time", 0.0) or 0.0),
        "environment_blocked": bool((getattr(result, "metadata", {}) or {}).get("environment_blocked", False)),
        "environment_block_reason": str((getattr(result, "metadata", {}) or {}).get("environment_block_reason", "") or ""),
        "validation_target": str(fixed_target),
        "patch_targets": patch_targets,
    }


def _resolve_validation_target(sample: ExperimentSample, version_root: Path) -> Path:
    root = version_root.expanduser().resolve()
    return root


def _experiment_diagnostics_count(
    analyzer_id: str,
    validation: Dict[str, Any],
    checker_name: str = "",
    patch_targets: Optional[List[str]] = None,
) -> int:
    diagnostics = validation.get("diagnostics") if isinstance(validation, dict) else None
    if isinstance(diagnostics, list):
        return _count_generated_diagnostics(analyzer_id, diagnostics, checker_name, patch_targets)
    return int((validation or {}).get("diagnostics_count", 0) or 0)


def _count_generated_diagnostics(
    analyzer_id: str,
    diagnostics: List[Any],
    checker_name: str = "",
    patch_targets: Optional[List[str]] = None,
) -> int:
    scoped = [
        diagnostic for diagnostic in diagnostics
        if _diagnostic_in_patch_targets(diagnostic, patch_targets)
    ]
    if analyzer_id != "csa":
        return len(scoped)
    return sum(1 for diagnostic in scoped if _is_generated_csa_diagnostic(diagnostic, checker_name))


def _diagnostic_in_patch_targets(diagnostic: Any, patch_targets: Optional[List[str]]) -> bool:
    targets = [str(target or "").strip().replace("\\", "/") for target in (patch_targets or []) if str(target or "").strip()]
    if not targets:
        return True
    if isinstance(diagnostic, dict):
        raw_path = str(diagnostic.get("file_path", diagnostic.get("path", "")) or "")
    else:
        raw_path = str(getattr(diagnostic, "file_path", "") or getattr(diagnostic, "path", "") or "")
    normalized = raw_path.replace("\\", "/")
    return any(normalized == target or normalized.endswith("/" + target) for target in targets)


def _is_generated_csa_diagnostic(diagnostic: Any, checker_name: str = "") -> bool:
    if isinstance(diagnostic, dict):
        values = [diagnostic.get(key, "") for key in ("message", "code", "checker", "check_name")]
    else:
        values = [getattr(diagnostic, key, "") for key in ("message", "code", "checker", "check_name")]
    text = " ".join(
        str(value or "")
        for value in values
    )
    expected = f"custom.{checker_name.strip()}" if checker_name.strip() else "custom."
    return expected in text


def _report_run_metrics(report_data: Dict[str, Any], analyzer_id: str) -> Dict[str, Any]:
    run_metrics = report_data.get("run_metrics", {}) if isinstance(report_data.get("run_metrics"), dict) else {}
    analyzers = run_metrics.get("analyzers", {}) if isinstance(run_metrics.get("analyzers"), dict) else {}
    return analyzers.get(analyzer_id, {}) if isinstance(analyzers.get(analyzer_id), dict) else {}


def _pipeline_usage(report_data: Dict[str, Any], analyzer_id: str) -> Dict[str, Dict[str, Any]]:
    patchweaver_usage = normalize_usage(((report_data.get("patchweaver") or {}).get("llm_usage", {}) if isinstance(report_data.get("patchweaver"), dict) else {}))
    analyzer_info = report_data.get(analyzer_id, {}) if isinstance(report_data.get(analyzer_id), dict) else {}
    analyzer_usage = normalize_usage(analyzer_info.get("llm_usage", {}))
    metrics = _report_run_metrics(report_data, analyzer_id)
    run_metrics_usage = {}
    if isinstance(metrics.get("llm_usage"), dict):
        run_metrics_usage = normalize_usage(((metrics.get("llm_usage") or {}).get("total", {})))
    top_metrics = report_data.get("run_metrics", {}) if isinstance(report_data.get("run_metrics"), dict) else {}
    overall_usage = normalize_usage(top_metrics.get("llm_usage", {}))
    total = overall_usage if overall_usage.get("available") else merge_usages([patchweaver_usage, analyzer_usage, run_metrics_usage])
    return {
        "patchweaver": patchweaver_usage,
        "agent": analyzer_usage,
        "run_metrics": run_metrics_usage,
        "total": total,
    }


def _extract_compile_attempts(report_data: Dict[str, Any], analyzer_id: str) -> int:
    analyzer_info = report_data.get(analyzer_id, {}) if isinstance(report_data.get(analyzer_id), dict) else {}
    return int(analyzer_info.get("compile_attempts", analyzer_info.get("iterations", 0)) or 0)


def _resolve_report_analyzer_id(report_data: Dict[str, Any], preferred: str) -> str:
    meta = report_data.get("meta", {}) if isinstance(report_data.get("meta"), dict) else {}
    analyzer_id = str(meta.get("analyzer_type", "") or preferred or "").strip().lower()
    if analyzer_id in {"csa", "codeql"}:
        return analyzer_id
    for candidate in ("csa", "codeql"):
        if isinstance(report_data.get(candidate), dict) and report_data.get(candidate):
            return candidate
    return preferred


def _event_logger(path: Path, *, echo: bool = False):
    path.parent.mkdir(parents=True, exist_ok=True)

    def on_progress(event_or_task_id, status_or_event=None, **kwargs):
        event_payload: Dict[str, Any]
        if isinstance(event_or_task_id, dict):
            event_payload = dict(event_or_task_id)
        elif isinstance(status_or_event, str):
            analyzer_name = kwargs.get("analyzer", "unknown")
            event_type = kwargs.get("event", status_or_event)
            event_payload = {"analyzer": analyzer_name, "event": event_type, **kwargs}
        else:
            event_payload = {"analyzer": event_or_task_id, "event": status_or_event, **kwargs}
        if "timestamp" not in event_payload:
            event_payload["timestamp"] = time.time()
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event_payload, ensure_ascii=False) + "\n")
        if echo:
            line = _format_progress_event_for_console(event_payload)
            if line:
                print(line, flush=True)

    return on_progress


def _format_progress_event_for_console(event: Dict[str, Any]) -> str:
    event_type = str(event.get("event", "") or "")
    analyzer = str(event.get("analyzer", "") or event.get("analyzer_name", "") or "unknown")
    prefix = f"[{analyzer}]"

    if event_type in {"pipeline_started", "generation_started"}:
        return f"{prefix} {event_type}"
    if event_type == "agent_tool_result":
        tool = str(event.get("tool_name", "") or "")
        success = bool(event.get("success", True))
        if success and tool not in {"codeql_analyze", "compile_checker", "lsp_validate", "review_artifact"}:
            return ""
        summary = _single_line(str(event.get("summary", "") or event.get("error", "") or ""), 500)
        status = "OK" if success else "FAIL"
        return f"{prefix} tool_result {tool or '-'} {status}: {summary}"
    if event_type == "agent_validation_failure":
        title = str(event.get("title", "") or "-")
        repeat = int(event.get("repeated_failure_count", 0) or 0)
        signature = _single_line(str(event.get("failure_signature", "") or ""), 300)
        preview = _single_line(str(event.get("preview", "") or ""), 700)
        return f"{prefix} validation_failure {title} repeat={repeat} sig={signature} diag={preview}"
    if event_type == "agent_repair_decision_started":
        title = str(event.get("latest_failure_title", "") or "-")
        repeat = int(event.get("repeated_failure_count", 0) or 0)
        preview = _single_line(str(event.get("latest_failure_preview", "") or ""), 500)
        return f"{prefix} repair_decision_started iteration={event.get('iteration', '-')} repeat={repeat} latest={title} diag={preview}"
    if event_type == "agent_repair_decision_completed":
        action = str(event.get("action", "") or "-")
        edits = int(event.get("edits_count", 0) or 0)
        summary = _single_line(str(event.get("summary", "") or ""), 500)
        return f"{prefix} repair_decision_completed iteration={event.get('iteration', '-')} action={action} edits={edits} summary={summary}"
    if event_type == "agent_repair_apply_failed":
        stage = str(event.get("stage", "") or "-")
        error = _single_line(str(event.get("error", "") or ""), 500)
        return f"{prefix} repair_apply_failed stage={stage}: {error}"
    if event_type == "agent_repair_applied":
        artifact = str(event.get("artifact_path", "") or "")
        return f"{prefix} repair_applied artifact={artifact}"
    if event_type == "agent_repair_loop_stopped":
        reason = str(event.get("reason", "") or "-")
        repeat = int(event.get("repeated_failure_count", 0) or 0)
        signature = _single_line(str(event.get("latest_failure_signature", "") or ""), 300)
        preview = _single_line(str(event.get("latest_failure_preview", "") or ""), 700)
        return f"{prefix} repair_loop_stopped reason={reason} repeat={repeat} sig={signature} diag={preview}"
    if event_type == "agent_run_completed":
        success = bool(event.get("success", False))
        iterations = int(event.get("iterations", 0) or 0)
        error = _single_line(str(event.get("error_message", "") or ""), 500)
        return f"{prefix} agent_run_completed success={success} iterations={iterations} error={error}"
    if event_type in {"generation_completed", "pipeline_failed", "portfolio_resolved"}:
        summary = _single_line(str(event.get("summary", "") or event.get("error", "") or ""), 500)
        return f"{prefix} {event_type}: {summary}"
    return ""


def _single_line(text: str, limit: int) -> str:
    compact = " ".join(str(text or "").split())
    return compact[:limit] + ("..." if len(compact) > limit else "")


def _select_samples(
    samples: List[ExperimentSample],
    *,
    sample_id: Optional[str],
    run_all: bool,
    generate_only: bool = False,
) -> List[ExperimentSample]:
    if sample_id:
        return [sample for sample in samples if sample.sample_id == sample_id]
    if run_all:
        if generate_only:
            return [sample for sample in samples if sample.run_generate]
        return list(samples)
    if generate_only:
        return [sample for sample in samples if sample.run_generate]
    return [sample for sample in samples if sample.run_generate or sample.run_refine or sample.run_backend_compare]


def _refresh_markdown_tables(layout: ExperimentLayout):
    for csv_name in (
        "sample_registry.csv",
        "generate_results.csv",
        "refine_results.csv",
        "backend_results.csv",
        "performance_results.csv",
    ):
        csv_path = layout.tables_dir / csv_name
        rows = _read_csv_rows(csv_path)
        md_path = csv_path.with_suffix(".md")
        md_path.write_text(_render_markdown_table(rows), encoding="utf-8")


def _render_markdown_table(rows: List[Dict[str, str]]) -> str:
    if not rows:
        return "当前无数据。\n"
    headers = list(rows[0].keys())
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(_markdown_escape(str(row.get(header, "") or "")) for header in headers) + " |")
    lines.append("")
    return "\n".join(lines)


def _markdown_escape(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", "<br>")


def _ensure_csv(path: Path, headers: List[str], *, force: bool = False):
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not force:
        existing_rows = _read_csv_rows(path)
        existing_headers = list(existing_rows[0].keys()) if existing_rows else []
        if existing_headers == headers:
            return
        normalized_rows = [{header: row.get(header, "") for header in headers} for row in existing_rows]
        with path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=headers)
            writer.writeheader()
            writer.writerows(normalized_rows)
        return
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=headers)
        writer.writeheader()


def _read_csv_rows(path: Path, headers: Optional[List[str]] = None) -> List[Dict[str, str]]:
    if not path.exists():
        return []
    with path.open("r", newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        rows = []
        for raw in reader:
            row = {key: str(value or "") for key, value in raw.items() if key is not None}
            if headers:
                for header in headers:
                    row.setdefault(header, "")
            rows.append(row)
        return rows


def _upsert_row(path: Path, headers: List[str], key_field: str, row: Dict[str, Any]):
    rows = _read_csv_rows(path, headers)
    normalized = {header: _stringify_cell(row.get(header, "")) for header in headers}
    found = False
    for index, existing in enumerate(rows):
        if str(existing.get(key_field, "") or "").strip() == str(normalized.get(key_field, "") or "").strip():
            rows[index] = normalized
            found = True
            break
    if not found:
        rows.append(normalized)

    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=headers)
        writer.writeheader()
        writer.writerows(rows)


def _upsert_row_by_keys(path: Path, headers: List[str], key_fields: tuple[str, ...], row: Dict[str, Any]):
    rows = _read_csv_rows(path, headers)
    normalized = {header: _stringify_cell(row.get(header, "")) for header in headers}

    def key_for(candidate: Dict[str, str]) -> tuple[str, ...]:
        return tuple(str(candidate.get(field, "") or "").strip() for field in key_fields)

    target_key = key_for(normalized)
    found = False
    for index, existing in enumerate(rows):
        if key_for(existing) == target_key:
            rows[index] = normalized
            found = True
            break
    if not found:
        rows.append(normalized)

    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=headers)
        writer.writeheader()
        writer.writerows(rows)


def _stringify_cell(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return _bool_text(value)
    return str(value)


def _read_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _semantic_config(config_path: Optional[str]) -> Dict[str, Any]:
    if not config_path:
        return {}
    config = _load_config(config_path)
    validation = config.get("validation", {}) if isinstance(config.get("validation"), dict) else {}
    semantic = validation.get("semantic", {}) if isinstance(validation.get("semantic"), dict) else {}
    return semantic


def _load_config(config_path: str) -> Dict[str, Any]:
    from ..utils import load_config

    return load_config(config_path)


def _write_audit_report(layout: ExperimentLayout, sample: ExperimentSample, audit: Dict[str, Any]):
    report_path = layout.audits_dir / f"{sample.sample_id}.md"
    findings = audit["findings"] or ["无自动预检问题"]
    review_missing = audit.get("review_requirements_missing", []) or ["无"]
    lines = [
        f"# 样本审查记录: {sample.sample_id}",
        "",
        "## 基本信息",
        f"- 项目: {sample.project or '未填写'}",
        f"- CWE: {sample.cwe_id or '未填写'}",
        f"- 漏洞类型: {sample.vulnerability_type or '未填写'}",
        f"- 预设分析器: {sample.preferred_analyzer}",
        f"- 质量状态: {sample.quality_status}",
        f"- 审核人: {sample.reviewer or '未填写'}",
        f"- 审核时间: {sample.reviewed_at or '未填写'}",
        "",
        "## 自动预检",
        f"- patch 存在: {_bool_text(audit['patch_exists'])}",
        f"- 漏洞版本存在: {_bool_text(audit['vulnerable_exists'])}",
        f"- 修复版本存在: {_bool_text(audit['fixed_exists'])}",
        f"- 证据路径存在: {_bool_text(audit['evidence_exists'])}",
        f"- 漏洞/修复版本已区分: {_bool_text(audit['distinct_versions'])}",
        f"- 补丁目标文件数: {audit['patch_target_count']}",
        f"- 已命中补丁目标文件: {audit['patch_targets_present']}",
        f"- 自动预检通过: {_bool_text(audit['preflight_ok'])}",
        "",
        "## 自动发现",
    ]
    for item in findings:
        lines.append(f"- {item}")
    lines.extend([
        "",
        "## 运行门禁",
        f"- 人工审查信息完整: {_bool_text(audit.get('manual_review_ok', False))}",
        f"- 允许进入正式实验: {_bool_text(audit.get('run_eligible', False))}",
        "- 缺失项:",
    ])
    for item in review_missing:
        lines.append(f"- {item}")
    lines.extend([
        "",
        "## 人工审查清单",
        "- [ ] 补丁主要描述单一且清晰的漏洞机制",
        "- [ ] 漏洞版本与修复版本配对准确",
        "- [ ] 样本适合静态分析验证",
        "- [ ] 可纳入正式实验",
        "",
        "## 备注",
        f"- 选择理由: {sample.selection_reason or '未填写'}",
        f"- 质量备注: {sample.quality_notes or '未填写'}",
        "",
    ])
    report_path.write_text("\n".join(lines), encoding="utf-8")
    audit["audit_report"] = str(report_path)


def _extract_patch_targets(patch_path: Path) -> List[str]:
    targets: List[str] = []
    try:
        text = patch_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return targets
    for line in text.splitlines():
        if line.startswith("+++ b/"):
            rel = line[len("+++ b/"):].strip()
            if rel and rel != "/dev/null" and rel not in targets:
                targets.append(rel)
        elif line.startswith("diff --git "):
            parts = line.split()
            if len(parts) >= 4 and parts[3].startswith("b/"):
                rel = parts[3][2:].strip()
                if rel and rel not in targets:
                    targets.append(rel)
    return targets


def _path_contains_patch_target(base_path: Path, rel_path: str) -> bool:
    if not base_path.exists():
        return False
    if base_path.is_file():
        return rel_path.endswith(base_path.name)
    candidate = (base_path / rel_path).resolve()
    if candidate.exists():
        return True
    return any(path.name == Path(rel_path).name for path in base_path.rglob(Path(rel_path).name))


def _review_requirements_missing(sample: ExperimentSample) -> List[str]:
    missing: List[str] = []
    if not sample.approved:
        missing.append("quality_status 不是 approved")
    if not sample.reviewer:
        missing.append("reviewer 未填写")
    if not sample.reviewed_at:
        missing.append("reviewed_at 未填写")
    if not sample.selection_reason:
        missing.append("selection_reason 未填写")
    return missing


def _sample_run_gate(sample: ExperimentSample, audit: Dict[str, Any]) -> Dict[str, Any]:
    review_missing = _review_requirements_missing(sample)
    manual_review_ok = not review_missing
    preflight_ok = bool(audit.get("preflight_ok", False))
    return {
        "manual_review_ok": manual_review_ok,
        "missing": review_missing,
        "run_eligible": manual_review_ok and preflight_ok,
    }


def _parse_bool(raw: Any, *, default: bool = False) -> bool:
    if raw is None:
        return default
    token = str(raw).strip().lower()
    if not token:
        return default
    if token in {"1", "true", "yes", "y", "on"}:
        return True
    if token in {"0", "false", "no", "n", "off"}:
        return False
    return default


def _bool_text(value: bool) -> str:
    return "true" if bool(value) else "false"


def _timestamp() -> str:
    return time.strftime("%Y%m%d_%H%M%S")


def _now_text() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def _is_fixed_silent(validation: Dict[str, Any]) -> bool:
    return bool(validation.get("success", False)) and int(validation.get("diagnostics_count", 0) or 0) == 0


def _experiment_readme() -> str:
    return """# v2 Experiments

该目录用于管理 `v2` 的正式实验资产，建议流程如下：

1. 在 `manifests/samples.csv` 中录入样本。
2. 先执行 `experiment audit` 生成样本审查记录。
3. 逐样本补全 `quality_status=approved`、`reviewer`、`reviewed_at`、`selection_reason`。
4. 仅当自动预检通过且人工审查信息完整时，样本才允许进入正式实验。
5. 执行 `experiment run --all` 批量跑实验。
6. 在 `tables/` 中查看自动汇总的 CSV 与 Markdown 表。

当前实验设计默认约定：
- 全量样本参与生成实验。
- 标记 `run_refine=true` 的子集参与证据收集与精炼实验。
- 标记 `run_backend_compare=true` 的样本参与 `CSA/CodeQL` 后端对比。
"""
