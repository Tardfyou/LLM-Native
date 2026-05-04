#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT / "v2") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "v2"))

from src.experiments.runner import default_experiment_root, load_samples
from src.experiments.sample_env import prepare_sample_environment
from src.validation.semantic_validator import SemanticValidator


AUDIT_HEADERS = [
    "sample_id",
    "project",
    "cwe_id",
    "preferred_analyzer",
    "vuln_prepare_strategy",
    "vuln_source_count",
    "fixed_prepare_strategy",
    "fixed_source_count",
    "csa_vuln_success",
    "csa_vuln_error",
    "csa_vuln_blocked",
    "csa_vuln_block_reason",
    "csa_fixed_success",
    "csa_fixed_error",
    "csa_fixed_blocked",
    "csa_fixed_block_reason",
    "codeql_vuln_success",
    "codeql_vuln_error",
    "codeql_fixed_success",
    "codeql_fixed_error",
    "checked_at",
]


def _bool_text(value: object) -> str:
    return "true" if bool(value) else "false"


def _select_samples(manifest_path: Path, sample_ids: List[str]) -> List[object]:
    requested = {item.strip() for item in sample_ids if str(item).strip()}
    rows = []
    for sample in load_samples(str(manifest_path)):
        if sample.quality_status.lower() != "approved":
            continue
        if not sample.run_generate:
            continue
        if requested and sample.sample_id not in requested:
            continue
        rows.append(sample)
    return rows


def _ensure_csv(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        return
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=AUDIT_HEADERS)
        writer.writeheader()


def _load_existing_rows(path: Path) -> Dict[str, Dict[str, str]]:
    if not path.exists():
        return {}
    with path.open("r", newline="", encoding="utf-8") as handle:
        return {
            str(row.get("sample_id", "") or "").strip(): row
            for row in csv.DictReader(handle)
            if str(row.get("sample_id", "") or "").strip()
        }


def _write_rows(path: Path, rows: Dict[str, Dict[str, str]]) -> None:
    ordered = [rows[key] for key in sorted(rows)]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=AUDIT_HEADERS)
        writer.writeheader()
        writer.writerows(ordered)


def _write_markdown(csv_path: Path, md_path: Path) -> None:
    with csv_path.open("r", newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    headers = AUDIT_HEADERS
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join(["---"] * len(headers)) + " |",
    ]
    for row in rows:
        values = [str(row.get(header, "") or "").replace("\n", " ").replace("|", "\\|") for header in headers]
        lines.append("| " + " | ".join(values) + " |")
    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _csa_payload(validator: SemanticValidator, checker_so: str, checker_name: str, target: str) -> Dict[str, str]:
    result = validator.validate_csa_checker(checker_so, checker_name, target)
    metadata = result.metadata or {}
    return {
        "success": _bool_text(result.success),
        "error": str(result.error_message or ""),
        "blocked": _bool_text(metadata.get("environment_blocked")),
        "block_reason": str(metadata.get("environment_block_reason", "") or ""),
    }


def _codeql_payload(validator: SemanticValidator, query_path: str, target: str) -> Dict[str, str]:
    database_root = str((Path(target).resolve() / ".patchweaver_env" / "codeql_db"))
    result = validator.validate_codeql_query(query_path, database_root, target_path=target)
    return {
        "success": _bool_text(result.success),
        "error": str(result.error_message or ""),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Prepare and smoke-audit selected experiment sample environments.")
    parser.add_argument("--experiment-root", default=str(default_experiment_root()))
    parser.add_argument("--manifest", default="")
    parser.add_argument("--sample-id", action="append", default=[])
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--csa-timeout", type=int, default=60)
    parser.add_argument("--codeql-timeout", type=int, default=180)
    parser.add_argument("--skip-csa", action="store_true")
    parser.add_argument("--skip-codeql", action="store_true")
    parser.add_argument("--checker-so", default=str(REPO_ROOT / "v2/tests/output/manual_buffer_guard_lab/csa/BufferOverflowChecker.so"))
    parser.add_argument("--checker-name", default="custom.BufferOverflowChecker")
    parser.add_argument("--codeql-query", default=str(REPO_ROOT / "v2_experiments/support/codeql_smoke/smoke.ql"))
    args = parser.parse_args()

    experiment_root = Path(args.experiment_root).expanduser().resolve()
    manifest_path = Path(args.manifest).expanduser().resolve() if args.manifest else experiment_root / "manifests" / "samples.csv"
    table_csv = experiment_root / "tables" / "environment_audit.csv"
    table_md = experiment_root / "tables" / "environment_audit.md"
    log_path = experiment_root / "logs" / "environment_audit.jsonl"

    _ensure_csv(table_csv)
    existing = _load_existing_rows(table_csv)
    samples = _select_samples(manifest_path, args.sample_id)
    if args.resume:
        samples = [sample for sample in samples if sample.sample_id not in existing]
    if args.limit and args.limit > 0:
        samples = samples[: args.limit]

    csa_validator = SemanticValidator({"timeout": args.csa_timeout, "clang_path": "/usr/lib/llvm-18/bin/clang++"})
    codeql_validator = SemanticValidator({"timeout": args.codeql_timeout, "codeql_path": "/usr/local/bin/codeql"})

    total = len(samples)
    print(f"pending_samples={total}", flush=True)
    for index, sample in enumerate(samples, start=1):
        print(f"[{index}/{total}] audit {sample.sample_id}", flush=True)
        prepared = prepare_sample_environment(sample)
        previous = existing.get(sample.sample_id, {})

        if args.skip_csa:
            vuln_csa = {
                "success": previous.get("csa_vuln_success", ""),
                "error": previous.get("csa_vuln_error", ""),
                "blocked": previous.get("csa_vuln_blocked", ""),
                "block_reason": previous.get("csa_vuln_block_reason", ""),
            }
            fixed_csa = {
                "success": previous.get("csa_fixed_success", ""),
                "error": previous.get("csa_fixed_error", ""),
                "blocked": previous.get("csa_fixed_blocked", ""),
                "block_reason": previous.get("csa_fixed_block_reason", ""),
            }
        else:
            vuln_csa = _csa_payload(csa_validator, args.checker_so, args.checker_name, sample.vulnerable_path)
            fixed_csa = _csa_payload(csa_validator, args.checker_so, args.checker_name, sample.fixed_path)

        if args.skip_codeql:
            vuln_codeql = {
                "success": previous.get("codeql_vuln_success", ""),
                "error": previous.get("codeql_vuln_error", ""),
            }
            fixed_codeql = {
                "success": previous.get("codeql_fixed_success", ""),
                "error": previous.get("codeql_fixed_error", ""),
            }
        else:
            vuln_codeql = _codeql_payload(codeql_validator, args.codeql_query, sample.vulnerable_path)
            fixed_codeql = _codeql_payload(codeql_validator, args.codeql_query, sample.fixed_path)

        row = {
            "sample_id": sample.sample_id,
            "project": sample.project,
            "cwe_id": sample.cwe_id,
            "preferred_analyzer": sample.preferred_analyzer,
            "vuln_prepare_strategy": str(prepared["versions"]["vulnerable"].get("strategy", "") or ""),
            "vuln_source_count": str(prepared["versions"]["vulnerable"].get("source_count", "") or ""),
            "fixed_prepare_strategy": str(prepared["versions"]["fixed"].get("strategy", "") or ""),
            "fixed_source_count": str(prepared["versions"]["fixed"].get("source_count", "") or ""),
            "csa_vuln_success": vuln_csa["success"],
            "csa_vuln_error": vuln_csa["error"],
            "csa_vuln_blocked": vuln_csa["blocked"],
            "csa_vuln_block_reason": vuln_csa["block_reason"],
            "csa_fixed_success": fixed_csa["success"],
            "csa_fixed_error": fixed_csa["error"],
            "csa_fixed_blocked": fixed_csa["blocked"],
            "csa_fixed_block_reason": fixed_csa["block_reason"],
            "codeql_vuln_success": vuln_codeql["success"],
            "codeql_vuln_error": vuln_codeql["error"],
            "codeql_fixed_success": fixed_codeql["success"],
            "codeql_fixed_error": fixed_codeql["error"],
            "checked_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        }
        existing[sample.sample_id] = row
        _write_rows(table_csv, existing)
        _write_markdown(table_csv, table_md)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with log_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")

        print(
            f"[{index}/{total}] done {sample.sample_id} "
            f"csa=({row['csa_vuln_success']},{row['csa_fixed_success']}) "
            f"codeql=({row['codeql_vuln_success']},{row['codeql_fixed_success']})",
            flush=True,
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
