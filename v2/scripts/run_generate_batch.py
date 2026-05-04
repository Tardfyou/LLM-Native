#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Set


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_EXPERIMENT_ROOT = REPO_ROOT / "v2_experiments"


def _read_csv(path: Path) -> List[Dict[str, str]]:
    if not path.exists():
        return []
    with path.open("r", newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def _approved_generate_samples(manifest_path: Path) -> List[str]:
    rows = _read_csv(manifest_path)
    return [
        str(row.get("sample_id", "") or "").strip()
        for row in rows
        if str(row.get("quality_status", "") or "").strip() == "approved"
        and str(row.get("run_generate", "") or "").strip().lower() == "true"
        and str(row.get("sample_id", "") or "").strip()
    ]


def _existing_generate_rows(table_path: Path) -> Set[str]:
    return {
        str(row.get("sample_id", "") or "").strip()
        for row in _read_csv(table_path)
        if str(row.get("sample_id", "") or "").strip()
    }


def _append_jsonl(path: Path, payload: Dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, ensure_ascii=False) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description="Run approved v2 generate experiments one sample at a time.")
    parser.add_argument("--experiment-root", default=str(DEFAULT_EXPERIMENT_ROOT))
    parser.add_argument("--manifest", default="")
    parser.add_argument("--resume", action="store_true", help="Skip samples already present in generate_results.csv")
    parser.add_argument("--limit", type=int, default=0, help="Only run the first N pending samples")
    parser.add_argument("--sample-id", action="append", default=[], help="Run only the specified sample_id (repeatable)")
    parser.add_argument("--stop-on-error", action="store_true")
    args = parser.parse_args()

    experiment_root = Path(args.experiment_root).expanduser().resolve()
    manifest_path = Path(args.manifest).expanduser().resolve() if args.manifest else experiment_root / "manifests" / "samples.csv"
    generate_table = experiment_root / "tables" / "generate_results.csv"
    progress_log = experiment_root / "logs" / "generate_batch_progress.jsonl"

    sample_ids = _approved_generate_samples(manifest_path)
    requested = {token.strip() for token in args.sample_id if str(token).strip()}
    if requested:
        sample_ids = [sample_id for sample_id in sample_ids if sample_id in requested]
    if args.resume:
        completed = _existing_generate_rows(generate_table)
        sample_ids = [sample_id for sample_id in sample_ids if sample_id not in completed]
    if args.limit and args.limit > 0:
        sample_ids = sample_ids[: args.limit]

    print(f"pending_samples={len(sample_ids)}", flush=True)
    if not sample_ids:
        return 0

    failures: List[str] = []
    total = len(sample_ids)
    for index, sample_id in enumerate(sample_ids, start=1):
        started_at = time.strftime("%Y-%m-%dT%H:%M:%S")
        print(f"[{index}/{total}] start {sample_id}", flush=True)
        _append_jsonl(progress_log, {"event": "started", "sample_id": sample_id, "index": index, "total": total, "at": started_at})

        cmd = [
            sys.executable,
            "-m",
            "src.main",
            "experiment",
            "run",
            "--root",
            str(experiment_root),
            "--sample-id",
            sample_id,
            "--generate-only",
        ]
        run_log_dir = experiment_root / "logs" / "generate_runs"
        run_log_dir.mkdir(parents=True, exist_ok=True)
        run_log_path = run_log_dir / f"{sample_id}.log"
        output_lines: List[str] = []
        proc = subprocess.Popen(
            cmd,
            cwd=str(REPO_ROOT / "v2"),
            env={**os.environ, "PYTHONPATH": str(REPO_ROOT / "v2")},
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        assert proc.stdout is not None
        with run_log_path.open("w", encoding="utf-8") as log_handle:
            for line in proc.stdout:
                output_lines.append(line)
                print(line, end="", flush=True)
                log_handle.write(line)
        proc.wait()

        row_present = sample_id in _existing_generate_rows(generate_table)
        status = "completed" if proc.returncode == 0 and row_present else "failed"
        _append_jsonl(
            progress_log,
            {
                "event": status,
                "sample_id": sample_id,
                "index": index,
                "total": total,
                "return_code": proc.returncode,
                "row_present": row_present,
                "at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            },
        )
        print(f"[{index}/{total}] {status} {sample_id} rc={proc.returncode} row_present={row_present}", flush=True)

        if proc.returncode != 0 or not row_present:
            failure = f"{sample_id}: rc={proc.returncode}, row_present={row_present}"
            failures.append(failure)
            failure_dir = experiment_root / "logs" / "generate_failures"
            failure_dir.mkdir(parents=True, exist_ok=True)
            (failure_dir / f"{sample_id}.combined.log").write_text("".join(output_lines), encoding="utf-8")
            if args.stop_on_error:
                break

    if failures:
        print("failures:", flush=True)
        for item in failures:
            print(f"  {item}", flush=True)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
