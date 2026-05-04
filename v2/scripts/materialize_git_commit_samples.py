#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Dict, List

from materialize_vul4c_samples import (
    DEFAULT_EXPERIMENT_ROOT,
    DEFAULT_MAIN_MANIFEST,
    MAIN_MANIFEST_HEADERS,
    _ensure_removed,
    _git_style_patch,
    _read_csv,
    _upsert_csv,
    _write_text,
)


DEFAULT_SELECTION = DEFAULT_EXPERIMENT_ROOT / "manifests" / "supplement_git_selection.csv"

SELECTION_HEADERS = [
    "sample_id",
    "source_dataset",
    "cve_id",
    "project",
    "repo_url",
    "fix_commit",
    "parent_commit",
    "target_relpath",
    "cwe_id",
    "vulnerability_type",
    "preferred_analyzer",
    "run_generate",
    "run_refine",
    "run_backend_compare",
    "selection_reason",
    "quality_notes",
    "reference_url",
    "patch_url",
]


def _run(command: List[str], cwd: Path) -> str:
    result = subprocess.run(
        command,
        cwd=str(cwd),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"command failed ({' '.join(command)}): {result.stderr.strip() or result.stdout.strip()}"
        )
    return result.stdout


def _ensure_repo_cache(row: Dict[str, str], cache_root: Path, force: bool = False) -> Path:
    project = row["project"].strip() or "unknown"
    fix_commit = row["fix_commit"].strip()
    repo_url = row["repo_url"].strip()
    if not repo_url:
        raise ValueError(f"{row['sample_id']}: repo_url is required")
    if not fix_commit:
        raise ValueError(f"{row['sample_id']}: fix_commit is required")

    repo_dir = cache_root / f"{project}__{fix_commit[:12]}" / "repo"
    if repo_dir.exists() and not force:
        return repo_dir

    _ensure_removed(repo_dir.parent)
    repo_dir.parent.mkdir(parents=True, exist_ok=True)
    _run(
        ["git", "clone", "--filter=blob:none", "--no-checkout", repo_url, str(repo_dir)],
        cwd=cache_root,
    )
    _run(["git", "rev-parse", f"{fix_commit}^{{commit}}"], cwd=repo_dir)
    return repo_dir


def _resolve_parent_commit(repo_dir: Path, fix_commit: str, explicit_parent: str) -> str:
    parent = explicit_parent.strip()
    if parent:
        _run(["git", "rev-parse", f"{parent}^{{commit}}"], cwd=repo_dir)
        return parent
    return _run(["git", "rev-parse", f"{fix_commit}^"], cwd=repo_dir).strip()


def _export_tree(repo_dir: Path, commit: str, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    archive = subprocess.Popen(
        ["git", "-C", str(repo_dir), "archive", commit],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert archive.stdout is not None
    tar_result = subprocess.run(
        ["tar", "-x", "-C", str(destination)],
        stdin=archive.stdout,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    archive.stdout.close()
    stderr = archive.stderr.read().decode("utf-8", errors="ignore") if archive.stderr else ""
    archive_rc = archive.wait()
    if archive_rc != 0:
        raise RuntimeError(f"git archive failed for {commit}: {stderr.strip()}")
    if tar_result.returncode != 0:
        raise RuntimeError(f"tar extract failed for {commit}: {tar_result.stderr.strip()}")


def _materialize_sample(
    row: Dict[str, str],
    *,
    experiment_root: Path,
    main_manifest_path: Path,
    cache_root: Path,
    force: bool,
) -> None:
    sample_id = row["sample_id"].strip()
    repo_dir = _ensure_repo_cache(row, cache_root=cache_root, force=force)
    fix_commit = row["fix_commit"].strip()
    parent_commit = _resolve_parent_commit(repo_dir, fix_commit, row.get("parent_commit", ""))
    target_relpath = row["target_relpath"].strip()
    if not target_relpath:
        raise ValueError(f"{sample_id}: target_relpath is required")

    sample_root = experiment_root / "datasets" / "curated" / sample_id
    vuln_dir = sample_root / "vulnerable"
    fixed_dir = sample_root / "fixed"
    patch_dir = sample_root / "patches"
    extra_dir = sample_root / "artifacts"

    if force:
        _ensure_removed(sample_root)
    sample_root.mkdir(parents=True, exist_ok=True)
    if vuln_dir.exists():
        _ensure_removed(vuln_dir)
    if fixed_dir.exists():
        _ensure_removed(fixed_dir)
    extra_dir.mkdir(parents=True, exist_ok=True)

    _export_tree(repo_dir, parent_commit, vuln_dir)
    _export_tree(repo_dir, fix_commit, fixed_dir)

    vuln_target = vuln_dir / target_relpath
    fixed_target = fixed_dir / target_relpath
    if not vuln_target.exists():
        raise FileNotFoundError(f"{sample_id}: target file missing in vulnerable tree: {vuln_target}")
    if not fixed_target.exists():
        raise FileNotFoundError(f"{sample_id}: target file missing in fixed tree: {fixed_target}")

    old_text = vuln_target.read_text(encoding="utf-8", errors="ignore")
    new_text = fixed_target.read_text(encoding="utf-8", errors="ignore")
    patch_text = _git_style_patch(target_relpath, old_text, new_text)
    if not patch_text.strip():
        raise RuntimeError(f"{sample_id}: empty generated patch")

    patch_path = patch_dir / "fix.patch"
    _write_text(patch_path, patch_text)

    upstream_full_patch = _run(["git", "show", "--format=email", "--patch", fix_commit], cwd=repo_dir)
    upstream_target_patch = _run(["git", "diff", parent_commit, fix_commit, "--", target_relpath], cwd=repo_dir)
    if upstream_target_patch.strip():
        _write_text(extra_dir / "upstream_target.patch", upstream_target_patch)
    _write_text(extra_dir / "upstream_full.patch", upstream_full_patch)

    metadata = {
        "sample_id": sample_id,
        "source_dataset": row["source_dataset"].strip(),
        "cve_id": row["cve_id"].strip(),
        "project": row["project"].strip(),
        "repo_url": row["repo_url"].strip(),
        "fix_commit": fix_commit,
        "parent_commit": parent_commit,
        "target_relpath": target_relpath,
        "cwe_id": row["cwe_id"].strip(),
        "vulnerability_type": row["vulnerability_type"].strip(),
        "reference_url": row.get("reference_url", "").strip(),
        "patch_url": row.get("patch_url", "").strip(),
    }
    _write_text(extra_dir / "sample_metadata.json", json.dumps(metadata, indent=2, ensure_ascii=False))

    quality_note = row.get("quality_notes", "").strip()
    if quality_note:
        quality_note += " | "
    quality_note += (
        "materialized_from=upstream_git; "
        f"repo_url={row['repo_url'].strip()}; "
        f"fix_commit={fix_commit}; "
        f"parent_commit={parent_commit}; "
        f"target_relpath={target_relpath}; "
        f"cve={row['cve_id'].strip()}"
    )

    manifest_row = {
        "sample_id": sample_id,
        "project": row["project"].strip(),
        "cwe_id": row["cwe_id"].strip(),
        "vulnerability_type": row["vulnerability_type"].strip(),
        "patch_path": str(patch_path.resolve()),
        "vulnerable_path": str(vuln_dir.resolve()),
        "fixed_path": str(fixed_dir.resolve()),
        "evidence_path": str(vuln_dir.resolve()),
        "preferred_analyzer": row["preferred_analyzer"].strip() or "csa",
        "run_generate": row["run_generate"].strip() or "true",
        "run_refine": row["run_refine"].strip() or "false",
        "run_backend_compare": row["run_backend_compare"].strip() or "false",
        "quality_status": "draft",
        "reviewer": "",
        "reviewed_at": "",
        "selection_reason": row["selection_reason"].strip(),
        "quality_notes": quality_note,
    }
    _upsert_csv(main_manifest_path, MAIN_MANIFEST_HEADERS, "sample_id", manifest_row)


def materialize_dataset(
    *,
    experiment_root: Path,
    selection_path: Path,
    main_manifest_path: Path,
    force: bool = False,
    sample_id: str | None = None,
    keep_going: bool = True,
) -> None:
    rows = _read_csv(selection_path, SELECTION_HEADERS)
    selected = [row for row in rows if not sample_id or row["sample_id"].strip() == sample_id]
    if sample_id and not selected:
        raise ValueError(f"sample_id not found in selection: {sample_id}")

    cache_root = experiment_root / "datasets" / "cache" / "git_commit_checkouts"
    failures: List[str] = []
    for index, row in enumerate(selected, start=1):
        sample = row["sample_id"].strip()
        print(f"[{index}/{len(selected)}] materializing {sample}", flush=True)
        try:
            _materialize_sample(
                row,
                experiment_root=experiment_root,
                main_manifest_path=main_manifest_path,
                cache_root=cache_root,
                force=force,
            )
        except Exception as exc:
            failures.append(f"{sample}: {exc}")
            print(f"FAILED {sample}: {exc}", flush=True)
            if not keep_going:
                break

    if failures:
        raise RuntimeError("materialization completed with failures:\n" + "\n".join(failures))


def main() -> None:
    parser = argparse.ArgumentParser(description="Materialize curated upstream git commit samples into v2_experiments.")
    parser.add_argument("--experiment-root", default=str(DEFAULT_EXPERIMENT_ROOT))
    parser.add_argument("--selection", default=str(DEFAULT_SELECTION))
    parser.add_argument("--main-manifest", default=str(DEFAULT_MAIN_MANIFEST))
    parser.add_argument("--sample-id")
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--stop-on-error", action="store_true")
    args = parser.parse_args()

    materialize_dataset(
        experiment_root=Path(args.experiment_root).expanduser().resolve(),
        selection_path=Path(args.selection).expanduser().resolve(),
        main_manifest_path=Path(args.main_manifest).expanduser().resolve(),
        force=bool(args.force),
        sample_id=args.sample_id,
        keep_going=not bool(args.stop_on_error),
    )


if __name__ == "__main__":
    main()
