#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import difflib
import hashlib
import json
import shutil
import subprocess
from pathlib import Path
from typing import Dict, Iterable, List


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_EXPERIMENT_ROOT = REPO_ROOT / "v2_experiments"
DEFAULT_SELECTION = DEFAULT_EXPERIMENT_ROOT / "manifests" / "vul4c_seed_selection.csv"
DEFAULT_MAIN_MANIFEST = DEFAULT_EXPERIMENT_ROOT / "manifests" / "samples.csv"
DEFAULT_VUL4C_ROOT = DEFAULT_EXPERIMENT_ROOT / "datasets" / "raw" / "SoK-Vul4C"

MAIN_MANIFEST_HEADERS = [
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

SELECTION_HEADERS = [
    "sample_id",
    "source_dataset",
    "cve_id",
    "project",
    "cwe_id",
    "vulnerability_type",
    "benchmark_relpath",
    "preferred_analyzer",
    "run_generate",
    "run_refine",
    "run_backend_compare",
    "selection_reason",
    "quality_notes",
]


def _read_csv(path: Path, headers: List[str]) -> List[Dict[str, str]]:
    if not path.exists():
        raise FileNotFoundError(path)
    with path.open("r", newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        rows: List[Dict[str, str]] = []
        for row in reader:
            normalized = {header: str((row or {}).get(header, "") or "") for header in headers}
            if any(value.strip() for value in normalized.values()):
                rows.append(normalized)
        return rows


def _upsert_csv(path: Path, headers: List[str], key_field: str, row: Dict[str, str]) -> None:
    rows = []
    if path.exists():
        with path.open("r", newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            for existing in reader:
                rows.append({header: str((existing or {}).get(header, "") or "") for header in headers})

    found = False
    normalized = {header: str(row.get(header, "") or "") for header in headers}
    for index, existing in enumerate(rows):
        if existing.get(key_field, "").strip() == normalized.get(key_field, "").strip():
            rows[index] = normalized
            found = True
            break
    if not found:
        rows.append(normalized)

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=headers)
        writer.writeheader()
        writer.writerows(rows)


def _parse_bool(raw: str, default: bool = False) -> bool:
    token = str(raw or "").strip().lower()
    if not token:
        return default
    return token in {"1", "true", "yes", "y", "on"}


def _ensure_removed(path: Path) -> None:
    if path.is_dir():
        shutil.rmtree(path)
    elif path.exists():
        path.unlink()


def _run_command(command: str, cwd: Path) -> None:
    result = subprocess.run(command, shell=True, cwd=str(cwd))
    if result.returncode != 0:
        raise RuntimeError(f"command failed: {command}")


def _load_vul4c_metadata(vul4c_root: Path) -> Dict[str, Dict[str, object]]:
    metadata_path = vul4c_root / "Vul4C_Src" / "Vul4C.json"
    return json.loads(metadata_path.read_text(encoding="utf-8"))


def _materialize_cache(meta: Dict[str, object], cache_root: Path, force: bool = False) -> Path:
    get_command = list(meta.get("get_command") or [])
    commit = ""
    for command in get_command:
        stripped = command.strip()
        if stripped.startswith("git checkout "):
            commit = stripped.split()[-1]
            break

    project = str(meta.get("project") or "unknown").strip()
    cache_token = commit
    if not cache_token:
        digest = hashlib.sha1("\n".join(get_command).encode("utf-8")).hexdigest()[:12]
        cache_token = f"{meta.get('cve_id', 'sample')}_{digest}"
    cache_dir = cache_root / f"{project}__{cache_token}"
    source_dir = cache_dir / "source"
    if source_dir.exists() and not force:
        return source_dir

    _ensure_removed(cache_dir)
    cache_dir.mkdir(parents=True, exist_ok=True)
    work_dir = cache_dir
    for command in get_command:
        stripped = command.strip()
        if stripped.startswith("cd "):
            work_dir = work_dir / stripped.split()[-1]
            continue
        _run_command(stripped, cwd=work_dir)
    if not source_dir.exists():
        raise RuntimeError(f"cache source missing for {meta.get('cve_id')}: {source_dir}")
    return source_dir


def _git_style_patch(target_relpath: str, old_text: str, new_text: str) -> str:
    diff_lines = list(
        difflib.unified_diff(
            old_text.splitlines(keepends=True),
            new_text.splitlines(keepends=True),
            fromfile=f"a/{target_relpath}",
            tofile=f"b/{target_relpath}",
            lineterm="",
        )
    )
    if not diff_lines:
        return ""
    patch_lines = [f"diff --git a/{target_relpath} b/{target_relpath}\n"]
    for line in diff_lines:
        if line.endswith("\n"):
            patch_lines.append(line)
        else:
            patch_lines.append(line + "\n")
    return "".join(patch_lines)


def _copy_tree(src: Path, dst: Path) -> None:
    shutil.copytree(src, dst, ignore=shutil.ignore_patterns(".git"))


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _materialize_sample(
    row: Dict[str, str],
    *,
    experiment_root: Path,
    vul4c_root: Path,
    vul4c_metadata: Dict[str, Dict[str, object]],
    cache_root: Path,
    force: bool,
) -> Dict[str, str]:
    cve_id = row["cve_id"].strip()
    meta = vul4c_metadata.get(cve_id)
    if not meta:
        raise KeyError(f"Vul4C metadata missing: {cve_id}")

    benchmark_relpath = row["benchmark_relpath"].strip()
    benchmark_dir = vul4c_root / "Vul4C-Benchmark" / benchmark_relpath
    if not benchmark_dir.exists():
        raise FileNotFoundError(benchmark_dir)

    old_file = next(benchmark_dir.glob("*_OLD.c"))
    new_file = next(benchmark_dir.glob("*_NEW.c"))
    original_diff = next(benchmark_dir.glob("*.diff"))
    readme = benchmark_dir / "README.txt"

    sample_root = experiment_root / "datasets" / "curated" / row["sample_id"].strip()
    vuln_dir = sample_root / "vulnerable"
    fixed_dir = sample_root / "fixed"
    patch_dir = sample_root / "patches"
    extra_dir = sample_root / "artifacts"

    if force:
        _ensure_removed(sample_root)
    sample_root.mkdir(parents=True, exist_ok=True)
    extra_dir.mkdir(parents=True, exist_ok=True)

    cache_source = _materialize_cache(meta, cache_root=cache_root, force=False)

    if vuln_dir.exists():
        _ensure_removed(vuln_dir)
    if fixed_dir.exists():
        _ensure_removed(fixed_dir)
    _copy_tree(cache_source, vuln_dir)
    _copy_tree(cache_source, fixed_dir)

    target_relpath = str(meta.get("file_name") or "").strip()
    if not target_relpath:
        raise RuntimeError(f"missing target file_name for {cve_id}")

    vuln_target = vuln_dir / target_relpath
    fixed_target = fixed_dir / target_relpath
    if not vuln_target.exists():
        raise FileNotFoundError(f"target file missing in vulnerable tree: {vuln_target}")
    if not fixed_target.exists():
        raise FileNotFoundError(f"target file missing in fixed tree: {fixed_target}")

    old_text = old_file.read_text(encoding="utf-8", errors="ignore")
    new_text = new_file.read_text(encoding="utf-8", errors="ignore")
    _write_text(vuln_target, old_text)
    _write_text(fixed_target, new_text)

    patch_text = _git_style_patch(target_relpath, old_text, new_text)
    if not patch_text.strip():
        raise RuntimeError(f"empty generated patch for {cve_id}")

    patch_path = patch_dir / "fix.patch"
    _write_text(patch_path, patch_text)
    shutil.copy2(original_diff, extra_dir / "vul4c_original.diff")
    if readme.exists():
        shutil.copy2(readme, extra_dir / "README.txt")

    metadata = {
        "sample_id": row["sample_id"],
        "source_dataset": row["source_dataset"],
        "cve_id": cve_id,
        "project": row["project"],
        "cwe_id": row["cwe_id"],
        "vulnerability_type": row["vulnerability_type"],
        "benchmark_relpath": benchmark_relpath,
        "target_relpath": target_relpath,
        "repo_commands": list(meta.get("get_command") or []),
    }
    _write_text(extra_dir / "sample_metadata.json", json.dumps(metadata, indent=2, ensure_ascii=False))

    quality_note = str(row.get("quality_notes", "") or "").strip()
    if quality_note:
        quality_note = quality_note + " | "
    quality_note += f"materialized_from=Vul4C; target_relpath={target_relpath}; cve={cve_id}"

    return {
        "sample_id": row["sample_id"],
        "project": row["project"],
        "cwe_id": row["cwe_id"],
        "vulnerability_type": row["vulnerability_type"],
        "patch_path": str(patch_path.resolve()),
        "vulnerable_path": str(vuln_dir.resolve()),
        "fixed_path": str(fixed_dir.resolve()),
        "evidence_path": str(vuln_dir.resolve()),
        "preferred_analyzer": row["preferred_analyzer"],
        "run_generate": row["run_generate"],
        "run_refine": row["run_refine"],
        "run_backend_compare": row["run_backend_compare"],
        "quality_status": "draft",
        "reviewer": "",
        "reviewed_at": "",
        "selection_reason": row["selection_reason"],
        "quality_notes": quality_note,
    }


def materialize_vul4c_dataset(
    *,
    experiment_root: Path,
    selection_path: Path,
    main_manifest_path: Path,
    vul4c_root: Path,
    force: bool = False,
    sample_id: str | None = None,
    keep_going: bool = True,
) -> None:
    rows = _read_csv(selection_path, SELECTION_HEADERS)
    selected = [
        row
        for row in rows
        if row["source_dataset"].strip().lower() == "vul4c" and (not sample_id or row["sample_id"].strip() == sample_id)
    ]
    if sample_id and not selected:
        raise ValueError(f"sample_id not found in selection: {sample_id}")

    cache_root = experiment_root / "datasets" / "cache" / "vul4c_checkouts"
    vul4c_metadata = _load_vul4c_metadata(vul4c_root)
    failures: List[str] = []
    for index, row in enumerate(selected, start=1):
        sample = row["sample_id"].strip()
        print(f"[{index}/{len(selected)}] materializing {sample}", flush=True)
        try:
            manifest_row = _materialize_sample(
                row,
                experiment_root=experiment_root,
                vul4c_root=vul4c_root,
                vul4c_metadata=vul4c_metadata,
                cache_root=cache_root,
                force=force,
            )
            _upsert_csv(main_manifest_path, MAIN_MANIFEST_HEADERS, "sample_id", manifest_row)
        except Exception as exc:
            failures.append(f"{sample}: {exc}")
            print(f"FAILED {sample}: {exc}", flush=True)
            if not keep_going:
                break

    if failures:
        raise RuntimeError("materialization completed with failures:\n" + "\n".join(failures))


def main() -> None:
    parser = argparse.ArgumentParser(description="Materialize selected Vul4C samples into v2_experiments.")
    parser.add_argument("--experiment-root", default=str(DEFAULT_EXPERIMENT_ROOT))
    parser.add_argument("--selection", default=str(DEFAULT_SELECTION))
    parser.add_argument("--main-manifest", default=str(DEFAULT_MAIN_MANIFEST))
    parser.add_argument("--vul4c-root", default=str(DEFAULT_VUL4C_ROOT))
    parser.add_argument("--sample-id")
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--stop-on-error", action="store_true")
    args = parser.parse_args()

    materialize_vul4c_dataset(
        experiment_root=Path(args.experiment_root).expanduser().resolve(),
        selection_path=Path(args.selection).expanduser().resolve(),
        main_manifest_path=Path(args.main_manifest).expanduser().resolve(),
        vul4c_root=Path(args.vul4c_root).expanduser().resolve(),
        force=bool(args.force),
        sample_id=args.sample_id,
        keep_going=not bool(args.stop_on_error),
    )


if __name__ == "__main__":
    main()
