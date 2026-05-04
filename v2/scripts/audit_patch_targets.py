#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import shlex
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT / "v2") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "v2"))

from src.experiments.runner import default_experiment_root, load_samples
from src.experiments.sample_env import prepare_sample_environment
from src.validation.codeql_support import build_codeql_search_path_args, ensure_codeql_pack, is_codeql_database_dir


SOURCE_EXTS = {".c", ".cc", ".cpp", ".cxx"}
AUDIT_HEADERS = [
    "sample_id",
    "project",
    "cwe_id",
    "version",
    "target_file",
    "patch_ranges",
    "compile_db_hit",
    "syntax_ok",
    "syntax_error",
    "codeql_db_ok",
    "codeql_file_hit",
    "codeql_hunk_ast_hit",
    "codeql_error",
    "checked_at",
]


@dataclass
class PatchTarget:
    old_path: str
    new_path: str
    old_ranges: List[Tuple[int, int]] = field(default_factory=list)
    new_ranges: List[Tuple[int, int]] = field(default_factory=list)


def _bool_text(value: object) -> str:
    return "true" if bool(value) else "false"


def _read_csv(path: Path) -> List[Dict[str, str]]:
    if not path.exists():
        return []
    with path.open("r", newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def _selected_samples(manifest_path: Path, requested_ids: Sequence[str]) -> List[object]:
    requested = {item.strip() for item in requested_ids if str(item).strip()}
    result = []
    for sample in load_samples(str(manifest_path)):
        if sample.quality_status.lower() != "approved":
            continue
        if not sample.run_generate:
            continue
        if requested and sample.sample_id not in requested:
            continue
        result.append(sample)
    return result


def _parse_patch_targets(patch_path: Path) -> List[PatchTarget]:
    targets: List[PatchTarget] = []
    current: Optional[PatchTarget] = None
    for raw_line in patch_path.read_text(encoding="utf-8", errors="replace").splitlines():
        if raw_line.startswith("diff --git "):
            parts = raw_line.split()
            old_path = _strip_patch_prefix(parts[2]) if len(parts) > 2 else ""
            new_path = _strip_patch_prefix(parts[3]) if len(parts) > 3 else old_path
            current = PatchTarget(old_path=old_path, new_path=new_path)
            targets.append(current)
            continue
        if current is None or not raw_line.startswith("@@"):
            continue
        old_range, new_range = _parse_hunk_header(raw_line)
        if old_range:
            current.old_ranges.append(old_range)
        if new_range:
            current.new_ranges.append(new_range)

    source_targets = []
    for target in targets:
        candidate = target.new_path or target.old_path
        if Path(candidate).suffix.lower() in SOURCE_EXTS:
            source_targets.append(target)
    return source_targets


def _strip_patch_prefix(path: str) -> str:
    token = str(path or "").strip()
    if token.startswith("a/") or token.startswith("b/"):
        return token[2:]
    return token


def _parse_hunk_header(line: str) -> Tuple[Optional[Tuple[int, int]], Optional[Tuple[int, int]]]:
    # Format: @@ -old_start,old_count +new_start,new_count @@
    parts = line.split()
    old_part = next((part for part in parts if part.startswith("-")), "")
    new_part = next((part for part in parts if part.startswith("+")), "")
    return _parse_range(old_part[1:]), _parse_range(new_part[1:])


def _parse_range(raw: str) -> Optional[Tuple[int, int]]:
    if not raw:
        return None
    if "," in raw:
        start_text, count_text = raw.split(",", 1)
    else:
        start_text, count_text = raw, "1"
    try:
        start = int(start_text)
        count = int(count_text)
    except ValueError:
        return None
    if count <= 0:
        return None
    return start, start + count - 1


def _load_compile_commands(version_root: Path) -> Dict[str, Dict[str, str]]:
    compile_db = version_root / ".patchweaver_env" / "compile_commands.json"
    if not compile_db.exists():
        return {}
    entries = json.loads(compile_db.read_text(encoding="utf-8"))
    result: Dict[str, Dict[str, str]] = {}
    for entry in entries:
        file_path = str(Path(str(entry.get("file", "") or "")).expanduser().resolve())
        if file_path:
            result[file_path] = entry
    return result


def _syntax_check(entry: Dict[str, str], timeout: int) -> Tuple[bool, str]:
    raw_command = str(entry.get("command", "") or "").strip()
    if not raw_command:
        return False, "empty compile command"
    tokens = shlex.split(raw_command)
    if not tokens:
        return False, "empty compile command"

    command = [tokens[0], "-fsyntax-only"]
    skip_next = False
    for index, token in enumerate(tokens[1:], start=1):
        if skip_next:
            skip_next = False
            continue
        if token in {"-c", "-o"}:
            skip_next = token == "-o"
            continue
        command.append(token)

    proc = subprocess.run(
        command,
        cwd=str(entry.get("directory", "") or "."),
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if proc.returncode == 0:
        return True, ""
    return False, ((proc.stderr or "") + "\n" + (proc.stdout or "")).strip()[:800]


def _ensure_codeql_database(version_root: Path, codeql_path: str, rebuild: bool, timeout: int) -> Tuple[bool, str]:
    db_path = version_root / ".patchweaver_env" / "codeql_db"
    if is_codeql_database_dir(str(db_path)) and not rebuild:
        return True, ""

    build_script = version_root / ".patchweaver_env" / "codeql_build.sh"
    if not build_script.exists():
        return False, f"missing build script: {build_script}"

    cmd = [
        codeql_path,
        "database",
        "create",
        str(db_path),
        "--language=cpp",
        f"--source-root={version_root}",
        "--overwrite",
        "--command",
        str(build_script),
    ]
    proc = subprocess.run(
        cmd,
        cwd=str(version_root),
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if proc.returncode == 0:
        return True, ""
    return False, ((proc.stderr or "") + "\n" + (proc.stdout or "")).strip()[-1200:]


def _write_codeql_target_query(query_path: Path, targets: Sequence[Tuple[str, List[Tuple[int, int]]]]) -> None:
    clauses = []
    for rel_path, ranges in targets:
        escaped = rel_path.replace("\\", "\\\\").replace('"', '\\"')
        if ranges:
            range_clause = " or ".join(
                f"(e.getLocation().getStartLine() >= {start} and e.getLocation().getStartLine() <= {end})"
                for start, end in ranges
            )
        else:
            range_clause = "false"
        clauses.append(
            f'(f.getRelativePath() = "{escaped}" and ({range_clause}))'
        )
    where_clause = "\n  or ".join(clauses) if clauses else "false"
    query_path.parent.mkdir(parents=True, exist_ok=True)
    query_path.write_text(
        "import cpp\n\n"
        "from File f, Element e\n"
        "where e.getFile() = f and (\n"
        f"  {where_clause}\n"
        ")\n"
        "select f.getRelativePath(), e.getLocation().getStartLine(), e.toString()\n",
        encoding="utf-8",
    )


def _run_codeql_hunk_query(
    version_root: Path,
    targets: Sequence[Tuple[str, List[Tuple[int, int]]]],
    codeql_path: str,
    timeout: int,
) -> Tuple[Dict[str, bool], Dict[str, bool], str]:
    db_path = version_root / ".patchweaver_env" / "codeql_db"
    query_path = version_root / ".patchweaver_env" / "patch_target_audit.ql"
    bqrs_path = version_root / ".patchweaver_env" / "patch_target_audit.bqrs"
    csv_path = version_root / ".patchweaver_env" / "patch_target_audit.csv"
    _write_codeql_target_query(query_path, targets)

    pack_dir, pack_error = ensure_codeql_pack(str(query_path), codeql_path, timeout, None)
    if pack_error:
        return {}, {}, pack_error

    run_cmd = [
        codeql_path,
        "query",
        "run",
        *build_codeql_search_path_args(codeql_path, None),
        "--database",
        str(db_path),
        "--output",
        str(bqrs_path),
        str(query_path),
    ]
    proc = subprocess.run(run_cmd, cwd=str(pack_dir), capture_output=True, text=True, timeout=timeout, check=False)
    if proc.returncode != 0:
        return {}, {}, ((proc.stderr or "") + "\n" + (proc.stdout or "")).strip()[-1200:]

    decode_cmd = [codeql_path, "bqrs", "decode", str(bqrs_path), "--format=csv", "--entities=all"]
    decoded = subprocess.run(decode_cmd, capture_output=True, text=True, timeout=timeout, check=False)
    if decoded.returncode != 0:
        return {}, {}, ((decoded.stderr or "") + "\n" + (decoded.stdout or "")).strip()[-1200:]
    csv_path.write_text(decoded.stdout or "", encoding="utf-8")

    file_hit = {rel_path: False for rel_path, _ in targets}
    hunk_hit = {f"{rel_path}:{start}-{end}": False for rel_path, ranges in targets for start, end in ranges}
    reader = csv.reader((decoded.stdout or "").splitlines())
    for row in reader:
        if len(row) < 3 or row[0] == "f.getRelativePath()":
            continue
        rel_path = row[0]
        try:
            line = int(row[1])
        except ValueError:
            continue
        if rel_path in file_hit:
            file_hit[rel_path] = True
        for target_rel, ranges in targets:
            if target_rel != rel_path:
                continue
            for start, end in ranges:
                if start <= line <= end:
                    hunk_hit[f"{target_rel}:{start}-{end}"] = True
    return file_hit, hunk_hit, ""


def _write_tables(csv_path: Path, md_path: Path, rows: Sequence[Dict[str, str]]) -> None:
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=AUDIT_HEADERS)
        writer.writeheader()
        writer.writerows(rows)
    lines = [
        "| " + " | ".join(AUDIT_HEADERS) + " |",
        "| " + " | ".join(["---"] * len(AUDIT_HEADERS)) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(str(row.get(header, "") or "").replace("|", "\\|") for header in AUDIT_HEADERS) + " |")
    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit whether formal experiment patch target files are compiled and indexed.")
    parser.add_argument("--experiment-root", default=str(default_experiment_root()))
    parser.add_argument("--manifest", default="")
    parser.add_argument("--sample-id", action="append", default=[])
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--codeql-path", default="/usr/local/bin/codeql")
    parser.add_argument("--syntax-timeout", type=int, default=90)
    parser.add_argument("--codeql-timeout", type=int, default=300)
    parser.add_argument("--rebuild-codeql", action="store_true")
    args = parser.parse_args()

    experiment_root = Path(args.experiment_root).expanduser().resolve()
    manifest_path = Path(args.manifest).expanduser().resolve() if args.manifest else experiment_root / "manifests" / "samples.csv"
    samples = _selected_samples(manifest_path, args.sample_id)
    if args.limit and args.limit > 0:
        samples = samples[: args.limit]

    rows: List[Dict[str, str]] = []
    checked_at = time.strftime("%Y-%m-%dT%H:%M:%S")
    print(f"pending_samples={len(samples)}", flush=True)
    for sample_index, sample in enumerate(samples, start=1):
        print(f"[{sample_index}/{len(samples)}] audit patch targets {sample.sample_id}", flush=True)
        prepare_sample_environment(sample)
        patch_targets = _parse_patch_targets(Path(sample.patch_path).expanduser().resolve())

        for version, root_raw in (("vulnerable", sample.vulnerable_path), ("fixed", sample.fixed_path)):
            version_root = Path(root_raw).expanduser().resolve()
            compile_commands = _load_compile_commands(version_root)
            version_targets: List[Tuple[str, List[Tuple[int, int]]]] = []
            for target in patch_targets:
                rel_path = target.old_path if version == "vulnerable" else target.new_path
                ranges = target.old_ranges if version == "vulnerable" else target.new_ranges
                if not rel_path:
                    continue
                version_targets.append((rel_path, ranges))

            codeql_ok, codeql_create_error = _ensure_codeql_database(
                version_root,
                args.codeql_path,
                args.rebuild_codeql,
                args.codeql_timeout,
            )
            file_hits: Dict[str, bool] = {}
            hunk_hits: Dict[str, bool] = {}
            query_error = ""
            if codeql_ok:
                file_hits, hunk_hits, query_error = _run_codeql_hunk_query(
                    version_root,
                    version_targets,
                    args.codeql_path,
                    args.codeql_timeout,
                )

            for rel_path, ranges in version_targets:
                source_path = str((version_root / rel_path).resolve())
                compile_entry = compile_commands.get(source_path)
                compile_hit = compile_entry is not None
                syntax_ok = False
                syntax_error = ""
                if compile_entry:
                    try:
                        syntax_ok, syntax_error = _syntax_check(compile_entry, args.syntax_timeout)
                    except subprocess.TimeoutExpired:
                        syntax_ok, syntax_error = False, f"syntax timeout after {args.syntax_timeout}s"

                range_keys = [f"{rel_path}:{start}-{end}" for start, end in ranges]
                hunk_ast_ok = bool(range_keys) and all(hunk_hits.get(key, False) for key in range_keys)
                row = {
                    "sample_id": sample.sample_id,
                    "project": sample.project,
                    "cwe_id": sample.cwe_id,
                    "version": version,
                    "target_file": rel_path,
                    "patch_ranges": ";".join(f"{start}-{end}" for start, end in ranges),
                    "compile_db_hit": _bool_text(compile_hit),
                    "syntax_ok": _bool_text(syntax_ok),
                    "syntax_error": syntax_error,
                    "codeql_db_ok": _bool_text(codeql_ok),
                    "codeql_file_hit": _bool_text(file_hits.get(rel_path, False)),
                    "codeql_hunk_ast_hit": _bool_text(hunk_ast_ok),
                    "codeql_error": query_error or codeql_create_error,
                    "checked_at": checked_at,
                }
                rows.append(row)

        _write_tables(
            experiment_root / "tables" / "patch_target_audit.csv",
            experiment_root / "tables" / "patch_target_audit.md",
            rows,
        )

    failed = [
        row for row in rows
        if row["compile_db_hit"] != "true"
        or row["syntax_ok"] != "true"
        or row["codeql_db_ok"] != "true"
        or row["codeql_file_hit"] != "true"
        or row["codeql_hunk_ast_hit"] != "true"
    ]
    print(f"checked_rows={len(rows)} failed_rows={len(failed)}", flush=True)
    for row in failed[:20]:
        print(
            "FAIL "
            f"{row['sample_id']} {row['version']} {row['target_file']} "
            f"compile={row['compile_db_hit']} syntax={row['syntax_ok']} "
            f"db={row['codeql_db_ok']} file={row['codeql_file_hit']} ast={row['codeql_hunk_ast_hit']} "
            f"err={(row['syntax_error'] or row['codeql_error'])[:180]}",
            flush=True,
        )
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
