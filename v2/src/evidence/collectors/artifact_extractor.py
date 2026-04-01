"""
Project-backed artifact extraction for PATCHWEAVER evidence collectors.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import unquote, urlparse

from ...core.analyzer_base import AnalyzerContext
from ...tools.project_analyzer import ProjectAnalyzerTool
from ...validation.codeql_support import build_codeql_search_path_args, ensure_codeql_pack
from ...validation.codeql_support import (
    build_codeql_database_path,
    is_codeql_database_dir,
    resolve_codeql_database_path,
)


CONTROL_KEYWORDS = {
    "if",
    "for",
    "while",
    "switch",
    "return",
    "sizeof",
}

MEMORY_APIS = {
    "malloc",
    "calloc",
    "realloc",
    "free",
    "delete",
    "strcpy",
    "strncpy",
    "strcat",
    "strncat",
    "memcpy",
    "memmove",
}

LOCK_APIS = {
    "pthread_mutex_lock",
    "pthread_mutex_unlock",
    "pthread_rwlock_rdlock",
    "pthread_rwlock_wrlock",
    "pthread_rwlock_unlock",
    "atomic_store",
    "atomic_load",
    "atomic_exchange",
    "atomic_compare_exchange_strong",
}

DEFAULT_CLANG_CANDIDATES = [
    "/usr/lib/llvm-18/bin/clang",
    "/usr/bin/clang",
    "clang",
]
DEFAULT_CODEQL_CANDIDATES = [
    "/usr/local/bin/codeql",
    "/usr/bin/codeql",
    "codeql",
]
CODEQL_CLONE_LIMIT_BYTES = 256 * 1024 * 1024


@dataclass(frozen=True)
class SourceArtifactContext:
    """Concrete source/build artifacts anchored to a patch hunk."""

    patch_file: str
    resolved_file: str
    relative_file: str
    hunk_index: int
    anchor_line: int
    function_name: str
    parameters: List[str] = field(default_factory=list)
    guard_exprs: List[str] = field(default_factory=list)
    call_targets: List[str] = field(default_factory=list)
    lock_calls: List[str] = field(default_factory=list)
    memory_ops: List[str] = field(default_factory=list)
    globals: List[str] = field(default_factory=list)
    state_ops: List[str] = field(default_factory=list)
    source_excerpt: str = ""
    compile_command: str = ""
    compile_directory: str = ""
    include_flags: List[str] = field(default_factory=list)
    define_flags: List[str] = field(default_factory=list)

    def compile_command_preview(self) -> str:
        if not self.compile_command:
            return ""
        command = self.compile_command.strip()
        return command if len(command) <= 160 else f"{command[:157]}..."


class ProjectArtifactExtractor:
    """Extract concrete project/source/build artifacts for evidence collection."""

    FUNCTION_PATTERN = re.compile(
        r"^\s*(?:[A-Za-z_][\w\s\*\(\)]*?\s+)?([A-Za-z_]\w*)\s*\(([^;{}]*)\)\s*\{?\s*$"
    )
    HUNK_PATTERN = re.compile(
        r"^@@ -(?P<old_start>\d+)(?:,(?P<old_count>\d+))? \+(?P<new_start>\d+)(?:,(?P<new_count>\d+))? @@"
    )

    def collect_source_contexts(
        self,
        context: AnalyzerContext,
        radius: int = 8,
    ) -> Tuple[List[SourceArtifactContext], Dict[str, Any]]:
        project_root = self.project_root(context)
        project_info = self.project_info(project_root)
        compile_commands = self.compile_commands(project_info)
        project_include_flags, project_define_flags = self.aggregate_project_flags(compile_commands)

        source_contexts: List[SourceArtifactContext] = []
        for patch_file in self.parse_patch(context.patch_path):
            resolved = self.resolve_project_file(project_root, patch_file.get("old_path") or patch_file.get("new_path") or "")
            if resolved is None or not resolved.exists():
                continue

            try:
                lines = resolved.read_text(encoding="utf-8", errors="ignore").splitlines()
            except Exception:
                continue

            compile_entry = self.find_compile_entry(resolved, compile_commands)
            compile_command = str(compile_entry.get("command", "") or "")
            compile_directory = str(compile_entry.get("directory", "") or "")
            include_flags, define_flags = self.extract_compile_flags(compile_command)
            if not include_flags:
                include_flags = list(project_include_flags)
            if not define_flags:
                define_flags = list(project_define_flags)
            if not compile_directory and compile_commands:
                compile_directory = str(compile_commands[0].get("directory", "") or project_root)

            for hunk_index, hunk in enumerate(patch_file.get("hunks", []) or []):
                for anchor_line in self.derive_anchor_lines(lines, hunk):
                    if anchor_line <= 0 or anchor_line > len(lines):
                        continue

                    window_excerpt, window_lines = self.read_window(lines, anchor_line, radius=radius)
                    function_name, parameters = self.find_function_context(lines, anchor_line)
                    call_targets = self.extract_call_targets(window_lines)
                    guard_exprs = self.extract_guard_exprs(window_lines)
                    globals_seen = self.extract_globals(window_lines)
                    memory_ops = [name for name in call_targets if name in MEMORY_APIS]
                    lock_calls = [name for name in call_targets if name in LOCK_APIS or "lock" in name]
                    state_ops = self.extract_state_ops(window_lines, globals_seen)

                    source_contexts.append(
                        SourceArtifactContext(
                            patch_file=str(patch_file.get("old_path") or patch_file.get("new_path") or ""),
                            resolved_file=str(resolved),
                            relative_file=self.relative_to(project_root, resolved),
                            hunk_index=hunk_index,
                            anchor_line=anchor_line,
                            function_name=function_name,
                            parameters=parameters,
                            guard_exprs=guard_exprs,
                            call_targets=call_targets,
                            lock_calls=lock_calls,
                            memory_ops=memory_ops,
                            globals=globals_seen,
                            state_ops=state_ops,
                            source_excerpt=window_excerpt,
                            compile_command=compile_command,
                            compile_directory=compile_directory,
                            include_flags=include_flags,
                            define_flags=define_flags,
                        )
                    )

        artifact_meta = {
            "project_root": str(project_root),
            "project_info": project_info,
            "compile_commands_count": len(compile_commands),
        }
        return source_contexts, artifact_meta

    def derive_anchor_lines(self, lines: List[str], hunk: Dict[str, Any]) -> List[int]:
        anchors: List[int] = []
        old_start = int(hunk.get("old_start", 0) or 0)
        old_count = int(hunk.get("old_count", 0) or 0)
        new_start = int(hunk.get("new_start", 0) or 0)

        if old_start > 0:
            anchors.append(old_start)
            if old_count > 6:
                anchors.append(min(len(lines), old_start + max(old_count // 2, 1)))
        elif new_start > 0:
            anchors.append(new_start)

        removed_lines = [str(item).strip() for item in (hunk.get("removed_lines", []) or [])]
        for removed_line in removed_lines:
            if not removed_line or removed_line.startswith("#"):
                continue
            for index, source_line in enumerate(lines, start=1):
                if source_line.strip() == removed_line:
                    anchors.append(index)
                    break

        return self._dedupe_ints(anchors)[:6]

    def collect_codeql_artifacts(self, context: AnalyzerContext) -> Dict[str, Any]:
        project_root = self.project_root(context)
        target_path = context.validate_path or str(project_root)
        configured_base = str(((context.shared_analysis or {}).get("codeql_database_path", "")) or "")
        if not configured_base:
            configured_base = str(((context.shared_analysis or {}).get("codeql", {}) or {}).get("database_path", ""))
        if not configured_base:
            configured_base = str((Path(context.output_dir or ".").resolve() / "codeql" / "database").resolve())

        resolved_base, resolution_message = resolve_codeql_database_path(configured_base, target_path)
        runtime_database = build_codeql_database_path(resolved_base, target_path)
        runtime_database = str(Path(runtime_database).expanduser().resolve())
        build_script = project_root / "codeql_build.sh"

        return {
            "database_path": runtime_database,
            "database_exists": is_codeql_database_dir(runtime_database),
            "database_resolution": resolution_message or "",
            "build_script": str(build_script) if build_script.exists() else "",
            "build_script_exists": build_script.exists(),
        }

    def collect_csa_runtime_artifacts(
        self,
        context: AnalyzerContext,
        source_contexts: List[SourceArtifactContext],
    ) -> Dict[str, Any]:
        cache_key = {
            "cache_version": 3,
            "patch_path": str(Path(context.patch_path).expanduser().resolve()),
            "validate_path": str(Path(context.validate_path or "").expanduser().resolve()) if context.validate_path else "",
            "source_files": sorted({item.relative_file for item in source_contexts}),
        }
        cached = self._load_runtime_cache(context, "csa_runtime_artifacts.json", cache_key)
        if cached is not None:
            return cached

        clang_path = self.resolve_executable(DEFAULT_CLANG_CANDIDATES)
        if not clang_path:
            payload = {
                "available": False,
                "clang_path": "",
                "cfg_snapshots": [],
                "call_edges": [],
                "error": "clang not available",
            }
            self._store_runtime_cache(context, "csa_runtime_artifacts.json", cache_key, payload)
            return payload

        project_root = self.project_root(context)
        targets = self._select_runtime_targets(source_contexts, limit=3)
        snapshots: List[Dict[str, Any]] = []
        aggregated_edges: List[str] = []
        for item in targets:
            command = self._build_csa_debug_command(
                clang_path=clang_path,
                source_context=item,
                project_root=project_root,
            )
            if not command:
                continue

            try:
                proc = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    timeout=30,
                    cwd=item.compile_directory or str(project_root),
                )
            except Exception as exc:
                snapshots.append({
                    "source_file": item.relative_file,
                    "function_name": item.function_name,
                    "anchor_line": item.anchor_line,
                    "branch_kinds": [],
                    "call_edges": [],
                    "call_targets": [],
                    "clang_command_preview": self.command_preview(command),
                    "dump_excerpt": "",
                    "error": str(exc),
                })
                continue

            raw_output = "\n".join(
                chunk
                for chunk in (proc.stderr or "", proc.stdout or "")
                if chunk
            )
            parsed = self._parse_csa_debug_dump(raw_output, item)
            parsed["clang_command_preview"] = self.command_preview(command)
            parsed["return_code"] = proc.returncode
            snapshots.append(parsed)
            aggregated_edges.extend(parsed.get("call_edges", []) or [])

        payload = {
            "available": bool(snapshots),
            "clang_path": clang_path,
            "cfg_snapshots": snapshots,
            "call_edges": self._dedupe(aggregated_edges)[:24],
            "error": "",
        }
        self._store_runtime_cache(context, "csa_runtime_artifacts.json", cache_key, payload)
        return payload

    def collect_codeql_runtime_artifacts(
        self,
        context: AnalyzerContext,
        source_contexts: List[SourceArtifactContext],
        project_info: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        base = self.collect_codeql_artifacts(context)
        project_root = self.project_root(context)
        database_path = str(base.get("database_path", "") or "")
        cache_key = {
            "cache_version": 3,
            "patch_path": str(Path(context.patch_path).expanduser().resolve()),
            "validate_path": str(Path(context.validate_path or "").expanduser().resolve()) if context.validate_path else "",
            "database_path": database_path,
            "source_files": sorted({item.relative_file for item in source_contexts}),
        }
        cached = self._load_runtime_cache(context, "codeql_runtime_artifacts.json", cache_key)
        if cached is not None:
            return cached

        payload = dict(base)
        payload.update({
            "codeql_path": "",
            "database_create_attempted": False,
            "database_create_message": "",
            "database_metadata": {},
            "baseline_files": [],
            "baseline_loc": 0,
            "live_inventory": {
                "status": "skipped",
                "functions": [],
                "call_edges": [],
                "target_files": [],
                "used_temp_copy": False,
                "error": "",
            },
            "existing_findings": [],
            "existing_findings_count": 0,
        })

        codeql_path = self.resolve_executable(DEFAULT_CODEQL_CANDIDATES)
        payload["codeql_path"] = codeql_path

        if database_path and not is_codeql_database_dir(database_path):
            ok, message = self._ensure_codeql_database(
                database_path=database_path,
                target_path=context.validate_path or str(project_root),
                codeql_path=codeql_path,
                build_script=str(base.get("build_script", "") or ""),
            )
            payload["database_create_attempted"] = bool(codeql_path)
            payload["database_create_message"] = message
            payload["database_exists"] = is_codeql_database_dir(database_path)
            if not ok and message and not payload.get("database_resolution"):
                payload["database_resolution"] = message

        if not database_path or not is_codeql_database_dir(database_path):
            payload["live_inventory"]["status"] = "database_missing"
            payload["live_inventory"]["error"] = (
                payload.get("database_create_message")
                or payload.get("database_resolution")
                or "codeql database unavailable"
            )
            self._store_runtime_cache(context, "codeql_runtime_artifacts.json", cache_key, payload)
            return payload

        payload["database_metadata"] = self._resolve_codeql_database_metadata(database_path)
        baseline = self._load_json_file(Path(database_path) / "baseline-info.json")
        cpp_info = ((baseline.get("languages") or {}).get("cpp") or {}) if isinstance(baseline, dict) else {}
        payload["baseline_files"] = list(cpp_info.get("files", []) or [])[:200]
        payload["baseline_loc"] = int(cpp_info.get("linesOfCode", 0) or 0)
        payload["existing_findings"] = self._find_existing_codeql_findings(context)
        payload["existing_findings_count"] = len(payload["existing_findings"])

        target_files = self._build_codeql_target_files(
            context=context,
            source_contexts=source_contexts,
            project_root=project_root,
            project_info=project_info or {},
            baseline_files=payload["baseline_files"],
        )
        payload["live_inventory"]["target_files"] = list(target_files)

        if not codeql_path or not target_files:
            payload["live_inventory"]["status"] = "unavailable"
            payload["live_inventory"]["error"] = "codeql unavailable or no queryable files"
            self._store_runtime_cache(context, "codeql_runtime_artifacts.json", cache_key, payload)
            return payload

        live_inventory = self._run_codeql_inventory_query(
            codeql_path=codeql_path,
            database_path=database_path,
            target_files=target_files,
        )
        payload["live_inventory"] = live_inventory
        self._store_runtime_cache(context, "codeql_runtime_artifacts.json", cache_key, payload)
        return payload

    def project_root(self, context: AnalyzerContext) -> Path:
        validate_path = Path(context.validate_path or ".").expanduser().resolve()
        return validate_path if validate_path.is_dir() else validate_path.parent

    def project_info(self, project_root: Path) -> Dict[str, Any]:
        try:
            result = ProjectAnalyzerTool().execute(project_path=str(project_root), max_depth=5)
            if result.success and isinstance(result.metadata, dict):
                return result.metadata
        except Exception:
            pass
        return {
            "root_path": str(project_root),
            "source_count": 0,
            "header_count": 0,
            "languages": [],
            "build_system": None,
            "has_compile_commands": False,
            "compile_commands_path": None,
            "modules": [],
            "dependencies": {},
        }

    def compile_commands(self, project_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        compile_commands_path = str(project_info.get("compile_commands_path") or "")
        if not compile_commands_path:
            return []
        try:
            with open(compile_commands_path, "r", encoding="utf-8") as handle:
                payload = json.load(handle)
            if isinstance(payload, list):
                return [item for item in payload if isinstance(item, dict)]
        except Exception:
            pass
        return []

    def aggregate_project_flags(self, compile_commands: List[Dict[str, Any]]) -> Tuple[List[str], List[str]]:
        include_flags: List[str] = []
        define_flags: List[str] = []
        for entry in compile_commands:
            incs, defs = self.extract_compile_flags(str(entry.get("command", "") or ""))
            include_flags.extend(incs)
            define_flags.extend(defs)
        return self._dedupe(include_flags)[:12], self._dedupe(define_flags)[:12]

    def parse_patch(self, patch_path: str) -> List[Dict[str, Any]]:
        try:
            lines = Path(patch_path).read_text(encoding="utf-8", errors="ignore").splitlines()
        except Exception:
            return []

        files: List[Dict[str, Any]] = []
        current_file: Optional[Dict[str, Any]] = None
        current_hunk: Optional[Dict[str, Any]] = None

        for raw_line in lines:
            if raw_line.startswith("diff --git "):
                if current_hunk and current_file is not None:
                    current_file.setdefault("hunks", []).append(current_hunk)
                    current_hunk = None
                if current_file is not None:
                    files.append(current_file)
                parts = raw_line.split()
                old_path = parts[2][2:] if len(parts) > 2 and parts[2].startswith("a/") else ""
                new_path = parts[3][2:] if len(parts) > 3 and parts[3].startswith("b/") else ""
                current_file = {"old_path": old_path, "new_path": new_path, "hunks": []}
                continue

            if current_file is None:
                continue

            if raw_line.startswith("--- "):
                path = raw_line[4:].strip()
                current_file["old_path"] = path[2:] if path.startswith("a/") else path
                continue

            if raw_line.startswith("+++ "):
                path = raw_line[4:].strip()
                current_file["new_path"] = path[2:] if path.startswith("b/") else path
                continue

            hunk_match = self.HUNK_PATTERN.match(raw_line)
            if hunk_match:
                if current_hunk is not None:
                    current_file.setdefault("hunks", []).append(current_hunk)
                current_hunk = {
                    "old_start": int(hunk_match.group("old_start") or 0),
                    "old_count": int(hunk_match.group("old_count") or 1),
                    "new_start": int(hunk_match.group("new_start") or 0),
                    "new_count": int(hunk_match.group("new_count") or 1),
                    "removed_lines": [],
                    "added_lines": [],
                    "context_lines": [],
                }
                continue

            if current_hunk is None:
                continue

            if raw_line.startswith("-") and not raw_line.startswith("--- "):
                current_hunk["removed_lines"].append(raw_line[1:])
            elif raw_line.startswith("+") and not raw_line.startswith("+++ "):
                current_hunk["added_lines"].append(raw_line[1:])
            else:
                current_hunk["context_lines"].append(raw_line[1:] if raw_line.startswith(" ") else raw_line)

        if current_hunk and current_file is not None:
            current_file.setdefault("hunks", []).append(current_hunk)
        if current_file is not None:
            files.append(current_file)
        return files

    def resolve_project_file(self, project_root: Path, patch_file: str) -> Optional[Path]:
        patch_file = str(patch_file or "").strip()
        if not patch_file:
            return None

        candidates = [project_root / patch_file]
        parts = Path(patch_file).parts
        if project_root.name in parts:
            index = parts.index(project_root.name)
            suffix = parts[index + 1:]
            if suffix:
                candidates.append(project_root.joinpath(*suffix))

        if len(parts) > 1:
            candidates.append(project_root.joinpath(*parts[-min(len(parts), 4):]))

        for candidate in candidates:
            if candidate.exists():
                return candidate.resolve()

        matches = sorted(project_root.rglob(Path(patch_file).name))
        if matches:
            return matches[0].resolve()
        return None

    def find_compile_entry(self, resolved_file: Path, compile_commands: List[Dict[str, Any]]) -> Dict[str, Any]:
        normalized_target = resolved_file.resolve()
        basename_matches: List[Dict[str, Any]] = []

        for entry in compile_commands:
            directory = Path(str(entry.get("directory", ".") or ".")).expanduser().resolve()
            file_value = str(entry.get("file", "") or "")
            if not file_value:
                continue
            candidate = (directory / file_value).resolve() if not Path(file_value).is_absolute() else Path(file_value).resolve()
            if candidate == normalized_target:
                return entry
            if candidate.name == normalized_target.name:
                basename_matches.append(entry)

        return basename_matches[0] if basename_matches else {}

    def extract_compile_flags(self, compile_command: str) -> Tuple[List[str], List[str]]:
        if not compile_command:
            return [], []
        try:
            tokens = shlex.split(compile_command)
        except Exception:
            tokens = compile_command.split()
        include_flags: List[str] = []
        define_flags: List[str] = []
        skip_next = False
        for index, token in enumerate(tokens):
            if skip_next:
                skip_next = False
                continue
            if token in {"-I", "-D"} and index + 1 < len(tokens):
                value = tokens[index + 1]
                if token == "-I":
                    include_flags.append(f"-I{value}")
                else:
                    define_flags.append(f"-D{value}")
                skip_next = True
                continue
            if token.startswith("-I"):
                include_flags.append(token)
            elif token.startswith("-D"):
                define_flags.append(token)
        return include_flags[:8], define_flags[:8]

    def command_preview(self, command: List[str]) -> str:
        rendered = " ".join(command)
        return rendered if len(rendered) <= 180 else f"{rendered[:177]}..."

    def read_window(
        self,
        lines: List[str],
        anchor_line: int,
        radius: int = 8,
    ) -> Tuple[str, List[Tuple[int, str]]]:
        start = max(1, anchor_line - radius)
        end = min(len(lines), anchor_line + radius)
        window = [(line_no, lines[line_no - 1]) for line_no in range(start, end + 1)]
        excerpt = "\n".join(f"{line_no}: {text}" for line_no, text in window)
        return excerpt, window

    def find_function_context(
        self,
        lines: List[str],
        anchor_line: int,
    ) -> Tuple[str, List[str]]:
        search_start = min(max(anchor_line, 1), len(lines))
        for index in range(search_start - 1, -1, -1):
            function_name, parameters = self._function_from_line(lines[index])
            if function_name:
                return function_name, parameters
        for index in range(search_start, min(len(lines), search_start + 6)):
            function_name, parameters = self._function_from_line(lines[index])
            if function_name:
                return function_name, parameters
        return "", []

    def extract_parameters(self, signature: str) -> List[str]:
        params: List[str] = []
        for raw_param in (signature or "").split(","):
            token = raw_param.strip()
            if not token or token == "void":
                continue
            match = re.search(r"([A-Za-z_]\w*)\s*(?:\[\s*\])?$", token)
            if match:
                params.append(match.group(1))
        return params[:8]

    def extract_guard_exprs(self, window_lines: List[Tuple[int, str]]) -> List[str]:
        guards: List[str] = []
        for _line_no, text in window_lines:
            stripped = text.strip()
            match = re.search(r"\b(?:if|while|for)\s*\((.+)\)", stripped)
            if match:
                guards.append(match.group(1).strip())
        return self._dedupe(guards)[:6]

    def extract_call_targets(self, window_lines: List[Tuple[int, str]]) -> List[str]:
        call_targets: List[str] = []
        for _line_no, text in window_lines:
            stripped = text.strip()
            if not stripped or stripped.startswith("//") or stripped.startswith("*"):
                continue
            if self.FUNCTION_PATTERN.match(stripped):
                continue
            for name in re.findall(r"\b([A-Za-z_]\w*)\s*\(", text):
                if name not in CONTROL_KEYWORDS:
                    call_targets.append(name)
        return self._dedupe(call_targets)[:10]

    def extract_globals(self, window_lines: List[Tuple[int, str]]) -> List[str]:
        globals_seen: List[str] = []
        for _line_no, text in window_lines:
            globals_seen.extend(re.findall(r"\b(g_[A-Za-z_]\w*)\b", text))
        return self._dedupe(globals_seen)[:8]

    def extract_state_ops(
        self,
        window_lines: List[Tuple[int, str]],
        globals_seen: List[str],
    ) -> List[str]:
        operations: List[str] = []
        tracked = set(globals_seen)
        for _line_no, text in window_lines:
            stripped = text.strip()
            if any(symbol in stripped for symbol in ("++", "--")):
                operations.append(stripped)
                continue
            if "=" in stripped and not stripped.startswith("#"):
                for token in tracked:
                    if token in stripped:
                        operations.append(stripped)
                        break
            if "ref_count" in stripped or "authorized" in stripped:
                operations.append(stripped)
        return self._dedupe(operations)[:6]

    def relative_to(self, project_root: Path, file_path: Path) -> str:
        try:
            return str(file_path.resolve().relative_to(project_root.resolve()))
        except Exception:
            return str(file_path)

    def resolve_executable(self, candidates: List[str]) -> str:
        for candidate in candidates:
            if not candidate:
                continue
            if os.path.isabs(candidate) and os.path.exists(candidate):
                return candidate
            resolved = shutil.which(candidate)
            if resolved:
                return resolved
        return ""

    def _runtime_cache_path(self, context: AnalyzerContext, filename: str) -> Path:
        preferred = Path(context.output_dir or ".").resolve() / "patchweaver_runtime"
        fallback = Path(tempfile.gettempdir()) / "patchweaver_runtime" / re.sub(
            r"[^0-9A-Za-z_]+",
            "_",
            str(Path(context.patch_path).stem or "default"),
        ).strip("_")
        for cache_dir in (preferred, fallback):
            try:
                cache_dir.mkdir(parents=True, exist_ok=True)
                if not os.access(cache_dir, os.W_OK):
                    continue
                return cache_dir / filename
            except Exception:
                continue
        return fallback / filename

    def _load_runtime_cache(
        self,
        context: AnalyzerContext,
        filename: str,
        cache_key: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        path = self._runtime_cache_path(context, filename)
        if not path.exists():
            return None
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            if payload.get("cache_key") == cache_key:
                data = payload.get("data")
                if isinstance(data, dict):
                    return data
        except Exception:
            return None
        return None

    def _store_runtime_cache(
        self,
        context: AnalyzerContext,
        filename: str,
        cache_key: Dict[str, Any],
        data: Dict[str, Any],
    ) -> None:
        path = self._runtime_cache_path(context, filename)
        try:
            path.write_text(
                json.dumps({"cache_key": cache_key, "data": data}, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        except Exception:
            return

    def _select_runtime_targets(
        self,
        source_contexts: List[SourceArtifactContext],
        limit: int = 3,
    ) -> List[SourceArtifactContext]:
        ranked = sorted(
            source_contexts,
            key=lambda item: (
                0 if item.compile_command else 1,
                0 if item.function_name else 1,
                -(len(item.guard_exprs) + len(item.lock_calls) + len(item.state_ops)),
                -item.anchor_line,
            ),
        )
        chosen: List[SourceArtifactContext] = []
        seen = set()
        for item in ranked:
            key = (item.relative_file, item.function_name or "", item.anchor_line)
            if key in seen:
                continue
            seen.add(key)
            chosen.append(item)
            if len(chosen) >= limit:
                break
        return chosen

    def _build_csa_debug_command(
        self,
        clang_path: str,
        source_context: SourceArtifactContext,
        project_root: Path,
    ) -> List[str]:
        source_file = str(Path(source_context.resolved_file).resolve())
        if not Path(source_file).exists():
            return []

        preserved: List[str] = []
        if source_context.compile_command:
            try:
                tokens = shlex.split(source_context.compile_command)
            except Exception:
                tokens = source_context.compile_command.split()
            preserved = self._sanitize_compile_tokens(tokens[1:], source_file)

        include_flags = list(source_context.include_flags)
        define_flags = list(source_context.define_flags)
        include_dir = project_root / "include"
        if include_dir.exists():
            include_flag = f"-I{include_dir}"
            if include_flag not in include_flags:
                include_flags.append(include_flag)

        command = [
            clang_path,
            "--analyze",
            *preserved,
            *[flag for flag in include_flags if flag not in preserved],
            *[flag for flag in define_flags if flag not in preserved],
            "-Xanalyzer",
            "-analyzer-checker=debug.DumpCFG",
            "-Xanalyzer",
            "-analyzer-checker=debug.DumpCallGraph",
            source_file,
        ]
        return command

    def _sanitize_compile_tokens(self, tokens: List[str], source_file: str) -> List[str]:
        sanitized: List[str] = []
        skip_next = False
        for token in tokens:
            if skip_next:
                skip_next = False
                continue
            if token in {"-c", "-S"}:
                continue
            if token in {"-o", "-MF", "-MT", "-MQ"}:
                skip_next = True
                continue
            if token in {"-MMD", "-MD", "-MP"}:
                continue
            if token.startswith("-o"):
                continue
            if token.endswith((".o", ".obj", ".d")):
                continue
            if token == source_file or token.endswith(Path(source_file).name):
                continue
            sanitized.append(token)
        return sanitized

    def _parse_csa_debug_dump(
        self,
        dump: str,
        source_context: SourceArtifactContext,
    ) -> Dict[str, Any]:
        current_function = ""
        branch_map: Dict[str, List[str]] = {}
        branch_conditions_map: Dict[str, List[str]] = {}
        state_statements_map: Dict[str, List[str]] = {}
        field_access_map: Dict[str, List[str]] = {}
        return_map: Dict[str, List[str]] = {}
        call_edges: List[str] = []
        for raw_line in dump.splitlines():
            line = raw_line.strip()
            if not line:
                continue

            call_graph_match = re.match(r"Function:\s*(.+?)\s*calls:\s*(.*)", line)
            if call_graph_match:
                caller = call_graph_match.group(1).strip()
                if caller == "< root >":
                    continue
                callees = [token.strip() for token in call_graph_match.group(2).split() if token.strip()]
                for callee in callees[:24]:
                    call_edges.append(f"{caller} -> {callee}")
                continue

            if "(" in line and line.endswith(")") and not line.startswith("[") and not line.startswith("T:"):
                current_function = self._extract_function_name_from_signature(line)
                continue

            if line.startswith("T:") and current_function:
                branch_conditions_map.setdefault(current_function, []).append(line[2:].strip())

            branch_match = re.match(r"T:\s*(if|while|for|switch)\b", line)
            if branch_match and current_function:
                branch_map.setdefault(current_function, []).append(branch_match.group(1))

            statement_match = re.match(r"\d+:\s*(.+)", line)
            if statement_match and current_function:
                statement = statement_match.group(1).strip()
                if statement:
                    if (
                        "=" in statement
                        or statement.startswith("return")
                        or "->" in statement
                        or "sizeof" in statement
                        or "++" in statement
                        or "--" in statement
                        or any(api in statement for api in MEMORY_APIS)
                    ):
                        state_statements_map.setdefault(current_function, []).append(statement)
                    if statement.startswith("return"):
                        return_map.setdefault(current_function, []).append(statement)
                    field_access_map.setdefault(current_function, []).extend(
                        re.findall(r"[A-Za-z_]\w*->\w+", statement)
                    )

        relevant_function = source_context.function_name or current_function
        relevant_edges = [
            edge
            for edge in call_edges
            if relevant_function and edge.startswith(f"{relevant_function} ->")
        ] or call_edges[:12]
        branch_kinds = self._dedupe(branch_map.get(relevant_function, []) or [
            kind
            for values in branch_map.values()
            for kind in values
        ])[:6]
        call_targets = self._dedupe([
            edge.split("->", 1)[1].strip()
            for edge in relevant_edges
            if "->" in edge
        ])[:10]
        branch_conditions = self._dedupe(branch_conditions_map.get(relevant_function, []) or [
            condition
            for values in branch_conditions_map.values()
            for condition in values
        ])[:8]
        state_statements = self._dedupe(state_statements_map.get(relevant_function, []) or [
            statement
            for values in state_statements_map.values()
            for statement in values
        ])[:12]
        field_accesses = self._dedupe(field_access_map.get(relevant_function, []) or [
            field
            for values in field_access_map.values()
            for field in values
        ])[:10]
        return_statements = self._dedupe(return_map.get(relevant_function, []) or [
            statement
            for values in return_map.values()
            for statement in values
        ])[:6]

        return {
            "source_file": source_context.relative_file,
            "function_name": relevant_function,
            "anchor_line": source_context.anchor_line,
            "branch_kinds": branch_kinds,
            "branch_conditions": branch_conditions,
            "call_edges": self._dedupe(relevant_edges)[:12],
            "call_targets": call_targets,
            "state_statements": state_statements,
            "field_accesses": field_accesses,
            "return_statements": return_statements,
            "dump_excerpt": "\n".join(dump.splitlines()[:80])[:4000],
            "error": "",
        }

    def _extract_function_name_from_signature(self, signature: str) -> str:
        match = re.search(r"([A-Za-z_]\w*)\s*\([^()]*\)\s*$", signature.strip())
        return match.group(1) if match else ""

    def _resolve_codeql_database_metadata(self, database_path: str) -> Dict[str, Any]:
        codeql_path = self.resolve_executable(DEFAULT_CODEQL_CANDIDATES)
        if not codeql_path:
            return {}
        try:
            proc = subprocess.run(
                [codeql_path, "resolve", "database", "--format=json", "--", database_path],
                capture_output=True,
                text=True,
                timeout=20,
            )
            if proc.returncode != 0:
                return {}
            payload = json.loads(proc.stdout or "{}")
            return payload if isinstance(payload, dict) else {}
        except Exception:
            return {}

    def _ensure_codeql_database(
        self,
        database_path: str,
        target_path: str,
        codeql_path: str,
        build_script: str = "",
    ) -> Tuple[bool, str]:
        build_script_path = None
        try:
            if is_codeql_database_dir(database_path):
                return True, "数据库已存在"

            if not codeql_path:
                return False, "CodeQL CLI 不可用，无法补建数据库"

            if not target_path or not os.path.exists(target_path):
                return False, f"无法创建数据库，目标路径不存在: {target_path}"

            source_root = target_path if os.path.isdir(target_path) else os.path.dirname(target_path)
            os.makedirs(os.path.dirname(database_path) or ".", exist_ok=True)

            build_command = None
            configured_build_script = Path(build_script).expanduser().resolve() if build_script else None
            if configured_build_script and configured_build_script.exists():
                build_command = f"/bin/sh {shlex.quote(str(configured_build_script))}"
            else:
                makefile_candidates = [
                    os.path.join(source_root, "Makefile"),
                    os.path.join(source_root, "makefile"),
                    os.path.join(source_root, "GNUmakefile"),
                ]
                if any(os.path.exists(path) for path in makefile_candidates):
                    jobs = max(os.cpu_count() or 1, 1)
                    build_script_dir = os.path.dirname(database_path) or source_root
                    os.makedirs(build_script_dir, exist_ok=True)
                    build_script_file = tempfile.NamedTemporaryFile(
                        mode="w",
                        suffix=".sh",
                        prefix="codeql_build_",
                        dir=build_script_dir,
                        delete=False,
                    )
                    build_script_file.write(
                        "#!/bin/sh\n"
                        "set -e\n"
                        "make clean >/dev/null 2>&1 || true\n"
                        f"make -B -j{jobs} OBJDIR=.codeql-obj BINDIR=.codeql-bin || make -B -j{jobs}\n"
                    )
                    build_script_file.flush()
                    build_script_file.close()
                    os.chmod(build_script_file.name, 0o755)
                    build_script_path = build_script_file.name
                    build_command = f"/bin/sh {shlex.quote(build_script_path)}"

            cmd = [
                codeql_path,
                "database",
                "create",
                database_path,
                "--language=cpp",
                f"--source-root={source_root}",
                "--overwrite",
            ]
            if build_command:
                cmd.extend(["--command", build_command])

            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
                cwd=source_root,
            )
            if proc.returncode != 0:
                return False, f"CodeQL 数据库创建失败: {(proc.stderr or proc.stdout)[:500]}"
            return True, "CodeQL 数据库创建成功"
        except FileNotFoundError:
            return False, "CodeQL CLI 不可用，无法补建数据库"
        except Exception as exc:
            return False, f"CodeQL 数据库创建异常: {exc}"
        finally:
            if build_script_path and os.path.exists(build_script_path):
                try:
                    os.unlink(build_script_path)
                except OSError:
                    pass

    def _build_codeql_target_files(
        self,
        context: AnalyzerContext,
        source_contexts: List[SourceArtifactContext],
        project_root: Path,
        project_info: Dict[str, Any],
        baseline_files: List[str],
    ) -> List[str]:
        targets: List[str] = []
        baseline_set = {str(item).replace("\\", "/") for item in baseline_files}
        baseline_basenames = {Path(item).name for item in baseline_set}

        for item in source_contexts:
            relative = str(item.relative_file or "").replace("\\", "/")
            if not relative:
                continue
            if relative in baseline_set or Path(relative).name in baseline_basenames:
                targets.append(relative)

        if len(self._dedupe(targets)) >= 3:
            return self._dedupe(targets)[:3]

        compile_commands = self.compile_commands(project_info)
        compile_relatives: List[str] = []
        for entry in compile_commands:
            directory = Path(str(entry.get("directory", ".") or ".")).expanduser().resolve()
            file_value = str(entry.get("file", "") or "")
            if not file_value:
                continue
            candidate = (directory / file_value).resolve() if not Path(file_value).is_absolute() else Path(file_value).resolve()
            relative = self.relative_to(project_root, candidate).replace("\\", "/")
            if relative and relative in baseline_set:
                compile_relatives.append(relative)

        preferred_roots = self._preferred_codeql_roots(source_contexts)
        primary_root = preferred_roots[0] if preferred_roots else ""
        compile_relatives = sorted(
            self._dedupe(compile_relatives),
            key=lambda relative: (
                -self._path_similarity(primary_root, relative),
                len(relative),
            ),
        )
        top_level_roots = self._dedupe([
            root.split("/", 1)[0] + "/"
            for root in preferred_roots
            if "/" in root
        ])
        for prefixes in (preferred_roots, top_level_roots, []):
            for relative in compile_relatives:
                if prefixes and not any(relative.startswith(root) for root in prefixes):
                    continue
                targets.append(relative)
                if len(self._dedupe(targets)) >= 3:
                    return self._dedupe(targets)[:3]

        return self._dedupe(targets)[:3]

    def _preferred_codeql_roots(self, source_contexts: List[SourceArtifactContext]) -> List[str]:
        roots: List[str] = []
        for item in source_contexts:
            relative = str(item.relative_file or "").replace("\\", "/")
            if not relative:
                continue
            parent = str(Path(relative).parent).replace("\\", "/")
            if parent and parent != ".":
                roots.append(parent.rstrip("/") + "/")
        return self._dedupe(roots)[:3]

    def _path_similarity(self, left: str, right: str) -> int:
        left_parts = [part for part in left.split("/") if part]
        right_parts = [part for part in right.split("/") if part]
        score = 0
        for a, b in zip(left_parts, right_parts):
            if a != b:
                break
            score += 1
        return score

    def _run_codeql_inventory_query(
        self,
        codeql_path: str,
        database_path: str,
        target_files: List[str],
    ) -> Dict[str, Any]:
        file_clauses: List[str] = []
        for relative in target_files:
            normalized = relative.replace("\\", "/")
            basename = Path(normalized).name
            file_clauses.append(f'file.getRelativePath() = "{normalized}"')
            if basename != normalized:
                file_clauses.append(f'file.getBaseName() = "{basename}"')

        if not file_clauses:
            return {
                "status": "skipped",
                "functions": [],
                "call_edges": [],
                "target_files": [],
                "used_temp_copy": False,
                "error": "no target files",
            }

        query_text = (
            "import cpp\n\n"
            "predicate inTargetFile(File file) {\n  "
            + "\n  or ".join(file_clauses)
            + "\n}\n\n"
            "from Locatable e, string label\n"
            "where\n"
            "  exists(Function f |\n"
            "    e = f and inTargetFile(f.getFile()) and label = \"FUNCTION=\" + f.getName()\n"
            "  )\n"
            "  or\n"
            "  exists(Function caller, FunctionCall call, Function callee |\n"
            "    e = call and inTargetFile(caller.getFile()) and call.getEnclosingFunction() = caller and call.getTarget() = callee\n"
            "    and label = \"CALL=\" + caller.getName() + \"->\" + callee.getName()\n"
            "  )\n"
            "select e, label\n"
        )

        db_size = self._safe_directory_size(Path(database_path))
        use_temp_copy = not os.access(database_path, os.W_OK)
        if use_temp_copy and db_size > CODEQL_CLONE_LIMIT_BYTES:
            return {
                "status": "skipped",
                "functions": [],
                "call_edges": [],
                "target_files": list(target_files),
                "used_temp_copy": False,
                "error": f"database copy required but too large ({db_size} bytes)",
            }

        try:
            with tempfile.TemporaryDirectory(prefix="patchweaver_codeql_") as temp_dir:
                temp_root = Path(temp_dir)
                query_dir = temp_root / "query"
                query_dir.mkdir(parents=True, exist_ok=True)
                query_path = query_dir / "inventory.ql"
                query_path.write_text(query_text, encoding="utf-8")
                pack_dir, pack_error = ensure_codeql_pack(str(query_path), codeql_path, timeout=120)
                if pack_error:
                    return {
                        "status": "error",
                        "functions": [],
                        "call_edges": [],
                        "target_files": list(target_files),
                        "used_temp_copy": False,
                        "error": pack_error,
                    }

                runtime_database = database_path
                if use_temp_copy:
                    runtime_database = str(self._copy_codeql_database_minimal(Path(database_path), temp_root / "database"))

                output_path = query_dir / "inventory.bqrs"
                proc = subprocess.run(
                    [
                        codeql_path,
                        "query",
                        "run",
                        *build_codeql_search_path_args(codeql_path),
                        "--database",
                        runtime_database,
                        "--output",
                        str(output_path),
                        str(query_path),
                    ],
                    capture_output=True,
                    text=True,
                    timeout=180,
                    cwd=str(pack_dir),
                )
                if proc.returncode != 0:
                    return {
                        "status": "error",
                        "functions": [],
                        "call_edges": [],
                        "target_files": list(target_files),
                        "used_temp_copy": use_temp_copy,
                        "error": (proc.stderr or proc.stdout or "codeql inventory query failed")[:1000],
                    }

                decode = subprocess.run(
                    [codeql_path, "bqrs", "decode", str(output_path), "--format=json", "--entities=all"],
                    capture_output=True,
                    text=True,
                    timeout=60,
                )
                if decode.returncode != 0:
                    return {
                        "status": "error",
                        "functions": [],
                        "call_edges": [],
                        "target_files": list(target_files),
                        "used_temp_copy": use_temp_copy,
                        "error": (decode.stderr or decode.stdout or "codeql decode failed")[:1000],
                    }

                parsed = self._parse_codeql_inventory_payload(decode.stdout or "")
                parsed["status"] = "success"
                parsed["target_files"] = list(target_files)
                parsed["used_temp_copy"] = use_temp_copy
                parsed["error"] = ""
                return parsed
        except Exception as exc:
            return {
                "status": "error",
                "functions": [],
                "call_edges": [],
                "target_files": list(target_files),
                "used_temp_copy": use_temp_copy,
                "error": str(exc),
            }

    def _copy_codeql_database_minimal(self, source: Path, destination: Path) -> Path:
        destination.mkdir(parents=True, exist_ok=True)
        for name in ("codeql-database.yml", "baseline-info.json", "src.zip"):
            src_file = source / name
            if src_file.exists():
                shutil.copy2(src_file, destination / name)
        for child in source.iterdir():
            if child.is_dir() and (child.name.startswith("db-") or child.name == "working"):
                shutil.copytree(child, destination / child.name)
        return destination

    def _parse_codeql_inventory_payload(self, payload_text: str) -> Dict[str, Any]:
        try:
            payload = json.loads(payload_text or "{}")
        except json.JSONDecodeError:
            return {"functions": [], "call_edges": []}

        tuples = ((payload.get("#select") or {}).get("tuples") or []) if isinstance(payload, dict) else []
        functions: List[Dict[str, Any]] = []
        call_edges: List[str] = []
        seen_functions = set()
        for row in tuples:
            if not isinstance(row, list) or len(row) < 2:
                continue
            entity = row[0] if isinstance(row[0], dict) else {}
            label = str(row[1] or "")
            url_info = entity.get("url") if isinstance(entity.get("url"), dict) else {}
            file_path = self._uri_to_path(url_info.get("uri"))
            line = int(url_info.get("startLine") or 0)
            if label.startswith("FUNCTION="):
                function_name = label.split("=", 1)[1].strip()
                key = (function_name, file_path, line)
                if key in seen_functions:
                    continue
                seen_functions.add(key)
                functions.append({
                    "function": function_name,
                    "file_path": file_path,
                    "line": line,
                })
            elif label.startswith("CALL="):
                call_edges.append(label.split("=", 1)[1].strip())

        return {
            "functions": functions[:20],
            "call_edges": self._dedupe(call_edges)[:30],
        }

    def _find_existing_codeql_findings(self, context: AnalyzerContext) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        result_path = Path(context.output_dir or ".").resolve() / "codeql" / "result.json"
        if not result_path.exists():
            return findings
        payload = self._load_json_file(result_path)
        diagnostics = (((payload.get("validation") or {}).get("diagnostics")) or []) if isinstance(payload, dict) else []
        for item in diagnostics[:20]:
            if not isinstance(item, dict):
                continue
            findings.append({
                "file_path": str(item.get("file_path", "") or ""),
                "line": int(item.get("line", 0) or 0),
                "message": str(item.get("message", "") or ""),
            })
        return findings

    def _load_json_file(self, path: Path) -> Dict[str, Any]:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            return payload if isinstance(payload, dict) else {}
        except Exception:
            return {}

    def _safe_directory_size(self, root: Path) -> int:
        total = 0
        try:
            for current_root, dirs, files in os.walk(root):
                dirs[:] = [item for item in dirs if item not in {"log", "diagnostic", "working"}]
                for name in files:
                    path = Path(current_root) / name
                    try:
                        total += path.stat().st_size
                    except OSError:
                        continue
        except Exception:
            return total
        return total

    def _uri_to_path(self, uri: Optional[str]) -> str:
        if not uri:
            return ""
        parsed = urlparse(uri)
        if parsed.scheme != "file":
            return str(uri)
        return unquote(parsed.path or "")

    def _dedupe(self, items: List[str]) -> List[str]:
        seen = set()
        deduped: List[str] = []
        for item in items:
            token = str(item).strip()
            if token and token not in seen:
                seen.add(token)
                deduped.append(token)
        return deduped

    def _dedupe_ints(self, items: List[int]) -> List[int]:
        seen = set()
        deduped: List[int] = []
        for item in items:
            value = int(item or 0)
            if value > 0 and value not in seen:
                seen.add(value)
                deduped.append(value)
        return deduped

    def _function_from_line(self, line: str) -> Tuple[str, List[str]]:
        stripped = line.strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("*"):
            return "", []
        match = self.FUNCTION_PATTERN.match(stripped)
        if not match:
            return "", []
        function_name = match.group(1)
        if function_name in CONTROL_KEYWORDS:
            return "", []
        signature = match.group(2)
        return function_name, self.extract_parameters(signature)
