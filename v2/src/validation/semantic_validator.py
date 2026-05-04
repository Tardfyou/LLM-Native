"""
语义验证器
"""

import json
import os
import re
import shlex
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, unquote

from ..experiments.sample_env import load_validation_env
from .codeql_support import (
    build_codeql_search_path_args,
    build_codeql_database_path,
    ensure_codeql_pack,
    is_codeql_database_dir,
    resolve_codeql_database_path,
)
from .types import AnalyzerType, Diagnostic, ValidationResult, ValidationStage


class SemanticValidator:
    """实际运行检测器做语义验证。"""

    _ANSI_ESCAPE_RE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.clang_path = self.config.get("clang_path", "/usr/lib/llvm-18/bin/clang++")
        self.codeql_path = self.config.get("codeql_path", "/usr/local/bin/codeql")
        self.codeql_search_path = self.config.get("search_path", "")
        self.timeout = self.config.get("timeout", 120)
        self.codeql_auto_create_db = self.config.get("codeql_auto_create_db", True)
        self.csa_jobs = self._resolve_csa_jobs(self.config.get("csa_jobs", self.config.get("jobs")))

    def validate_csa_checker(
        self,
        checker_so_path: str,
        checker_name: str,
        target_path: str,
        include_dirs: List[str] = None,
    ) -> ValidationResult:
        start_time = time.time()
        checker_so_path = str(Path(checker_so_path).expanduser().resolve())
        target_path = str(Path(target_path).expanduser().resolve())

        if not os.path.exists(checker_so_path):
            return ValidationResult(
                stage=ValidationStage.SEMANTIC,
                analyzer=AnalyzerType.CSA,
                success=False,
                execution_time=time.time() - start_time,
                error_message=f"检测器文件不存在: {checker_so_path}",
            )
        if not os.path.exists(target_path):
            return ValidationResult(
                stage=ValidationStage.SEMANTIC,
                analyzer=AnalyzerType.CSA,
                success=False,
                execution_time=time.time() - start_time,
                error_message=f"目标路径不存在: {target_path}",
            )

        try:
            project_root = Path(__file__).resolve().parents[2]
            scan_script = project_root / "scripts" / "scan_project.sh"
            validation_env = load_validation_env(target_path)
            compile_commands_path = str(validation_env.get("compile_commands_path", "") or "").strip()
            resolved_include_dirs = self._resolve_csa_include_dirs(
                target_path,
                include_dirs,
                validation_env=validation_env,
            )

            if compile_commands_path and Path(compile_commands_path).exists():
                diagnostics, report_path, return_code = self._run_csa_with_compile_db(
                    checker_so_path=checker_so_path,
                    checker_name=checker_name,
                    target_path=target_path,
                    compile_commands_path=compile_commands_path,
                    include_dirs=resolved_include_dirs,
                )
                diagnostic_output = ""
            else:
                scan_script = project_root / "scripts" / "scan_project.sh"
                if not scan_script.exists():
                    return ValidationResult(
                        stage=ValidationStage.SEMANTIC,
                        analyzer=AnalyzerType.CSA,
                        success=False,
                        execution_time=time.time() - start_time,
                        error_message=f"扫描脚本不存在: {scan_script}",
                    )

                cmd = [str(scan_script), checker_so_path, checker_name, target_path]
                for inc_dir in resolved_include_dirs:
                    cmd.extend(["-I", inc_dir])
                cmd.extend(["--format", "text"])

                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout,
                    cwd=str(project_root),
                )
                output = (proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")
                diagnostic_output, report_path = self._resolve_csa_scan_output(output, project_root)
                diagnostics = self._parse_analyzer_output(diagnostic_output, target_path, "csa")
                return_code = proc.returncode
            hard_errors = [diag for diag in diagnostics if diag.severity == "error"]
            env_blocked, env_block_reason = self._detect_environment_block(
                diagnostics,
                diagnostic_output,
            )
            success = return_code == 0 and not hard_errors
            error_message = ""
            if not success:
                if hard_errors:
                    first = hard_errors[0]
                    error_message = f"{first.file_path}:{first.line}: {first.message}"[:500]
                else:
                    error_message = self._strip_ansi(diagnostic_output or "CSA 扫描失败")[:500]
            return ValidationResult(
                stage=ValidationStage.SEMANTIC,
                analyzer=AnalyzerType.CSA,
                success=success,
                diagnostics=diagnostics,
                execution_time=time.time() - start_time,
                error_message=error_message,
                metadata={
                    "bugs_found": len(diagnostics),
                    "checker_name": checker_name,
                    "scan_script": str(scan_script),
                    "target_path": target_path,
                    "include_dirs": resolved_include_dirs,
                    "compile_commands_path": compile_commands_path,
                    "return_code": return_code,
                    "hard_errors": len(hard_errors),
                    "report_path": report_path,
                    "diagnostic_output_source": "compile_commands" if compile_commands_path else ("saved_report" if report_path else "process_output"),
                    "environment_blocked": env_blocked,
                    "environment_block_reason": env_block_reason,
                    "validation_target": target_path,
                },
            )
        except subprocess.TimeoutExpired:
            return ValidationResult(
                stage=ValidationStage.SEMANTIC,
                analyzer=AnalyzerType.CSA,
                success=False,
                execution_time=time.time() - start_time,
                error_message=f"分析超时 ({self.timeout}秒)",
            )
        except Exception as exc:
            return ValidationResult(
                stage=ValidationStage.SEMANTIC,
                analyzer=AnalyzerType.CSA,
                success=False,
                execution_time=time.time() - start_time,
                error_message=str(exc),
            )

    def validate_codeql_query(
        self,
        query_path: str,
        database_path: str,
        target_path: str = None,
        output_path: str = None,
    ) -> ValidationResult:
        start_time = time.time()
        query_path = str(Path(query_path).expanduser().resolve())

        if not os.path.exists(query_path):
            return ValidationResult(
                stage=ValidationStage.SEMANTIC,
                analyzer=AnalyzerType.CODEQL,
                success=False,
                execution_time=time.time() - start_time,
                error_message=f"查询文件不存在: {query_path}",
            )

        resolved_database_path, resolution_message = resolve_codeql_database_path(database_path, target_path)
        database_path = resolved_database_path

        if not os.path.exists(database_path) or not is_codeql_database_dir(database_path):
            if self.codeql_auto_create_db and target_path:
                database_path = build_codeql_database_path(database_path, target_path)
                ok, msg = self._ensure_codeql_database(database_path, target_path)
                if not ok:
                    return ValidationResult(
                        stage=ValidationStage.SEMANTIC,
                        analyzer=AnalyzerType.CODEQL,
                        success=False,
                        execution_time=time.time() - start_time,
                        error_message=msg,
                    )
            else:
                return ValidationResult(
                    stage=ValidationStage.SEMANTIC,
                    analyzer=AnalyzerType.CODEQL,
                    success=False,
                    execution_time=time.time() - start_time,
                    error_message=resolution_message or f"数据库不存在或无效: {database_path}",
                )

        try:
            pack_dir, pack_error = ensure_codeql_pack(
                query_path,
                self.codeql_path,
                self.timeout,
                self.codeql_search_path,
            )
            if pack_error:
                return ValidationResult(
                    stage=ValidationStage.SEMANTIC,
                    analyzer=AnalyzerType.CODEQL,
                    success=False,
                    execution_time=time.time() - start_time,
                    error_message=pack_error,
                )

            output_path = output_path or os.path.join(os.path.dirname(query_path), "results.bqrs")
            cmd = [
                self.codeql_path,
                "query",
                "run",
                *build_codeql_search_path_args(self.codeql_path, self.codeql_search_path),
                "--threads=0",
                "--database",
                database_path,
                "--output",
                output_path,
                query_path,
            ]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=max(self.timeout, 300),
                cwd=str(pack_dir),
            )

            decoded_artifacts: Dict[str, Any] = {}
            diagnostics: List[Diagnostic] = []
            if result.returncode == 0:
                decoded_artifacts = self._decode_codeql_bqrs(output_path)
                diagnostics = self._parse_codeql_results(output_path, decoded_artifacts)

            return ValidationResult(
                stage=ValidationStage.SEMANTIC,
                analyzer=AnalyzerType.CODEQL,
                success=result.returncode == 0,
                diagnostics=diagnostics,
                execution_time=time.time() - start_time,
                error_message="" if result.returncode == 0 else (result.stderr or result.stdout)[:500],
                metadata={
                    "output_file": output_path,
                    "bugs_found": len(diagnostics),
                    "database_path": database_path,
                    "database_resolution": resolution_message,
                    "query_path": query_path,
                    "decoded_results": decoded_artifacts,
                    "environment_blocked": False,
                    "environment_block_reason": "",
                    "validation_target": target_path or database_path,
                },
            )
        except subprocess.TimeoutExpired:
            return ValidationResult(
                stage=ValidationStage.SEMANTIC,
                analyzer=AnalyzerType.CODEQL,
                success=False,
                execution_time=time.time() - start_time,
                error_message=f"分析超时 ({self.timeout}秒)",
            )
        except FileNotFoundError:
            return ValidationResult(
                stage=ValidationStage.SEMANTIC,
                analyzer=AnalyzerType.CODEQL,
                success=False,
                execution_time=time.time() - start_time,
                error_message="CodeQL 未安装或不可用",
            )
        except Exception as exc:
            return ValidationResult(
                stage=ValidationStage.SEMANTIC,
                analyzer=AnalyzerType.CODEQL,
                success=False,
                execution_time=time.time() - start_time,
                error_message=str(exc),
            )

    def _parse_analyzer_output(self, output: str, target_path: str, source: str) -> List[Diagnostic]:
        output = self._strip_ansi(output)
        diagnostics: List[Diagnostic] = []
        pattern = re.compile(
            r"^(?P<file>.*?):(?P<line>\d+):(?P<column>\d+): (?P<severity>warning|error|fatal error): (?P<message>.+)$"
        )
        for line in output.split("\n"):
            if "warning:" not in line.lower() and "error:" not in line.lower():
                continue
            match = pattern.match(line.strip())
            if not match:
                continue
            severity = "error" if match.group("severity") == "fatal error" else match.group("severity")
            diagnostics.append(Diagnostic(
                file_path=match.group("file") or target_path,
                line=int(match.group("line")),
                column=int(match.group("column")),
                severity=severity,
                message=match.group("message"),
                source=source,
            ))
        return diagnostics

    def _resolve_csa_scan_output(self, output: str, project_root: Path) -> Tuple[str, str]:
        cleaned_output = self._strip_ansi(output)
        report_path = self._extract_csa_report_path(cleaned_output, project_root)
        if report_path:
            try:
                report_text = Path(report_path).read_text(encoding="utf-8", errors="ignore")
            except OSError:
                report_text = ""
            if report_text.strip():
                return report_text, report_path
        return cleaned_output, report_path

    def _extract_csa_report_path(self, output: str, project_root: Path) -> str:
        match = re.search(r"完整报告已保存:\s*(?P<path>[^\r\n]+)", output)
        if not match:
            return ""

        report_token = match.group("path").strip()
        if not report_token:
            return ""

        candidate = Path(report_token).expanduser()
        if not candidate.is_absolute():
            candidate = (project_root / candidate).resolve()
        else:
            candidate = candidate.resolve()
        return str(candidate)

    def _strip_ansi(self, text: str) -> str:
        return self._ANSI_ESCAPE_RE.sub("", text or "")

    def _resolve_csa_include_dirs(
        self,
        target_path: str,
        include_dirs: Optional[List[str]],
        validation_env: Optional[Dict[str, Any]] = None,
    ) -> List[str]:
        resolved: List[str] = []
        seen = set()

        def add(path: Path):
            try:
                candidate = path.expanduser().resolve()
            except FileNotFoundError:
                candidate = path.expanduser()
            key = str(candidate)
            if candidate.exists() and candidate.is_dir() and key not in seen:
                seen.add(key)
                resolved.append(key)

        for item in include_dirs or []:
            token = str(item or "").strip()
            if token:
                add(Path(token))

        env_include_dirs = (validation_env or {}).get("include_dirs", [])
        for item in env_include_dirs or []:
            token = str(item or "").strip()
            if token:
                add(Path(token))

        if resolved:
            return resolved

        target = Path(target_path).expanduser().resolve()
        roots = [target if target.is_dir() else target.parent]
        if roots:
            parent = roots[0].parent
            if parent.exists():
                roots.append(parent)

        candidate_relatives = (
            "include",
            "includes",
            "inc",
            "headers",
            "src/include",
        )
        for root in roots:
            add(root)
            for relative in candidate_relatives:
                add(root / relative)

        return resolved

    def _run_csa_with_compile_db(
        self,
        checker_so_path: str,
        checker_name: str,
        target_path: str,
        compile_commands_path: str,
        include_dirs: List[str],
    ) -> Tuple[List[Diagnostic], str, int]:
        target = Path(target_path).expanduser().resolve()
        compile_db = self._load_compile_commands(compile_commands_path)
        jobs: List[Tuple[int, Dict[str, Any], Path, List[str]]] = []
        for index, entry in enumerate(compile_db):
            source_path = self._resolve_compile_db_source(entry)
            if source_path is None or not source_path.exists():
                continue
            if target.is_file() and source_path.resolve() != target:
                continue
            if target.is_dir():
                try:
                    source_path.resolve().relative_to(target)
                except ValueError:
                    continue
            command = self._build_csa_command_from_compile_entry(
                checker_so_path=checker_so_path,
                checker_name=checker_name,
                entry=entry,
                source_path=source_path,
                include_dirs=include_dirs,
            )
            jobs.append((index, entry, source_path, command))

        diagnostics: List[Diagnostic] = []
        failures = 0
        if jobs:
            max_workers = max(1, min(self.csa_jobs, len(jobs)))
            ordered_results: List[Tuple[int, List[Diagnostic], int]] = []
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {
                    executor.submit(self._run_csa_compile_entry, entry, source_path, command): (index, source_path)
                    for index, entry, source_path, command in jobs
                }
                for future in as_completed(futures):
                    index, source_path = futures[future]
                    try:
                        entry_diags, return_code = future.result()
                    except subprocess.TimeoutExpired as exc:
                        entry_diags = [
                            Diagnostic(
                                file_path=str(source_path),
                                line=1,
                                column=1,
                                severity="error",
                                message=f"CSA 单文件分析超时 ({self.timeout}秒): {exc}",
                                source="csa",
                            )
                        ]
                        return_code = 124
                    except Exception as exc:
                        entry_diags = [
                            Diagnostic(
                                file_path=str(source_path),
                                line=1,
                                column=1,
                                severity="error",
                                message=f"CSA 单文件分析失败: {exc}",
                                source="csa",
                            )
                        ]
                        return_code = 1
                    ordered_results.append((index, entry_diags, return_code))

            for _, entry_diags, return_code in sorted(ordered_results, key=lambda item: item[0]):
                diagnostics.extend(entry_diags)
                if return_code != 0:
                    failures += 1
        report_path = ""
        return diagnostics, report_path, 0 if failures == 0 else 1

    def _run_csa_compile_entry(
        self,
        entry: Dict[str, Any],
        source_path: Path,
        command: List[str],
    ) -> Tuple[List[Diagnostic], int]:
        proc = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=self.timeout,
            cwd=str(Path(str(entry.get("directory", source_path.parent)) or source_path.parent).expanduser().resolve()),
        )
        output = (proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")
        return self._parse_analyzer_output(output, str(source_path), "csa"), proc.returncode

    def _resolve_csa_jobs(self, configured: Any) -> int:
        env_value = os.environ.get("PATCHWEAVER_CSA_JOBS") or os.environ.get("CSA_JOBS")
        raw_value = env_value if env_value not in (None, "") else configured
        try:
            jobs = int(raw_value)
        except (TypeError, ValueError):
            jobs = min(8, max(1, os.cpu_count() or 1))
        return max(1, jobs)

    def _load_compile_commands(self, compile_commands_path: str) -> List[Dict[str, Any]]:
        try:
            payload = json.loads(Path(compile_commands_path).read_text(encoding="utf-8"))
        except Exception:
            return []
        if isinstance(payload, list):
            return [item for item in payload if isinstance(item, dict)]
        return []

    def _resolve_compile_db_source(self, entry: Dict[str, Any]) -> Optional[Path]:
        directory = Path(str(entry.get("directory", ".") or ".")).expanduser().resolve()
        file_value = str(entry.get("file", "") or "").strip()
        if not file_value:
            return None
        file_path = Path(file_value)
        return file_path.resolve() if file_path.is_absolute() else (directory / file_path).resolve()

    def _build_csa_command_from_compile_entry(
        self,
        checker_so_path: str,
        checker_name: str,
        entry: Dict[str, Any],
        source_path: Path,
        include_dirs: List[str],
    ) -> List[str]:
        raw_command = str(entry.get("command", "") or "")
        tokens = self._safe_split(raw_command)
        compiler = self.clang_path
        if source_path.suffix.lower() == ".c":
            compiler = re.sub(r"clang\+\+$", "clang", self.clang_path)
        args = self._extract_validation_args(tokens, Path(str(entry.get("directory", source_path.parent)) or source_path.parent))
        for include_dir in include_dirs:
            args.append(f"-I{include_dir}")
        return [
            compiler,
            "--analyze",
            "-Xclang",
            "-load",
            "-Xclang",
            checker_so_path,
            "-Xclang",
            "-analyzer-checker",
            "-Xclang",
            checker_name,
            "-Xclang",
            "-analyzer-output=text",
            *self._dedupe_args(args),
            str(source_path),
        ]

    def _extract_validation_args(self, tokens: List[str], directory: Path) -> List[str]:
        args: List[str] = []
        skip_next = False
        for index, token in enumerate(tokens):
            if skip_next:
                skip_next = False
                continue
            if token in {"-c", "-o", "-MF", "-MT", "-MQ"}:
                skip_next = index + 1 < len(tokens)
                continue
            if token in {"-I", "-D", "-U", "-include", "-isystem", "-iquote", "-imacros", "-std", "-x"}:
                if index + 1 < len(tokens):
                    value = tokens[index + 1]
                    args.extend([token, self._resolve_command_flag_value(token, value, directory)])
                    skip_next = True
                continue
            if token.startswith("-I") and len(token) > 2:
                args.append("-I" + self._resolve_command_flag_value("-I", token[2:], directory))
            elif token.startswith("-D") or token.startswith("-U"):
                args.append(token)
            elif token.startswith("-std="):
                args.append(token)
            elif token.startswith("-include") and len(token) > len("-include"):
                args.extend(["-include", self._resolve_command_flag_value("-include", token[len("-include") :], directory)])
            elif token.startswith("-isystem") and len(token) > len("-isystem"):
                args.extend(["-isystem", self._resolve_command_flag_value("-isystem", token[len("-isystem") :], directory)])
            elif token.startswith("-iquote") and len(token) > len("-iquote"):
                args.extend(["-iquote", self._resolve_command_flag_value("-iquote", token[len("-iquote") :], directory)])
            elif token in {"-pthread", "-fPIC", "-fpic", "-fms-extensions", "-funsigned-char", "-fshort-wchar"} or token.startswith("-m") or token.startswith("-W"):
                args.append(token)
        return args

    def _resolve_command_flag_value(self, flag: str, value: str, directory: Path) -> str:
        if flag in {"-I", "-include", "-isystem", "-iquote", "-imacros"}:
            path = Path(value)
            return str(path if path.is_absolute() else (directory / path).resolve())
        return value

    def _dedupe_args(self, args: List[str]) -> List[str]:
        deduped: List[str] = []
        seen = set()
        index = 0
        while index < len(args):
            token = args[index]
            if token in {"-I", "-include", "-isystem", "-iquote", "-imacros", "-D", "-U", "-std", "-x"} and index + 1 < len(args):
                pair = (token, args[index + 1])
                if pair not in seen:
                    seen.add(pair)
                    deduped.extend([token, args[index + 1]])
                index += 2
                continue
            if token not in seen:
                seen.add(token)
                deduped.append(token)
            index += 1
        return deduped

    def _safe_split(self, raw_command: str) -> List[str]:
        try:
            return shlex.split(raw_command)
        except Exception:
            return raw_command.split()

    def _parse_codeql_results(self, output_path: str, decoded_artifacts: Optional[Dict[str, Any]] = None) -> List[Diagnostic]:
        decoded_json = ((decoded_artifacts or {}).get("json") or {}).get("content")
        if not decoded_json:
            return []

        try:
            payload = json.loads(decoded_json)
        except json.JSONDecodeError:
            return []

        diagnostics: List[Diagnostic] = []
        for result_set_name, result_set in payload.items():
            tuples = result_set.get("tuples") or []
            for row in tuples:
                entity_label = ""
                message = ""
                file_path = output_path
                line = 1
                column = 1

                if row:
                    first = row[0]
                    if isinstance(first, dict):
                        entity_label = first.get("label") or first.get("url", "")
                        url_info = first.get("url") if isinstance(first.get("url"), dict) else None
                        if url_info:
                            file_path = self._codeql_uri_to_path(url_info.get("uri")) or output_path
                            line = int(url_info.get("startLine") or 1)
                            column = int(url_info.get("startColumn") or 1)
                    elif first is not None:
                        entity_label = str(first)

                if len(row) > 1:
                    message = str(row[1])
                else:
                    message = entity_label or result_set_name

                diagnostics.append(Diagnostic(
                    file_path=file_path,
                    line=line,
                    column=column,
                    severity="warning",
                    message=message,
                    source="codeql",
                    code=result_set_name,
                ))
        return diagnostics

    def _detect_environment_block(self, diagnostics: List[Diagnostic], raw_output: str) -> Tuple[bool, str]:
        messages = [str(diag.message or "").strip() for diag in diagnostics if getattr(diag, "severity", "") == "error"]
        text = "\n".join(messages + [self._strip_ansi(raw_output)])
        lowered = text.lower()
        if "file not found" in lowered:
            return True, "missing_header"
        if "no such file or directory" in lowered:
            return True, "missing_file"
        if "fatal error" in lowered and "include" in lowered:
            return True, "include_resolution_failed"
        return False, ""

    def _codeql_uri_to_path(self, uri: Optional[str]) -> str:
        if not uri:
            return ""
        parsed = urlparse(uri)
        if parsed.scheme != "file":
            return uri
        path = unquote(parsed.path or "")
        if os.name == "nt" and path.startswith("/") and len(path) > 2 and path[2] == ":":
            path = path[1:]
        return path

    def _decode_codeql_bqrs(self, output_path: str) -> Dict[str, Any]:
        formats = {"text": "text", "json": "json"}
        artifacts: Dict[str, Any] = {}
        if not self.codeql_path or not os.path.exists(self.codeql_path):
            return artifacts

        base_path = os.path.splitext(output_path)[0]
        for key, fmt in formats.items():
            target_path = f"{base_path}.{fmt}"
            try:
                proc = subprocess.run(
                    [self.codeql_path, "bqrs", "decode", output_path, f"--format={fmt}", "--entities=all"],
                    capture_output=True,
                    text=True,
                    timeout=min(self.timeout, 60),
                )
                if proc.returncode != 0:
                    artifacts[key] = {"path": target_path, "error": (proc.stderr or proc.stdout)[:500]}
                    continue

                content = proc.stdout or ""
                if key == "text":
                    Path(target_path).write_text(content, encoding="utf-8")

                artifacts[key] = {
                    "path": target_path if key == "text" else "",
                    "preview": content[:1000],
                    "content": content if key == "json" else None,
                }
            except Exception as exc:
                artifacts[key] = {"path": target_path, "error": str(exc)}
        return artifacts

    def _ensure_codeql_database(self, database_path: str, target_path: str) -> Tuple[bool, str]:
        build_script_path = None
        try:
            if is_codeql_database_dir(database_path):
                return True, "数据库已存在"

            resolved_target = str(Path(target_path).expanduser().resolve()) if target_path else ""
            if not resolved_target or not os.path.exists(resolved_target):
                return False, f"无法创建数据库，目标路径不存在: {target_path}"

            source_root = resolved_target if os.path.isdir(resolved_target) else os.path.dirname(resolved_target)
            os.makedirs(os.path.dirname(database_path) or ".", exist_ok=True)

            validation_env = load_validation_env(resolved_target)
            build_command = str(validation_env.get("codeql_build_script", "") or "").strip() or None
            makefile_candidates = [
                os.path.join(source_root, "Makefile"),
                os.path.join(source_root, "makefile"),
                os.path.join(source_root, "GNUmakefile"),
            ]
            if not build_command and any(os.path.exists(path) for path in makefile_candidates):
                jobs = max(os.cpu_count() or 1, 1)
                build_script_dir = os.path.dirname(database_path) or source_root
                os.makedirs(build_script_dir, exist_ok=True)
                build_script = tempfile.NamedTemporaryFile(
                    mode="w",
                    suffix=".sh",
                    prefix="codeql_build_",
                    dir=build_script_dir,
                    delete=False,
                )
                build_script.write(
                    "#!/bin/sh\n"
                    "set -e\n"
                    "make clean >/dev/null 2>&1 || true\n"
                    f"make -B -j{jobs} OBJDIR=.codeql-obj BINDIR=.codeql-bin || make -B -j{jobs}\n"
                )
                build_script.flush()
                build_script.close()
                os.chmod(build_script.name, 0o755)
                build_script_path = build_script.name
                build_command = build_script_path

            cmd = [
                self.codeql_path,
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
                timeout=max(self.timeout, 300),
                cwd=str(Path(str(validation_env.get("version_root", source_root)) or source_root).expanduser().resolve()),
            )
            if proc.returncode != 0:
                return False, f"CodeQL 数据库创建失败: {(proc.stderr or proc.stdout)[:500]}"
            return True, "数据库创建成功"
        except FileNotFoundError:
            return False, "CodeQL 未安装或不可用"
        except Exception as exc:
            return False, f"CodeQL 数据库创建异常: {exc}"
        finally:
            if build_script_path and os.path.exists(build_script_path):
                try:
                    os.unlink(build_script_path)
                except OSError:
                    pass
