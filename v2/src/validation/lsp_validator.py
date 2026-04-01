"""
LSP 语法验证器
"""

import os
import subprocess
import tempfile
import time
from typing import Any, Dict, List

from .codeql_support import build_codeql_search_path_args, ensure_codeql_pack
from .types import AnalyzerType, Diagnostic, ValidationResult, ValidationStage


class LSPValidator:
    """LSP 语法验证器。"""

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.clangd_path = self.config.get("clangd_path", "/usr/bin/clangd")
        self.timeout = self.config.get("timeout", 30)

    def validate_csa_code(self, code: str, file_path: str = None) -> ValidationResult:
        start_time = time.time()

        if not file_path:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".cpp", delete=False) as file_handle:
                file_handle.write(code)
                file_path = file_handle.name

        try:
            clang_path = self.config.get("clang_path", "/usr/lib/llvm-18/bin/clang++")
            cmd = [
                clang_path,
                "-fsyntax-only",
                "-std=c++20",
                "-I/usr/lib/llvm-18/include",
                file_path,
            ]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
            diagnostics = self._parse_clang_output(result.stdout + result.stderr, file_path, "csa")
            return ValidationResult(
                stage=ValidationStage.LSP,
                analyzer=AnalyzerType.CSA,
                success=result.returncode == 0,
                diagnostics=diagnostics,
                execution_time=time.time() - start_time,
                error_message="" if result.returncode == 0 else "语法错误",
            )
        except subprocess.TimeoutExpired:
            return ValidationResult(
                stage=ValidationStage.LSP,
                analyzer=AnalyzerType.CSA,
                success=False,
                execution_time=time.time() - start_time,
                error_message=f"验证超时 ({self.timeout}秒)",
            )
        except Exception as exc:
            return ValidationResult(
                stage=ValidationStage.LSP,
                analyzer=AnalyzerType.CSA,
                success=False,
                execution_time=time.time() - start_time,
                error_message=str(exc),
            )
        finally:
            if file_path and file_path.startswith(tempfile.gettempdir()):
                try:
                    os.unlink(file_path)
                except OSError:
                    pass

    def validate_codeql_query(self, query: str, file_path: str = None) -> ValidationResult:
        start_time = time.time()

        if not file_path:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".ql", delete=False) as file_handle:
                file_handle.write(query)
                file_path = file_handle.name

        try:
            codeql_path = self.config.get("codeql_path", "/usr/local/bin/codeql")
            if not os.path.exists(codeql_path):
                return self._basic_ql_syntax_check(query, file_path, start_time)

            pack_dir, pack_error = ensure_codeql_pack(
                file_path,
                codeql_path,
                self.timeout,
                self.config.get("search_path"),
            )
            if pack_error:
                return ValidationResult(
                    stage=ValidationStage.LSP,
                    analyzer=AnalyzerType.CODEQL,
                    success=False,
                    execution_time=time.time() - start_time,
                    error_message=pack_error,
                )

            cmd = [
                codeql_path,
                "query",
                "compile",
                "--check-only",
                *build_codeql_search_path_args(codeql_path, self.config.get("search_path")),
                file_path,
            ]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                cwd=str(pack_dir),
            )
            diagnostics = self._parse_codeql_output(result.stdout + result.stderr, file_path)
            return ValidationResult(
                stage=ValidationStage.LSP,
                analyzer=AnalyzerType.CODEQL,
                success=result.returncode == 0,
                diagnostics=diagnostics,
                execution_time=time.time() - start_time,
                error_message="" if result.returncode == 0 else "QL 语法错误",
            )
        except subprocess.TimeoutExpired:
            return ValidationResult(
                stage=ValidationStage.LSP,
                analyzer=AnalyzerType.CODEQL,
                success=False,
                execution_time=time.time() - start_time,
                error_message=f"验证超时 ({self.timeout}秒)",
            )
        except FileNotFoundError:
            return self._basic_ql_syntax_check(query, file_path, start_time)
        except Exception as exc:
            return ValidationResult(
                stage=ValidationStage.LSP,
                analyzer=AnalyzerType.CODEQL,
                success=False,
                execution_time=time.time() - start_time,
                error_message=str(exc),
            )
        finally:
            if file_path and file_path.startswith(tempfile.gettempdir()):
                try:
                    os.unlink(file_path)
                except OSError:
                    pass

    def _basic_ql_syntax_check(self, query: str, file_path: str, start_time: float) -> ValidationResult:
        diagnostics: List[Diagnostic] = []
        lines = query.split("\n")

        for line_number, line in enumerate(lines, start=1):
            if "select" in line.lower() and not line.strip().endswith(")"):
                open_count = line.count("(")
                close_count = line.count(")")
                if open_count > close_count:
                    diagnostics.append(Diagnostic(
                        file_path=file_path,
                        line=line_number,
                        column=len(line),
                        severity="warning",
                        message="可能缺少右括号",
                        source="lsp",
                        code="paren-mismatch",
                    ))

        success = len([item for item in diagnostics if item.severity == "error"]) == 0
        return ValidationResult(
            stage=ValidationStage.LSP,
            analyzer=AnalyzerType.CODEQL,
            success=success,
            diagnostics=diagnostics,
            execution_time=time.time() - start_time,
            error_message="" if success else "基础语法检查发现问题",
        )

    def _parse_clang_output(self, output: str, file_path: str, source: str) -> List[Diagnostic]:
        import re

        diagnostics: List[Diagnostic] = []
        pattern = r"(.+?):(\d+):(\d+):\s*(error|warning|note):\s*(.+)"
        for line in output.split("\n"):
            match = re.match(pattern, line)
            if match:
                diagnostics.append(Diagnostic(
                    file_path=match.group(1),
                    line=int(match.group(2)),
                    column=int(match.group(3)),
                    severity=match.group(4),
                    message=match.group(5),
                    source=source,
                ))
        return diagnostics

    def _parse_codeql_output(self, output: str, file_path: str) -> List[Diagnostic]:
        import re

        diagnostics: List[Diagnostic] = []
        for line in output.split("\n"):
            if "error" in line.lower():
                match = re.search(r"\[line (\d+)\]", line)
                line_num = int(match.group(1)) if match else 1
                diagnostics.append(Diagnostic(
                    file_path=file_path,
                    line=line_num,
                    column=1,
                    severity="error",
                    message=line.strip(),
                    source="codeql",
                ))
        return diagnostics
