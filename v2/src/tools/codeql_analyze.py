"""
CodeQL 分析工具

提供:
- 执行 CodeQL 查询
- 解析查询结果
- 生成分析报告
"""

import os
import json
import re
import shlex
import subprocess
import tempfile
from typing import Dict, Any, List, Optional, Tuple
from pathlib import Path
from dataclasses import dataclass

from loguru import logger

from ..agent.tools import Tool, ToolResult
from ..validation import (
    build_codeql_search_path_args,
    ensure_codeql_pack,
    resolve_codeql_database_path,
    is_codeql_database_dir,
)


class CodeQLAnalyzeTool(Tool):
    """CodeQL 执行工具（最小可用实现）"""

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.work_dir = self.config.get("work_dir")
        self.codeql_path = self.config.get("codeql_path", "codeql")
        self.database_path = self.config.get("database_path", "")
        self.search_path = self.config.get("search_path", "")
        self.timeout = int(self.config.get("timeout", 180))
        self.threads = max(int(self.config.get("threads", 0) or 0), 0)
        self.max_memory_mb = max(int(self.config.get("max_memory_mb", 2048) or 2048), 2048)
        self.default_target_path: Optional[str] = self.config.get("target_path")

    def set_work_dir(self, work_dir: str):
        """设置工作目录，支持相对路径查询文件。"""
        self.work_dir = os.path.abspath(work_dir) if work_dir else work_dir

        # 仅在未配置数据库路径时，使用当前任务输出目录下的默认路径。
        # 注意：不要把“用户配置的相对路径”强行拼接到 work_dir，
        # 否则会出现 test_project/codeql/tests/test_project/codeql 这类重复堆叠。
        if not self.database_path:
            self.database_path = os.path.join(self.work_dir, "database", "default_cpp")

    def set_target_path(self, target_path: str):
        """设置默认目标路径（用于数据库自动创建）。"""
        self.default_target_path = self._normalize_target_path(target_path)

    @property
    def name(self) -> str:
        return "codeql_analyze"

    @property
    def description(self) -> str:
        return "执行 CodeQL 查询并返回结果摘要。"

    @property
    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "query_file": {"type": "string", "description": "QL 查询文件路径"},
                "database_path": {"type": "string", "description": "CodeQL 数据库路径（可选）"},
            },
            "required": ["query_file"],
        }

    def execute(self, query_file: str, database_path: Optional[str] = None, **kwargs) -> ToolResult:
        from ..validation import (
            build_codeql_database_path,
            resolve_codeql_database_path,
            is_codeql_database_dir,
        )

        query_file = self._resolve_query_file(query_file)
        db_path = database_path or self.database_path
        if not db_path and self.work_dir:
            db_path = os.path.join(self.work_dir, "database", "default_cpp")
        target_path = self._normalize_target_path(self.default_target_path)

        if not os.path.exists(query_file):
            return ToolResult(success=False, output="", error=f"查询文件不存在: {query_file}")

        try:
            pack_dir, pack_error = ensure_codeql_pack(
                query_file,
                self.codeql_path,
                self.timeout,
                self.search_path,
            )
            if pack_error:
                return ToolResult(success=False, output="", error=pack_error)

            compile_cmd = [
                self.codeql_path,
                "query",
                "compile",
                "--check-only",
                *build_codeql_search_path_args(self.codeql_path, self.search_path),
                query_file,
            ]
            compile_proc = subprocess.run(
                compile_cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                cwd=str(pack_dir),
            )

            compile_output = ((compile_proc.stdout or "") + "\n" + (compile_proc.stderr or "")).strip()
            if compile_proc.returncode != 0:
                diagnostics = self._extract_compile_diagnostics(compile_output, query_file)
                suggestions = self._build_repair_suggestions(compile_output)
                output = self._format_compile_failure_output(
                    compile_output=compile_output,
                    query_file=query_file,
                    diagnostics=diagnostics,
                    suggestions=suggestions,
                )
                return ToolResult(
                    success=False,
                    output=output,
                    error="CodeQL 查询语法检查失败",
                    metadata={
                        "query_file": query_file,
                        "stage": "compile",
                        "returncode": compile_proc.returncode,
                        "diagnostics": diagnostics,
                        "suggestions": suggestions,
                    },
                )

            db_path, resolution_message = resolve_codeql_database_path(db_path, target_path)
            if not os.path.exists(db_path) or not is_codeql_database_dir(db_path):
                if target_path:
                    db_path = build_codeql_database_path(db_path, target_path)
                    ok, msg = self._ensure_codeql_database(db_path, target_path)
                    if not ok:
                        return ToolResult(
                            success=False,
                            output="",
                            error=msg,
                            metadata={
                                "query_file": query_file,
                                "database_path": db_path,
                                "stage": "database-create",
                            },
                        )
                else:
                    return ToolResult(
                        success=True,
                        output=(
                            "CodeQL 查询语法检查通过。"
                            + (f" 未发现可用数据库，跳过语义执行。{resolution_message}" if resolution_message else " 未发现可用数据库，跳过语义执行。")
                        ),
                        metadata={
                            "query_file": query_file,
                            "database_path": db_path,
                            "syntax_only": True,
                            "stage": "compile",
                            "resolution_message": resolution_message,
                        },
                    )

            out_path = os.path.join(os.path.dirname(query_file), "results.bqrs")
            cmd = [
                self.codeql_path,
                "query",
                "run",
                *build_codeql_search_path_args(self.codeql_path, self.search_path),
                f"--threads={self.threads}",
                "--ram",
                str(self.max_memory_mb),
                "--database",
                db_path,
                "--output",
                out_path,
                query_file,
            ]
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                cwd=str(pack_dir),
            )
            ok = proc.returncode == 0
            stdout = proc.stdout or ""
            stderr = proc.stderr or ""

            return ToolResult(
                success=ok,
                output=(stdout + "\n" + stderr).strip(),
                error=None if ok else "CodeQL 查询执行失败",
                metadata={
                    "query_file": query_file,
                    "database_path": db_path,
                    "output_bqrs": out_path,
                    "syntax_only": False,
                    "returncode": proc.returncode,
                },
            )
        except subprocess.TimeoutExpired:
            return ToolResult(success=False, output="", error=f"CodeQL 执行超时 ({self.timeout}s)")
        except Exception as e:
            return ToolResult(success=False, output="", error=f"CodeQL 执行异常: {e}")

    def _resolve_query_file(self, query_file: str) -> str:
        """将相对路径查询文件解析到工作目录或 codeql 子目录。"""
        if not query_file:
            return query_file

        if os.path.isabs(query_file):
            if os.path.exists(query_file) or not self.work_dir:
                return query_file

            basename = os.path.basename(query_file)
            candidates = [
                os.path.join(self.work_dir, basename),
                os.path.join(self.work_dir, "codeql", basename),
            ]
            raw_path = Path(query_file)
            for candidate in candidates:
                if os.path.exists(candidate):
                    return os.path.abspath(candidate)

            work_dir_path = Path(self.work_dir)
            for candidate in [work_dir_path, work_dir_path / "codeql"]:
                if not candidate.exists():
                    continue
                if self._path_suffix_overlap(raw_path, candidate) >= 2:
                    return str(candidate.resolve())
            return query_file

        if not self.work_dir:
            return query_file

        candidates = [
            os.path.join(self.work_dir, query_file),
            os.path.join(self.work_dir, "codeql", query_file.lstrip("./")),
            os.path.join(self.work_dir, "codeql", os.path.basename(query_file)),
        ]
        for candidate in candidates:
            if os.path.exists(candidate):
                return os.path.abspath(candidate)

        return os.path.abspath(candidates[0])

    def _normalize_target_path(self, target_path: Optional[str]) -> str:
        raw = str(target_path or "").strip()
        if not raw:
            return ""
        path = Path(raw).expanduser()
        if path.is_absolute():
            return str(path.resolve())
        return str(path.resolve())

    def _path_suffix_overlap(self, raw_path: Path, candidate: Path) -> int:
        raw_parts = [part for part in raw_path.parts if part not in {os.sep, ""}]
        candidate_parts = [part for part in candidate.parts if part not in {os.sep, ""}]
        overlap = 0
        while overlap < len(raw_parts) and overlap < len(candidate_parts):
            if raw_parts[-(overlap + 1)] != candidate_parts[-(overlap + 1)]:
                break
            overlap += 1
        return overlap

    def _build_repair_suggestions(self, compile_output: str) -> List[str]:
        """基于常见 CodeQL 编译报错给出简短修复建议。"""
        lower_output = (compile_output or "").lower()
        suggestions: List[str] = []

        if "unexpected input ')'" in lower_output or "unexpected input ']'" in lower_output:
            suggestions.append("优先检查报错行前一行是否残留 `and`/`or`，以及当前 `exists(...)` / `not exists(...)` / 分组括号是否少关或多关了一层。")
        if "multiple select clauses" in lower_output:
            suggestions.append("一个 .ql 文件只保留一个最终 select 子句；把多个模式收敛为多个 predicate，再由单个 from/where/select 汇总。")
        if "cannot be resolved" in lower_output:
            suggestions.append("如果报错对象是局部变量名，先检查它是否被引用在定义它的量词之外；优先把变量移回同一个 `exists(...)` / `forall(...)`。")
            suggestions.append("先按报错行做本地最小修复；只有同类 exact API 错误连续两次仍未收敛时，再检索 exact symbol。")
            suggestions.append("替换报错的未知 CodeQL API，改用已知的基础 `cpp` AST API；不要删除整类漏洞模式。")
        if "could not resolve type" in lower_output:
            suggestions.append("优先直接替换无法解析的类型名；只有连续两次本地修复仍失败时，再检索 exact 类型或模块。")
            suggestions.append("只修正无法解析的类型名或导入，保留原有查询结构和泛化目标。")
        if "isglobal() cannot be resolved" in lower_output:
            suggestions.append("不要调用 `Variable.isGlobal()`；改用 `v instanceof GlobalVariable` 判定全局变量。")
        if "getnumberofcallsites() cannot be resolved" in lower_output:
            suggestions.append("不要调用 `getNumberOfCallSites()`；改用 `count(FunctionCall fc | fc.getTarget() = f) > N`。")
        if "getaparent() cannot be resolved" in lower_output:
            suggestions.append("不要调用 `getAParent()`；C/C++ AST 节点应改用 `Expr.getParent()`，递归遍历再配合 `getAChild()`。")
        if "getbase() cannot be resolved for type access::fieldaccess" in lower_output:
            suggestions.append("不要把 `FieldAccess` 当成有 `getBase()`；字段接收者应改用 `FieldAccess.getQualifier()`。")
        if "getqualifier() cannot be resolved" in lower_output:
            suggestions.append("只有 `VariableAccess` / `FieldAccess` / `Call` 等节点才有 `getQualifier()`；先把表达式收窄到正确 AST 类型再调用。")
        if "gettarget() cannot be resolved for type expr::expr" in lower_output:
            suggestions.append("`Expr` 没有 `getTarget()`；先把该表达式收窄为 `FieldAccess` 或 `VariableAccess`，再调用 `.getTarget()`。")
        if "could not resolve type callsite" in lower_output:
            suggestions.append("`CallSite` 在当前上下文不可用；改用 `FunctionCall` 或 `Expr`。")
        if "could not resolve type staticvariable" in lower_output:
            suggestions.append("不要依赖 `StaticVariable` 类型；优先使用 `GlobalVariable` + 访问模式组合建模。")
        if "could not resolve type declarator" in lower_output:
            suggestions.append("不要使用 `Declarator`；优先在 `Expr`/`VariableAccess`/`FunctionCall` 层建模。")
        if "could not resolve type unaryexpr" in lower_output:
            suggestions.append("不要使用 `UnaryExpr`；在 CodeQL C/C++ 中直接改用 `UnaryOperation`，不要先为这个错误发起 broad 检索。")
        if "unaryoperation is incompatible with comparisonoperation::relationaloperation" in lower_output:
            suggestions.append("不要把同一个条件表达式同时当成 `UnaryOperation` 和 `RelationalOperation`；改成两个带 `instanceof` 的分支分别处理。")
        if "no viable parse" in lower_output or "unexpected input" in lower_output:
            suggestions.append("检查谓词体是否缺少 `and`/`or` 连接，避免裸表达式连续堆叠。")
        if "missing one of: ')'" in lower_output:
            suggestions.append("优先检查出错行附近的括号是否闭合，以及 `or` 分支是否整体用括号包住；不要通过删除整段谓词来绕过。")
        if "query module contains multiple select clauses" in lower_output:
            suggestions.append("不要为每类模式单独写一个 select；保留现有模式逻辑，将它们折叠进单个最终查询。")
        if "unused variable" in lower_output:
            suggestions.append("删除未使用的量词变量或 helper 参数；不要为了“以后可能会用”保留它。")

        if compile_output:
            suggestions.append("禁止通过重命名文件或大幅删减逻辑来绕过错误；应针对报错行附近做定点修复。")

        return suggestions[:4]

    def _extract_compile_diagnostics(self, compile_output: str, query_file: str) -> List[Dict[str, Any]]:
        pattern = re.compile(
            r"^(?P<severity>ERROR|WARNING):\s*(?P<message>.+?)\s+\((?P<path>.+?):(?P<line>\d+),(?P<column>\d+)(?:-\d+)?\)$"
        )
        resolved_query = str(Path(query_file).resolve())
        diagnostics: List[Dict[str, Any]] = []

        for raw_line in (compile_output or "").splitlines():
            line = str(raw_line or "").strip()
            if not line:
                continue
            match = pattern.match(line)
            if not match:
                continue

            file_path = str(Path(match.group("path")).resolve())
            diagnostics.append(
                {
                    "severity": match.group("severity"),
                    "message": match.group("message").strip(),
                    "file_path": file_path,
                    "line": int(match.group("line")),
                    "column": int(match.group("column")),
                    "is_primary": file_path == resolved_query,
                }
            )

        diagnostics.sort(
            key=lambda item: (
                not bool(item.get("is_primary")),
                0 if str(item.get("severity")) == "ERROR" else 1,
                int(item.get("line", 0) or 0),
                int(item.get("column", 0) or 0),
            )
        )
        return diagnostics

    def _format_compile_failure_output(
        self,
        compile_output: str,
        query_file: str,
        diagnostics: List[Dict[str, Any]],
        suggestions: List[str],
    ) -> str:
        lines: List[str] = ["CodeQL 查询语法检查失败。"]
        primary_file = str(Path(query_file).resolve())

        if diagnostics:
            lines.append("")
            lines.append("关键诊断:")
            for item in diagnostics[:6]:
                file_path = str(item.get("file_path", "") or "")
                file_label = "当前查询" if file_path == primary_file else Path(file_path).name
                location = f"{item.get('line', 0)}:{item.get('column', 0)}"
                lines.append(f"- {item.get('severity', 'ERROR')} [{file_label} {location}] {item.get('message', '')}")

        if suggestions:
            lines.append("")
            lines.append("修复建议:")
            lines.extend(f"- {item}" for item in suggestions[:4])

        if compile_output.strip():
            lines.append("")
            lines.append("原始输出:")
            lines.append(compile_output.strip())

        return "\n".join(lines).strip()

    def _ensure_codeql_database(self, database_path: str, target_path: str) -> Tuple[bool, str]:
        """确保数据库存在，不存在则创建。"""
        from ..validation import is_codeql_database_dir

        build_script_path = None
        try:
            if is_codeql_database_dir(database_path):
                return True, "数据库已存在"

            if not target_path or not os.path.exists(target_path):
                return False, f"无法创建数据库，目标路径不存在: {target_path}"

            source_root = target_path if os.path.isdir(target_path) else os.path.dirname(target_path)
            os.makedirs(os.path.dirname(database_path) or ".", exist_ok=True)

            build_command = self._project_build_script(source_root)
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
                cwd=source_root,
            )

            if proc.returncode != 0:
                return False, self._format_database_create_failure(
                    cmd=cmd,
                    proc=proc,
                    database_path=database_path,
                    source_root=source_root,
                    build_script_path=build_script_path,
                )

            return True, "数据库创建成功"
        except Exception as e:
            return False, f"CodeQL 数据库创建异常: {e}"
        finally:
            if build_script_path and os.path.exists(build_script_path):
                try:
                    os.unlink(build_script_path)
                except OSError:
                    pass

    def _project_build_script(self, source_root: str) -> Optional[str]:
        """Use the prepared whole-directory build script when sample_env created one."""
        env_dir = Path(source_root) / ".patchweaver_env"
        manifest_path = env_dir / "validation_env.json"
        if manifest_path.exists():
            try:
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                script = str(manifest.get("codeql_build_script", "") or "").strip()
                if script and Path(script).exists():
                    return script
            except Exception:
                pass
        fallback = env_dir / "codeql_build.sh"
        if fallback.exists():
            return str(fallback)
        return None

    def _format_database_create_failure(
        self,
        *,
        cmd: List[str],
        proc: subprocess.CompletedProcess,
        database_path: str,
        source_root: str,
        build_script_path: Optional[str],
    ) -> str:
        lines = [
            "CodeQL 数据库创建失败。",
            f"returncode={proc.returncode}",
            f"source_root={source_root}",
            f"database_path={database_path}",
            "command=" + " ".join(shlex.quote(str(part)) for part in cmd),
        ]
        if build_script_path:
            lines.append(f"build_script={build_script_path}")
            try:
                lines.append("build_script_content:")
                lines.append(Path(build_script_path).read_text(encoding="utf-8", errors="replace")[:2000])
            except OSError:
                pass

        combined = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
        if combined:
            lines.append("codeql_stdout_stderr:")
            lines.append(combined[:4000])

        log_tail = self._latest_database_log_tail(database_path)
        if log_tail:
            lines.append("latest_codeql_log_tail:")
            lines.append(log_tail)

        return "\n".join(lines).strip()

    def _latest_database_log_tail(self, database_path: str, limit: int = 4000) -> str:
        log_dir = Path(database_path) / "log"
        if not log_dir.exists():
            return ""
        logs = sorted(log_dir.glob("*.log"), key=lambda path: path.stat().st_mtime, reverse=True)
        if not logs:
            return ""
        latest = logs[0]
        try:
            text = latest.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""
        return f"{latest}:\n{text[-limit:]}"
