from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from ..agent.tools import ToolRegistry, ToolResult
from .models import RefinementRequest


@dataclass
class RefinementTracker:
    request: RefinementRequest
    compile_attempts: int = 0
    last_compile_output_path: str = ""
    last_codeql_ok: bool = False
    last_semantic_ok: bool = False
    last_review_ok: bool = False
    last_review_metadata: Dict[str, Any] = field(default_factory=dict)
    last_tool_error: str = ""
    history: List[Dict[str, Any]] = field(default_factory=list)


class RefinementToolkit:
    def __init__(
        self,
        tool_registry: ToolRegistry,
        request: RefinementRequest,
        tracker: RefinementTracker,
        analyzer_name: str,
        progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    ):
        self._tool_registry = tool_registry
        self._request = request
        self._tracker = tracker
        self._analyzer_name = analyzer_name
        self._progress_callback = progress_callback

    def read_artifact(self) -> str:
        return self._run("read_file", {"path": self._request.target_path})

    def read_patch(self) -> str:
        return self._run("read_file", {"path": self._request.patch_path})

    def read_reference_file(self, path: str) -> str:
        resolved = self._resolve_allowed_path(path)
        return self._run("read_file", {"path": resolved})

    def list_reference_dir(self, path: str, recursive: bool = False) -> str:
        resolved = self._resolve_allowed_path(path, expect_dir=True)
        return self._run(
            "multi_file_ops",
            {"operation": "list_dir", "directory": resolved, "recursive": bool(recursive)},
        )

    def apply_artifact_patch(self, patch: str, resulting_content: str = "") -> str:
        args: Dict[str, Any] = {
            "source_path": self._request.target_path,
            "target_path": self._request.target_path,
            "patch": patch,
        }
        if resulting_content:
            args["resulting_content"] = resulting_content
        return self._run("apply_patch", args)

    def lsp_validate_artifact(self, check_level: str = "quick") -> str:
        code = Path(self._request.target_path).read_text(encoding="utf-8")
        return self.lsp_validate_code(
            code=code,
            check_level=check_level,
            file_name=Path(self._request.target_path).name,
        )

    def lsp_validate_code(self, code: str, check_level: str = "quick", file_name: str = "") -> str:
        return self._run(
            "lsp_validate",
            {
                "code": code,
                "check_level": check_level,
                "file_name": file_name or Path(self._request.target_path).name,
            },
        )

    def compile_artifact(self) -> str:
        code = Path(self._request.target_path).read_text(encoding="utf-8")
        checker_name = self._request.checker_name or Path(self._request.target_path).stem
        return self._run(
            "compile_checker",
            {
                "checker_name": checker_name,
                "source_code": code,
                "output_dir": self._request.work_dir,
            },
        )

    def analyze_artifact(self) -> str:
        return self._run(
            "codeql_analyze",
            {
                "query_file": self._request.target_path,
            },
        )

    def semantic_validate_artifact(self) -> str:
        checker_so_path = str(self._tracker.last_compile_output_path or "").strip()
        if not checker_so_path:
            return "ERROR: 缺少已编译的检测器 .so，无法执行功能验证。"

        target_path = str(self._request.validate_path or "").strip()
        if not target_path:
            return "ERROR: 缺少 validate_path，无法执行功能验证。"

        checker_name = self._request.checker_name or Path(self._request.target_path).stem
        args: Dict[str, Any] = {
            "checker_so_path": checker_so_path,
            "checker_name": f"custom.{checker_name}",
            "target_path": target_path,
        }
        compile_commands_path = self._resolve_compile_commands_path(target_path)
        if compile_commands_path:
            args["compile_commands_path"] = compile_commands_path
        result = self._run("semantic_validate", args)
        if not self._tracker.last_semantic_ok and not str(result or "").startswith("ERROR:"):
            return "ERROR: 功能验证未在漏洞目标上产生诊断。\n" + result
        return result

    def has_tool(self, tool_name: str) -> bool:
        return bool(self._tool_registry and self._tool_registry.has(tool_name))

    def review_artifact(self) -> str:
        code = Path(self._request.target_path).read_text(encoding="utf-8")
        return self.review_source_code(code)

    def review_source_code(self, code: str) -> str:
        return self._run(
            "review_artifact",
            {
                "artifact_path": self._request.target_path,
                "analyzer": self._request.analyzer,
                "source_code": code,
                "review_mode": "refine",
            },
        )

    def _resolve_allowed_path(self, raw_path: str, expect_dir: bool = False) -> str:
        token = str(raw_path or "").strip()
        if not token:
            raise ValueError("path 不能为空")

        path = Path(token).expanduser()
        base_root = (
            self._request.evidence_dir
            or self._request.validate_path
            or self._request.work_dir
        )
        resolved = (path if path.is_absolute() else Path(base_root) / path).resolve()
        allowed_roots = [
            Path(self._request.patch_path).expanduser().resolve().parent,
            Path(self._request.target_path).expanduser().resolve().parent,
        ]
        if self._request.evidence_dir:
            allowed_roots.append(Path(self._request.evidence_dir).expanduser().resolve())
        if self._request.validate_path:
            allowed_roots.append(Path(self._request.validate_path).expanduser().resolve())

        if not any(resolved == root or root in resolved.parents for root in allowed_roots):
            raise ValueError(f"路径超出 refine 允许范围: {resolved}")
        if expect_dir and not resolved.is_dir():
            raise ValueError(f"目标不是目录: {resolved}")
        if not expect_dir and not resolved.exists():
            raise FileNotFoundError(f"文件不存在: {resolved}")
        return str(resolved)

    def _resolve_compile_commands_path(self, target_path: str) -> str:
        try:
            from ..experiments.sample_env import load_validation_env

            validation_env = load_validation_env(target_path)
        except Exception:
            validation_env = {}
        compile_commands_path = str((validation_env or {}).get("compile_commands_path", "") or "").strip()
        if compile_commands_path and Path(compile_commands_path).exists():
            return compile_commands_path

        target = Path(target_path).expanduser()
        candidates = []
        if target.is_dir():
            candidates.append(target / "compile_commands.json")
        else:
            candidates.append(target.parent / "compile_commands.json")
        for candidate in candidates:
            if candidate.exists():
                return str(candidate.resolve())
        return ""

    def _run(self, tool_name: str, args: Dict[str, Any]) -> str:
        if not self._tool_registry or not self._tool_registry.has(tool_name):
            raise ValueError(f"未注册工具: {tool_name}")

        self._emit_progress("tool_called", tool_name=tool_name, args_preview=self._preview_args(args))
        tool = self._tool_registry.get(tool_name)
        result = tool.execute(**args)
        self._record(tool_name, args, result)
        self._emit_progress(
            "tool_result",
            tool_name=tool_name,
            success=result.success,
            error=result.error,
            summary=self._summarize_tool_result(result),
            llm_usage=self._tool_llm_usage(result),
        )

        if result.success:
            return result.output or json.dumps(result.metadata or {}, ensure_ascii=False, indent=2)
        details: List[str] = [f"ERROR: {result.error or 'tool execution failed'}"]
        output_text = str(result.output or "").strip()
        if output_text:
            details.append(output_text)
        metadata = dict(result.metadata or {})
        if metadata and not output_text:
            details.append(json.dumps(metadata, ensure_ascii=False, indent=2))
        return "\n".join(details)

    def _record(self, tool_name: str, args: Dict[str, Any], result: ToolResult):
        metadata = dict(result.metadata or {})
        item = {
            "tool_name": tool_name,
            "success": bool(result.success),
            "error": result.error or "",
            "metadata": metadata,
        }
        self._tracker.history.append(item)
        if not result.success:
            self._tracker.last_tool_error = result.error or result.output or ""

        if tool_name == "compile_checker":
            self._tracker.compile_attempts += 1
            if result.success:
                self._tracker.last_compile_output_path = str(metadata.get("output_file", "") or "")
        elif tool_name == "codeql_analyze":
            self._tracker.last_codeql_ok = bool(result.success)
        elif tool_name == "semantic_validate":
            report_count = self._semantic_report_count(result)
            self._tracker.last_semantic_ok = bool(result.success and report_count > 0)
        elif tool_name == "review_artifact":
            self._tracker.last_review_ok = bool(result.success)
            self._tracker.last_review_metadata = metadata

    def _semantic_report_count(self, result: ToolResult) -> int:
        metadata = dict(result.metadata or {})
        for key in ("total_bug_reports", "bugs_found", "diagnostics_count"):
            try:
                return int(metadata.get(key, 0) or 0)
            except Exception:
                continue
        match = re.search(r"漏洞报告数\s*[:：]\s*(\d+)", str(result.output or ""))
        if match:
            return int(match.group(1))
        return 0

    def _emit_progress(self, event: str, **payload: Any):
        if self._progress_callback is None:
            return
        self._progress_callback({
            "event": event,
            "analyzer_name": self._analyzer_name,
            **payload,
        })

    def _preview_args(self, args: Dict[str, Any]) -> str:
        preview_items: List[str] = []
        for key, value in args.items():
            if value is None:
                continue
            text = str(value)
            if len(text) > 120:
                text = text[:117] + "..."
            preview_items.append(f"{key}={text}")
        return ", ".join(preview_items[:4])

    def _summarize_tool_result(self, result: ToolResult) -> str:
        if result.success:
            source = result.output or json.dumps(result.metadata or {}, ensure_ascii=False, indent=2)
        else:
            parts: List[str] = []
            if result.error:
                parts.append(f"ERROR: {result.error}")
            if result.output:
                parts.append(str(result.output))
            elif result.metadata:
                parts.append(json.dumps(result.metadata, ensure_ascii=False, indent=2))
            source = "\n".join(parts)
        text = " ".join(str(source).split())
        return text[:200]

    def _tool_llm_usage(self, result: ToolResult) -> Dict[str, Any]:
        metadata = dict(result.metadata or {})
        raw_usage = metadata.get("llm_usage", {})
        if not isinstance(raw_usage, dict):
            return {}
        if not any(int(raw_usage.get(key, 0) or 0) > 0 for key in ("prompt_tokens", "completion_tokens", "total_tokens")):
            return {}
        return {
            "prompt_tokens": int(raw_usage.get("prompt_tokens", 0) or 0),
            "completion_tokens": int(raw_usage.get("completion_tokens", 0) or 0),
            "total_tokens": int(raw_usage.get("total_tokens", 0) or 0),
            "call_count": int(raw_usage.get("call_count", 1) or 1),
            "available": bool(raw_usage.get("available", True)),
            "model": str(raw_usage.get("model", "") or "").strip(),
        }
