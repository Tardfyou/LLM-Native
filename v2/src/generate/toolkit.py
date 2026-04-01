"""
简化版 Generate Toolkit - 封装工作流所需工具
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional

if TYPE_CHECKING:
    from ..agent.tools import ToolRegistry, ToolResult
else:
    # 运行时导入，避免循环依赖
    ToolRegistry = None
    ToolResult = None

from .models import GenerationRequest


def _get_tool_classes():
    """延迟导入工具类"""
    global ToolRegistry, ToolResult
    if ToolRegistry is None:
        from ..agent.tools import ToolRegistry as _TR
        from ..agent.tools import ToolResult as _TR2
        ToolRegistry = _TR
        ToolResult = _TR2
    return ToolRegistry, ToolResult


@dataclass
class GenerationTracker:
    """跟踪生成过程状态"""
    request: GenerationRequest
    compile_attempts: int = 0
    last_compile_output_path: str = ""
    last_codeql_ok: bool = False
    last_review_ok: bool = False
    last_lsp_ok: bool = False
    last_tool_error: str = ""
    knowledge_search_calls: int = 0
    history: List[Dict[str, Any]] = field(default_factory=list)


class GenerationToolkit:
    """简化版工具封装"""

    def __init__(
        self,
        tool_registry: "ToolRegistry",
        request: GenerationRequest,
        tracker: GenerationTracker,
        analyzer_name: str,
        progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        max_knowledge_search_calls: int = 2,
    ):
        self._tool_registry = tool_registry
        self._request = request
        self._tracker = tracker
        self._analyzer_name = analyzer_name
        self._progress_callback = progress_callback
        self._max_knowledge_search_calls = max(1, int(max_knowledge_search_calls or 2))

    def read_patch(self) -> "ToolResult":
        return self._run("read_file", {"path": self._request.patch_path})

    def analyze_patch(self) -> "ToolResult":
        return self._run(
            "analyze_patch",
            {"patch_path": self._request.patch_path, "analysis_depth": "deep"},
        )

    def search_knowledge(self, query: str, top_k: int = 3) -> "ToolResult":
        return self._run(
            "search_knowledge",
            {"query": query, "top_k": max(1, min(int(top_k or 3), 8))},
        )

    def generate_codeql_query(
        self,
        query_name: str,
        vulnerability_type: str,
        description: str,
        pattern_description: str,
        custom_query: str,
    ) -> "ToolResult":
        return self._run(
            "generate_codeql_query",
            {
                "query_name": query_name,
                "vulnerability_type": vulnerability_type,
                "description": description,
                "pattern_description": pattern_description,
                "custom_query": custom_query,
                "include_header": True,
            },
        )

    def write_artifact(self, path: str, content: str) -> "ToolResult":
        return self._run("write_file", {"path": path, "content": content})

    def read_artifact(self, path: str) -> "ToolResult":
        return self._run("read_file", {"path": path})

    def apply_artifact_patch(self, path: str, patch: str, resulting_content: str = "") -> "ToolResult":
        args: Dict[str, Any] = {
            "source_path": path,
            "target_path": path,
            "patch": patch,
        }
        if resulting_content:
            args["resulting_content"] = resulting_content
        return self._run("apply_patch", args)

    def lsp_validate_code(self, code: str, file_name: str, check_level: str = "quick") -> "ToolResult":
        return self._run(
            "lsp_validate",
            {"code": code, "check_level": check_level, "file_name": file_name},
        )

    def review_artifact(self, artifact_path: str, analyzer: str, source_code: str = "", review_mode: str = "generate") -> "ToolResult":
        args: Dict[str, Any] = {
            "artifact_path": artifact_path,
            "analyzer": analyzer,
            "review_mode": review_mode,
        }
        if source_code:
            args["source_code"] = source_code
        return self._run("review_artifact", args)

    def compile_artifact(self, artifact_path: str, checker_name: str) -> "ToolResult":
        code = Path(artifact_path).read_text(encoding="utf-8")
        return self._run(
            "compile_checker",
            {
                "checker_name": checker_name,
                "source_code": code,
                "output_dir": self._request.work_dir,
            },
        )

    def analyze_artifact(self, artifact_path: str) -> "ToolResult":
        return self._run("codeql_analyze", {"query_file": artifact_path})

    def _run(self, tool_name: str, args: Dict[str, Any]) -> "ToolResult":
        if not self._tool_registry or not self._tool_registry.has(tool_name):
            raise ValueError(f"未注册工具: {tool_name}")

        # 检查 knowledge search 次数限制
        if tool_name == "search_knowledge" and self._tracker.knowledge_search_calls >= self._max_knowledge_search_calls:
            _, ToolResultCls = _get_tool_classes()
            result = ToolResultCls(
                success=False,
                output="",
                error=f"generate 阶段最多只允许调用 {self._max_knowledge_search_calls} 次 search_knowledge。",
            )
            self._record(tool_name, args, result)
            return result

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
        )
        return result

    def _record(self, tool_name: str, args: Dict[str, Any], result: "ToolResult"):
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
        if tool_name == "search_knowledge":
            self._tracker.knowledge_search_calls += 1
        elif tool_name == "compile_checker":
            self._tracker.compile_attempts += 1
            if result.success:
                self._tracker.last_compile_output_path = str(metadata.get("output_file", "") or "")
        elif tool_name == "codeql_analyze":
            self._tracker.last_codeql_ok = bool(result.success)
        elif tool_name == "review_artifact":
            self._tracker.last_review_ok = bool(result.success)
        elif tool_name == "lsp_validate":
            self._tracker.last_lsp_ok = bool(result.success)

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

    def _summarize_tool_result(self, result: "ToolResult") -> str:
        if result.success:
            source = result.output or str(result.metadata or {})
        else:
            source = result.output or result.error or str(result.metadata or {})
        text = " ".join(str(source).split())
        return text[:200]