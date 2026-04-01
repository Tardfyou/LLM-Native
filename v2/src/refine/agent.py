from __future__ import annotations

import ast
import difflib
import json
import re
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, TypedDict

from langchain_core.messages import HumanMessage, SystemMessage
from langgraph.errors import GraphRecursionError
from langgraph.graph import END, START, StateGraph

from ..agent.tools import ToolRegistry
from ..prompts import PromptRepository
from .codeql_structural import build_codeql_structural_candidate
from .csa_structural import build_csa_structural_candidate
from .structural.codeql import infer_codeql_structural_family
from .structural.csa import infer_csa_structural_family
from .llm import build_langchain_chat_model
from .models import RefinementRequest, RefinementResult
from .toolkit import RefinementToolkit, RefinementTracker

_CSA_RESULTING_CONTENT_GUARDS = (
    (
        re.compile(r"\bassumeInBound\s*\("),
        "候选代码引入了 `assumeInBound(...)`；这是当前工作副本中不存在且高风险的 CSA API 臆造，禁止继续提交。",
    ),
    (
        re.compile(r"\bassume\s*\([\s\S]{0,240}\)\s*\.isValid\s*\(", flags=re.MULTILINE),
        "不要把 `assume(...).isValid()` 当成 size guard 已成立的证据；这不是补丁式 barrier 语义。",
    ),
)


class RefinementDecision(TypedDict, total=False):
    action: str
    summary: str
    path: str
    recursive: bool
    query: str
    patch: str
    resulting_content: str


class RefinementWorkflowState(TypedDict, total=False):
    artifact_text: str
    patch_text: str
    context_notes: List[str]
    decision: RefinementDecision
    model_turns: int
    patch_applied: bool
    route: str
    error_message: str
    final_message: str
    raw_decision_text: str


class LangChainRefinementAgent:
    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        tool_registry: Optional[ToolRegistry] = None,
        analyzer: str = "csa",
        progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        llm_override: Any = None,
    ):
        self.config = config or {}
        self.tool_registry = tool_registry
        self.analyzer = str(analyzer or "csa").strip().lower()
        self.progress_callback = progress_callback
        self.prompt_repository = PromptRepository(config=self.config)
        self.max_iterations = max(
            4,
            int(((self.config.get("agent", {}) or {}).get("max_iterations", 12) or 12)),
        )
        gate_config = ((self.config.get("quality_gates", {}) or {}).get("artifact_review", {}) or {})
        self.artifact_review_required = bool(gate_config.get("enabled", True))
        self.model = build_langchain_chat_model(self.config, override=llm_override)

    def run(self, request: RefinementRequest) -> RefinementResult:
        tracker = RefinementTracker(request=request)
        toolkit = RefinementToolkit(
            tool_registry=self.tool_registry,
            request=request,
            tracker=tracker,
            analyzer_name=self._analyzer_display_name(),
            progress_callback=self.progress_callback,
        )
        system_prompt = self._render_system_prompt()
        task_prompt = self._render_task_prompt(request)
        workflow = self._build_workflow(
            request=request,
            tracker=tracker,
            toolkit=toolkit,
            system_prompt=system_prompt,
            task_prompt=task_prompt,
        )

        self._emit_progress("run_started", patch_path=request.patch_path, target_path=request.target_path)
        try:
            final_state = workflow.invoke(
                {
                    "artifact_text": "",
                    "patch_text": "",
                    "context_notes": [],
                    "decision": {},
                    "model_turns": 0,
                    "patch_applied": False,
                    "route": "bootstrap",
                    "error_message": "",
                    "final_message": "",
                },
                config={"recursion_limit": max(24, request.max_iterations * 8)},
            )
        except GraphRecursionError as exc:
            return self._finalize_result(
                tracker=tracker,
                final_state={},
                error_message=f"达到最大精炼步数限制: {exc}",
            )
        except Exception as exc:
            return self._finalize_result(
                tracker=tracker,
                final_state={},
                error_message=str(exc),
            )

        return self._finalize_result(tracker=tracker, final_state=final_state)

    def _build_workflow(
        self,
        request: RefinementRequest,
        tracker: RefinementTracker,
        toolkit: RefinementToolkit,
        system_prompt: str,
        task_prompt: str,
    ):
        def bootstrap(state: RefinementWorkflowState) -> RefinementWorkflowState:
            artifact_text = toolkit.read_artifact()
            if self._is_error_text(artifact_text):
                return {
                    "artifact_text": "",
                    "patch_text": "",
                    "context_notes": [self._make_note("bootstrap.read_artifact", artifact_text)],
                    "route": "finish",
                    "error_message": artifact_text.removeprefix("ERROR: ").strip(),
                    "final_message": "无法读取当前工作副本。",
                }

            patch_text = toolkit.read_patch()
            if self._is_error_text(patch_text):
                return {
                    "artifact_text": artifact_text,
                    "patch_text": "",
                    "context_notes": [self._make_note("bootstrap.read_patch", patch_text)],
                    "route": "finish",
                    "error_message": patch_text.removeprefix("ERROR: ").strip(),
                    "final_message": "无法读取补丁内容。",
                }

            notes: List[str] = []
            notes.extend(self._bootstrap_reference_notes(request, toolkit, patch_text))
            structural_candidate = ""
            if self._structural_candidate_enabled(request, artifact_text, patch_text):
                structural_candidate = self._build_structural_candidate(
                    request=request,
                    artifact_text=artifact_text,
                    patch_text=patch_text,
                )
            if structural_candidate:
                structural_review = "artifact review disabled"
                if self.artifact_review_required:
                    structural_review = toolkit.review_source_code(structural_candidate)
                    notes.append(self._make_note("bootstrap.structural_review", structural_review, limit=2200))
                if not self.artifact_review_required or not self._is_error_text(structural_review):
                    structural_ready = True
                    if request.analyzer == "csa":
                        structural_lsp = toolkit.lsp_validate_code(
                            code=structural_candidate,
                            check_level="quick",
                            file_name=Path(request.target_path).name,
                        )
                        notes.append(self._make_note("bootstrap.structural_lsp", structural_lsp, limit=2000))
                        structural_ready = not self._is_error_text(structural_lsp)
                    if structural_ready:
                        synthesized_patch = self._build_unified_diff(
                            file_name=Path(request.target_path).name,
                            original_text=artifact_text,
                            desired_text=structural_candidate,
                        )
                        if synthesized_patch:
                            apply_result = toolkit.apply_artifact_patch(
                                patch=synthesized_patch,
                                resulting_content=structural_candidate,
                            )
                            notes.append(self._make_note("bootstrap.structural_apply", apply_result, limit=2000))
                            if not self._is_error_text(apply_result):
                                updated_artifact = toolkit.read_artifact()
                                if not self._is_error_text(updated_artifact):
                                    return {
                                        "artifact_text": updated_artifact,
                                        "patch_text": patch_text,
                                        "context_notes": notes,
                                        "route": "validate",
                                        "final_message": "已应用基于 patch 机制的结构修复候选。",
                                    }
            return {
                "artifact_text": artifact_text,
                "patch_text": patch_text,
                "context_notes": notes,
                "route": "decide",
            }

        def decide(state: RefinementWorkflowState) -> RefinementWorkflowState:
            model_turns = int(state.get("model_turns", 0) or 0) + 1
            if model_turns > int(request.max_iterations or self.max_iterations):
                return {
                    "model_turns": model_turns - 1,
                    "route": "finish",
                    "error_message": f"达到最大精炼轮次 ({request.max_iterations})",
                    "final_message": "达到最大精炼轮次，仍未产出可采纳候选。",
                }

            prompt = self._render_decision_prompt(
                task_prompt=task_prompt,
                artifact_text=str(state.get("artifact_text", "") or ""),
                patch_text=str(state.get("patch_text", "") or ""),
                context_notes=list(state.get("context_notes", []) or []),
                iteration=model_turns,
                max_iterations=int(request.max_iterations or self.max_iterations),
            )
            self._emit_progress("decision_started", iteration=model_turns)
            messages = [
                SystemMessage(content=system_prompt),
                HumanMessage(content=prompt),
            ]
            response = self._invoke_decision_model(messages)
            raw_text = self._extract_raw_response_text(response)
            decision, parse_error = self._parse_decision(raw_text)
            if parse_error:
                raw_preview = raw_text[:2000]
                self._emit_progress(
                    "decision_parse_failed",
                    iteration=model_turns,
                    error=parse_error,
                    raw_preview=raw_preview,
                )
                return {
                    "model_turns": model_turns,
                    "route": "finish",
                    "error_message": parse_error,
                    "final_message": "模型未返回可解析的 refine 决策。",
                    "raw_decision_text": raw_preview,
                    "context_notes": list(state.get("context_notes", []) or [])
                    + [self._make_note("decision.parse_error", raw_preview or "空响应", limit=2000)],
                }

            summary = str(decision.get("summary", "") or "").strip()
            self._emit_progress(
                "decision_completed",
                iteration=model_turns,
                action=decision.get("action", ""),
                summary=summary,
            )
            return {
                "decision": decision,
                "model_turns": model_turns,
                "route": self._route_from_decision(decision),
                "final_message": summary or str(state.get("final_message", "") or ""),
                "raw_decision_text": raw_text[:2000],
            }

        def read_reference(state: RefinementWorkflowState) -> RefinementWorkflowState:
            decision = dict(state.get("decision", {}) or {})
            path = str(decision.get("path", "") or "").strip()
            if not path:
                return self._append_error_note(
                    state,
                    title="read_reference_file",
                    error_message="模型请求 read_reference_file，但未提供 path。",
                )
            content = toolkit.read_reference_file(path)
            return self._append_context_note(
                state,
                title=f"reference_file:{path}",
                body=content,
            )

        def list_reference(state: RefinementWorkflowState) -> RefinementWorkflowState:
            decision = dict(state.get("decision", {}) or {})
            path = str(decision.get("path", "") or "").strip()
            if not path:
                return self._append_error_note(
                    state,
                    title="list_reference_dir",
                    error_message="模型请求 list_reference_dir，但未提供 path。",
                )
            recursive = bool(decision.get("recursive", False))
            content = toolkit.list_reference_dir(path, recursive=recursive)
            return self._append_context_note(
                state,
                title=f"reference_dir:{path}",
                body=content,
            )

        def search_knowledge(state: RefinementWorkflowState) -> RefinementWorkflowState:
            decision = dict(state.get("decision", {}) or {})
            query = str(decision.get("query", "") or "").strip()
            if not query:
                return self._append_error_note(
                    state,
                    title="search_knowledge",
                    error_message="模型请求 search_knowledge，但未提供 query。",
                )
            content = toolkit.search_knowledge(query)
            return self._append_context_note(
                state,
                title=f"knowledge:{query}",
                body=content,
            )

        def apply_patch(state: RefinementWorkflowState) -> RefinementWorkflowState:
            decision = dict(state.get("decision", {}) or {})
            patch = str(decision.get("patch", "") or "").strip()
            resulting_content = str(decision.get("resulting_content", "") or "")
            if not patch:
                return self._append_error_note(
                    state,
                    title="apply_patch",
                    error_message="模型请求 apply_patch，但未提供 unified diff。",
                )

            notes = list(state.get("context_notes", []) or [])
            preflight_issues = self._preflight_candidate_issues(request, resulting_content)
            if preflight_issues:
                notes.append(
                    self._make_note(
                        "preflight_candidate_checks",
                        "ERROR: " + "\n".join(f"- {issue}" for issue in preflight_issues),
                        limit=2000,
                    )
                )
                return {
                    "context_notes": notes,
                    "route": "decide",
                }

            if resulting_content.strip():
                if request.analyzer == "csa":
                    preflight_lsp = toolkit.lsp_validate_code(
                        code=resulting_content,
                        check_level="quick",
                        file_name=Path(request.target_path).name,
                    )
                    notes.append(self._make_note("preflight_lsp_validate_resulting_content", preflight_lsp, limit=2000))
                    if self._is_error_text(preflight_lsp):
                        return {
                            "context_notes": notes,
                            "route": "decide",
                        }
                if self.artifact_review_required:
                    preflight_review = toolkit.review_source_code(resulting_content)
                    notes.append(self._make_note("preflight_review_resulting_content", preflight_review, limit=2200))
                    if self._is_error_text(preflight_review):
                        return {
                            "context_notes": notes,
                            "route": "decide",
                        }

            result = toolkit.apply_artifact_patch(patch=patch, resulting_content=resulting_content)
            notes.append(self._make_note("apply_patch", result, limit=2000))
            if self._is_error_text(result):
                original_text = str(state.get("artifact_text", "") or "")
                if self._is_incremental_repair(original_text, resulting_content):
                    synthesized_patch = self._build_unified_diff(
                        file_name=Path(request.target_path).name,
                        original_text=original_text,
                        desired_text=resulting_content,
                    )
                    if synthesized_patch:
                        fallback_result = toolkit.apply_artifact_patch(
                            patch=synthesized_patch,
                            resulting_content=resulting_content,
                        )
                        notes.append(self._make_note("apply_patch_fallback", fallback_result, limit=2000))
                        if not self._is_error_text(fallback_result):
                            artifact_text = toolkit.read_artifact()
                            if self._is_error_text(artifact_text):
                                return {
                                    "artifact_text": str(state.get("artifact_text", "") or ""),
                                    "context_notes": notes + [self._make_note("post_patch.read_artifact", artifact_text)],
                                    "route": "finish",
                                    "error_message": artifact_text.removeprefix("ERROR: ").strip(),
                                    "final_message": "补丁已落盘，但无法重新读取工作副本。",
                                }
                            return {
                                "artifact_text": artifact_text,
                                "context_notes": notes,
                                "patch_applied": True,
                                "route": "validate",
                            }
                else:
                    notes.append(
                        self._make_note(
                            "apply_patch_fallback_skipped",
                            "resulting_content rewrites too much of the artifact; refusing to synthesize a whole-file fallback diff.",
                            limit=1200,
                        )
                    )
                return {
                    "context_notes": notes,
                    "route": "decide",
                }

            artifact_text = toolkit.read_artifact()
            if self._is_error_text(artifact_text):
                return {
                    "artifact_text": str(state.get("artifact_text", "") or ""),
                    "context_notes": notes + [self._make_note("post_patch.read_artifact", artifact_text)],
                    "route": "finish",
                    "error_message": artifact_text.removeprefix("ERROR: ").strip(),
                    "final_message": "补丁已落盘，但无法重新读取工作副本。",
                }
            return {
                "artifact_text": artifact_text,
                "context_notes": notes,
                "patch_applied": True,
                "route": "validate",
            }

        def validate(state: RefinementWorkflowState) -> RefinementWorkflowState:
            notes = list(state.get("context_notes", []) or [])

            if request.analyzer == "csa":
                lsp = toolkit.lsp_validate_artifact(check_level="quick")
                notes.append(self._make_note("lsp_validate_artifact", lsp, limit=2000))
                if self._is_error_text(lsp):
                    return {
                        "context_notes": notes,
                        "route": "decide",
                    }

                compile_result = toolkit.compile_artifact()
                notes.append(self._make_note("compile_artifact", compile_result, limit=2200))
                if self._is_error_text(compile_result):
                    return {
                        "context_notes": notes,
                        "route": "decide",
                    }
            else:
                analyze_result = toolkit.analyze_artifact()
                notes.append(self._make_note("analyze_artifact", analyze_result, limit=2200))
                if self._is_error_text(analyze_result):
                    return {
                        "context_notes": notes,
                        "route": "decide",
                    }

            if self.artifact_review_required:
                review_result = toolkit.review_artifact()
                notes.append(self._make_note("review_artifact", review_result, limit=2200))
                if self._is_error_text(review_result):
                    return {
                        "context_notes": notes,
                        "route": "decide",
                    }

            return {
                "context_notes": notes,
                "route": "finish",
                "final_message": str(state.get("final_message", "") or "").strip()
                or (
                    "当前候选已通过本地验证与结构审查。"
                    if self.artifact_review_required
                    else "当前候选已通过本地验证。"
                ),
            }

        def finish(state: RefinementWorkflowState) -> RefinementWorkflowState:
            return {
                "route": "finish",
            }

        graph = StateGraph(RefinementWorkflowState)
        graph.add_node("bootstrap", bootstrap)
        graph.add_node("decide", decide)
        graph.add_node("read_reference", read_reference)
        graph.add_node("list_reference", list_reference)
        graph.add_node("search_knowledge", search_knowledge)
        graph.add_node("apply_patch", apply_patch)
        graph.add_node("validate", validate)
        graph.add_node("finish", finish)

        graph.add_edge(START, "bootstrap")
        graph.add_conditional_edges(
            "bootstrap",
            lambda state: str(state.get("route", "finish") or "finish"),
            {
                "decide": "decide",
                "validate": "validate",
                "finish": "finish",
            },
        )
        graph.add_conditional_edges(
            "decide",
            lambda state: str(state.get("route", "finish") or "finish"),
            {
                "read_reference": "read_reference",
                "list_reference": "list_reference",
                "search_knowledge": "search_knowledge",
                "apply_patch": "apply_patch",
                "finish": "finish",
            },
        )
        graph.add_conditional_edges(
            "read_reference",
            lambda state: str(state.get("route", "finish") or "finish"),
            {
                "decide": "decide",
                "finish": "finish",
            },
        )
        graph.add_conditional_edges(
            "list_reference",
            lambda state: str(state.get("route", "finish") or "finish"),
            {
                "decide": "decide",
                "finish": "finish",
            },
        )
        graph.add_conditional_edges(
            "search_knowledge",
            lambda state: str(state.get("route", "finish") or "finish"),
            {
                "decide": "decide",
                "finish": "finish",
            },
        )
        graph.add_conditional_edges(
            "apply_patch",
            lambda state: str(state.get("route", "finish") or "finish"),
            {
                "validate": "validate",
                "decide": "decide",
                "finish": "finish",
            },
        )
        graph.add_conditional_edges(
            "validate",
            lambda state: str(state.get("route", "finish") or "finish"),
            {
                "decide": "decide",
                "finish": "finish",
            },
        )
        graph.add_edge("finish", END)
        return graph.compile()

    def _finalize_result(
        self,
        tracker: RefinementTracker,
        final_state: Dict[str, Any],
        error_message: str = "",
    ) -> RefinementResult:
        request = tracker.request
        final_message = str(final_state.get("final_message", "") or "").strip()
        if not error_message:
            error_message = str(final_state.get("error_message", "") or "").strip()

        checker_code = ""
        target_path = Path(request.target_path)
        if target_path.exists():
            checker_code = target_path.read_text(encoding="utf-8")

        if request.analyzer == "csa":
            output_path = tracker.last_compile_output_path
            success = bool(output_path and Path(output_path).exists() and tracker.last_review_ok and not error_message)
        else:
            output_path = str(target_path)
            success = bool(target_path.exists() and tracker.last_codeql_ok and tracker.last_review_ok and not error_message)

        if not success and not error_message:
            if tracker.last_tool_error:
                error_message = tracker.last_tool_error
            elif not tracker.last_review_ok:
                error_message = "结构审查未通过"
            elif request.analyzer == "csa":
                error_message = "编译或本地审查未通过"
            else:
                error_message = "CodeQL 本地检查或审查未通过"

        result = RefinementResult(
            success=success,
            checker_name=request.checker_name or target_path.stem,
            checker_code=checker_code,
            output_path=output_path,
            iterations=int(final_state.get("model_turns", 0) or 0),
            compile_attempts=tracker.compile_attempts,
            error_message=error_message,
            final_message=final_message,
            history=list(tracker.history),
            metadata={
                "tool_history": list(tracker.history),
                "last_review": dict(tracker.last_review_metadata or {}),
                "last_codeql_ok": tracker.last_codeql_ok,
                "workflow": "langgraph_refine",
                "context_notes": list(final_state.get("context_notes", []) or []),
                "raw_decision_text": str(final_state.get("raw_decision_text", "") or ""),
            },
        )
        self._emit_progress(
            "run_completed",
            success=result.success,
            iterations=result.iterations,
            compile_attempts=result.compile_attempts,
            output_path=result.output_path,
            error_message=result.error_message,
            final_message=result.final_message,
        )
        return result

    def _render_system_prompt(self) -> str:
        return self.prompt_repository.render(
            "refine.agent.system",
            {
                "ANALYZER_NAME": self._analyzer_display_name(),
            },
            strict=True,
        )

    def _render_task_prompt(self, request: RefinementRequest) -> str:
        return self.prompt_repository.render(
            "refine.agent.task",
            {
                "ANALYZER_ID": request.analyzer,
                "WORK_DIR": request.work_dir,
                "TARGET_PATH": request.target_path,
                "SOURCE_PATH": request.source_path or request.target_path,
                "PATCH_PATH": request.patch_path,
                "VALIDATE_PATH": request.validate_path or "未提供",
                "EXTRA_CONTEXT": request.extra_context or "无额外上下文",
            },
            strict=True,
        )

    def _render_decision_prompt(
        self,
        task_prompt: str,
        artifact_text: str,
        patch_text: str,
        context_notes: List[str],
        iteration: int,
        max_iterations: int,
    ) -> str:
        return self.prompt_repository.render(
            "refine.agent.decide",
            {
                "TASK_PROMPT": task_prompt,
                "ITERATION": iteration,
                "MAX_ITERATIONS": max_iterations,
                "ARTIFACT_TEXT": artifact_text,
                "PATCH_TEXT": patch_text,
                "CONTEXT_NOTES": self._render_context_notes(context_notes),
            },
            strict=True,
        )

    def _bootstrap_reference_notes(
        self,
        request: RefinementRequest,
        toolkit: RefinementToolkit,
        patch_text: str,
    ) -> List[str]:
        notes: List[str] = []
        validate_root = str(request.validate_path or "").strip()
        if not validate_root:
            return notes

        for relative_path in self._extract_patch_target_paths(patch_text)[:2]:
            candidate = Path(validate_root) / relative_path
            if not candidate.exists() or not candidate.is_file():
                continue
            content = toolkit.read_reference_file(relative_path)
            notes.append(self._make_note(f"patch_target:{relative_path}", content, limit=2200))
        return notes

    def _extract_patch_target_paths(self, patch_text: str) -> List[str]:
        paths: List[str] = []
        for match in re.finditer(r"^\+\+\+\s+b/(?P<path>.+)$", patch_text or "", flags=re.MULTILINE):
            path = str(match.group("path") or "").strip()
            if path and path != "/dev/null" and path not in paths:
                paths.append(path)
        return paths

    def _append_context_note(
        self,
        state: RefinementWorkflowState,
        title: str,
        body: str,
    ) -> RefinementWorkflowState:
        notes = list(state.get("context_notes", []) or [])
        notes.append(self._make_note(title, body))
        return {
            "context_notes": notes,
            "route": "decide",
        }

    def _append_error_note(
        self,
        state: RefinementWorkflowState,
        title: str,
        error_message: str,
    ) -> RefinementWorkflowState:
        notes = list(state.get("context_notes", []) or [])
        notes.append(self._make_note(title, f"ERROR: {error_message}", limit=1600))
        return {
            "context_notes": notes,
            "route": "decide",
        }

    def _route_from_decision(self, decision: RefinementDecision) -> str:
        action = str(decision.get("action", "") or "").strip()
        mapping = {
            "apply_patch": "apply_patch",
            "read_reference_file": "read_reference",
            "list_reference_dir": "list_reference",
            "search_knowledge": "search_knowledge",
            "finish": "finish",
        }
        return mapping.get(action, "finish")

    def _parse_decision(self, raw_content: Any) -> tuple[RefinementDecision, str]:
        content = self._stringify_message_content(raw_content).strip()
        if not content:
            return {}, "模型返回了空决策。"

        parsed: Optional[Dict[str, Any]] = None
        for candidate in self._json_candidates(content):
            try:
                parsed = json.loads(candidate)
                break
            except Exception:
                try:
                    literal = ast.literal_eval(candidate)
                except Exception:
                    continue
                if isinstance(literal, dict):
                    parsed = literal
                    break

        if not isinstance(parsed, dict):
            return {}, "模型未返回可解析的 JSON 决策。"

        action = str(parsed.get("action", "") or "").strip()
        if action not in {"apply_patch", "read_reference_file", "list_reference_dir", "search_knowledge", "finish"}:
            return {}, f"模型返回了不支持的 refine action: {action or '空'}"

        decision: RefinementDecision = {
            "action": action,
            "summary": str(parsed.get("summary", "") or "").strip(),
            "path": str(parsed.get("path", "") or "").strip(),
            "recursive": bool(parsed.get("recursive", False)),
            "query": str(parsed.get("query", "") or "").strip(),
            "patch": str(parsed.get("patch", "") or ""),
            "resulting_content": str(parsed.get("resulting_content", "") or ""),
        }
        return decision, ""

    def _json_candidates(self, content: str) -> List[str]:
        candidates: List[str] = []
        stripped = content.strip()
        if stripped:
            candidates.append(stripped)

        fenced = re.findall(r"```(?:json)?\s*(\{[\s\S]*?\})\s*```", content, flags=re.IGNORECASE)
        candidates.extend(item.strip() for item in fenced if item.strip())

        start = content.find("{")
        end = content.rfind("}")
        if start != -1 and end != -1 and end > start:
            candidates.append(content[start:end + 1].strip())

        deduped: List[str] = []
        seen = set()
        for item in candidates:
            if item in seen:
                continue
            seen.add(item)
            deduped.append(item)
        return deduped

    def _build_unified_diff(
        self,
        file_name: str,
        original_text: str,
        desired_text: str,
    ) -> str:
        original = str(original_text or "")
        desired = str(desired_text or "")
        if not desired or original == desired:
            return ""

        diff = list(
            difflib.unified_diff(
                original.splitlines(),
                desired.splitlines(),
                fromfile=f"a/{file_name}",
                tofile=f"b/{file_name}",
                lineterm="",
            )
        )
        return "\n".join(diff).strip()

    def _is_incremental_repair(self, original_text: str, desired_text: str) -> bool:
        original = str(original_text or "")
        desired = str(desired_text or "")
        if not desired or original == desired:
            return False

        matcher = difflib.SequenceMatcher(a=original.splitlines(), b=desired.splitlines())
        changed = 0
        for opcode, a0, a1, b0, b1 in matcher.get_opcodes():
            if opcode in {"replace", "delete"}:
                changed += max(0, a1 - a0)
            if opcode in {"replace", "insert"}:
                changed += max(0, b1 - b0)

        original_lines = max(len(original.splitlines()), 1)
        return changed <= max(60, int(original_lines * 0.65))

    def _build_structural_candidate(
        self,
        request: RefinementRequest,
        artifact_text: str,
        patch_text: str,
    ) -> str:
        if request.analyzer == "codeql":
            return build_codeql_structural_candidate(
                artifact_text=artifact_text,
                patch_text=patch_text,
            )
        return build_csa_structural_candidate(
            artifact_text=artifact_text,
            patch_text=patch_text,
        )

    def _structural_candidate_enabled(
        self,
        request: RefinementRequest,
        artifact_text: str,
        patch_text: str,
    ) -> bool:
        refine_config = (self.config.get("refine", {}) or {})
        structural_config = (refine_config.get("structural_candidate", {}) or {})
        if structural_config.get("enabled", True) is False:
            return False

        allowed = structural_config.get("allowed_families", {}) or {}
        analyzer_allowlist = allowed.get(request.analyzer, []) if isinstance(allowed, dict) else allowed
        normalized_allowlist = {
            str(item).strip().lower()
            for item in (analyzer_allowlist or [])
            if str(item).strip()
        }
        if not normalized_allowlist:
            return True

        family = ""
        if request.analyzer == "codeql":
            family = infer_codeql_structural_family(artifact_text=artifact_text, patch_text=patch_text)
        else:
            family = infer_csa_structural_family(artifact_text=artifact_text, patch_text=patch_text)
        return str(family or "").strip().lower() in normalized_allowlist

    def _preflight_candidate_issues(
        self,
        request: RefinementRequest,
        resulting_content: str,
    ) -> List[str]:
        if request.analyzer != "csa":
            return []

        code = str(resulting_content or "")
        if not code.strip():
            return []

        issues: List[str] = []
        for pattern, message in _CSA_RESULTING_CONTENT_GUARDS:
            if pattern.search(code):
                issues.append(message)
        return issues[:4]

    def _invoke_decision_model(self, messages: List[Any]) -> Any:
        try:
            bound = self.model.bind(response_format={"type": "json_object"})
        except Exception:
            bound = None

        if bound is not None:
            try:
                return bound.invoke(messages)
            except Exception as exc:
                self._emit_progress("decision_bind_fallback", error=str(exc))

        return self.model.invoke(messages)

    def _extract_raw_response_text(self, response: Any) -> str:
        if response is None:
            return ""

        parsed = None
        if isinstance(response, dict):
            parsed = response.get("parsed")
            if isinstance(parsed, dict):
                try:
                    return json.dumps(parsed, ensure_ascii=False)
                except Exception:
                    return str(parsed)
            raw = response.get("raw")
            if raw is not None:
                return self._stringify_message_content(getattr(raw, "content", raw))

        content = getattr(response, "content", response)
        return self._stringify_message_content(content)

    def _stringify_message_content(self, content: Any) -> str:
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            parts: List[str] = []
            for item in content:
                if isinstance(item, str):
                    parts.append(item)
                elif isinstance(item, dict):
                    text = item.get("text")
                    if text:
                        parts.append(str(text))
            return "\n".join(parts)
        return str(content or "")

    def _render_context_notes(self, notes: List[str]) -> str:
        if not notes:
            return "无"

        rendered: List[str] = []
        total = 0
        for note in notes[-8:]:
            text = str(note or "").strip()
            if not text:
                continue
            if total >= 9000:
                break
            rendered.append(text)
            total += len(text)
        return "\n\n".join(rendered) if rendered else "无"

    def _make_note(self, title: str, body: str, limit: int = 1800) -> str:
        text = str(body or "").strip() or "空"
        if len(text) > limit:
            text = text[:limit] + "\n...[truncated]"
        return f"## {title}\n{text}"

    def _is_error_text(self, text: str) -> bool:
        return str(text or "").strip().startswith("ERROR:")

    def _emit_progress(self, event: str, **payload: Any):
        if self.progress_callback is None:
            return
        self.progress_callback({
            "event": event,
            "analyzer_name": self._analyzer_display_name(),
            **payload,
        })

    def _analyzer_display_name(self) -> str:
        return "CSA (Clang Static Analyzer)" if self.analyzer == "csa" else "CodeQL"
