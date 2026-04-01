"""
简化版 Generate Agent - 基于 LangGraph 的检测器生成工作流

工作流:
1. bootstrap -> 读取补丁
2. analyze_patch -> 分析补丁机制
3. search_knowledge -> RAG 检索
4. rag_check -> 判断 RAG 符合性
5. draft -> 生成首稿
6. validate -> 验证 (LSP/审查/编译或analyse)
7. repair_decide -> 修复决策
8. apply_patch -> 应用修复
9. finish
"""
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

from ..prompts import PromptRepository
from .models import GenerationRequest, GenerationResult
from .toolkit import GenerationToolkit, GenerationTracker


class GeneratePlan(TypedDict, total=False):
    summary: str
    checker_name: str
    knowledge_query: str
    vulnerability_type: str
    query_description: str
    pattern_description: str


class RagCheckResult(TypedDict, total=False):
    match: bool
    reason: str
    reuse_strategy: str


class GenerateDraft(TypedDict, total=False):
    summary: str
    checker_name: str
    content: str


class GenerateDecision(TypedDict, total=False):
    action: str
    summary: str
    edits: List[Dict[str, str]]


class GenerateWorkflowState(TypedDict, total=False):
    patch_text: str
    analysis_text: str
    analysis_metadata: Dict[str, Any]
    knowledge_text: str
    knowledge_metadata: Dict[str, Any]
    rag_match: bool
    rag_check_result: str
    checker_name: str
    artifact_path: str
    artifact_text: str
    plan: GeneratePlan
    rag_check: RagCheckResult
    decision: GenerateDecision
    model_turns: int
    route: str
    error_message: str
    final_message: str
    notes: List[str]
    latest_failure_title: str
    latest_failure_text: str
    latest_failure_lines: List[int]
    repeated_failure_count: int
    latest_patch_result: str
    raw_plan_text: str
    raw_draft_text: str
    raw_decision_text: str


class LangChainGenerateAgent:
    """简化的 Generate Agent"""

    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        tool_registry=None,
        analyzer: str = "csa",
        progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        llm_override: Any = None,
    ):
        from ..llm.langchain_builder import build_langchain_chat_model

        self.config = config or {}
        self.tool_registry = tool_registry
        self.analyzer = str(analyzer or "csa").strip().lower()
        self.progress_callback = progress_callback
        self.prompt_repository = PromptRepository(config=self.config)
        self.max_iterations = max(
            4,
            int(((self.config.get("agent", {}) or {}).get("max_iterations", 12) or 12)),
        )
        self.max_knowledge_search_calls = max(
            1,
            int(((self.config.get("agent", {}) or {}).get("generate_max_knowledge_search_calls", 2) or 2)),
        )
        gate_config = ((self.config.get("quality_gates", {}) or {}).get("artifact_review", {}) or {})
        self.artifact_review_required = bool(gate_config.get("enabled", True))
        self.model = (
            llm_override
            if llm_override is not None
            else build_langchain_chat_model(
                config=self.config,
                temperature_key="generate_temperature",
                default_temperature=0.15,
            )
        )

    def run(self, request: GenerationRequest) -> GenerationResult:
        tracker = GenerationTracker(request=request)
        toolkit = GenerationToolkit(
            tool_registry=self.tool_registry,
            request=request,
            tracker=tracker,
            analyzer_name=self._analyzer_display_name(),
            progress_callback=self.progress_callback,
            max_knowledge_search_calls=self.max_knowledge_search_calls,
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

        self._emit_progress("run_started", patch_path=request.patch_path, work_dir=request.work_dir)
        try:
            final_state = workflow.invoke(
                {
                    "patch_text": "",
                    "analysis_text": "",
                    "analysis_metadata": {},
                    "knowledge_text": "",
                    "knowledge_metadata": {},
                    "rag_match": False,
                    "rag_check_result": "",
                    "checker_name": "",
                    "artifact_path": "",
                    "artifact_text": "",
                    "plan": {},
                    "rag_check": {},
                    "decision": {},
                    "model_turns": 0,
                    "route": "bootstrap",
                    "error_message": "",
                    "final_message": "",
                    "notes": [],
                    "latest_failure_title": "",
                    "latest_failure_text": "",
                    "latest_failure_lines": [],
                    "repeated_failure_count": 0,
                    "latest_patch_result": "",
                    "raw_plan_text": "",
                    "raw_draft_text": "",
                    "raw_decision_text": "",
                },
                config={"recursion_limit": max(24, request.max_iterations * 8)},
            )
        except GraphRecursionError as exc:
            return self._finalize_result(
                tracker=tracker,
                final_state={},
                error_message=f"达到最大 generate 步数限制: {exc}",
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
        request: GenerationRequest,
        tracker: GenerationTracker,
        toolkit: GenerationToolkit,
        system_prompt: str,
        task_prompt: str,
    ):
        """构建简化的工作流"""

        def bootstrap(state: GenerateWorkflowState) -> GenerateWorkflowState:
            patch_result = toolkit.read_patch()
            if not patch_result.success:
                return {
                    "route": "finish",
                    "error_message": patch_result.error or "无法读取补丁内容",
                    "final_message": "无法读取补丁内容。",
                    "notes": [self._make_note("bootstrap.read_patch", patch_result.error or "")],
                }
            notes = list(state.get("notes", []) or [])
            if request.extra_context:
                notes.append(self._make_note("request.extra_context", request.extra_context, limit=2200))
            return {
                "patch_text": patch_result.output or "",
                "notes": notes,
                "route": "analyze_patch",
            }

        def analyze_patch(state: GenerateWorkflowState) -> GenerateWorkflowState:
            result = toolkit.analyze_patch()
            if not result.success:
                return {
                    "route": "finish",
                    "error_message": result.error or "补丁分析失败",
                    "final_message": "补丁分析失败。",
                    "notes": list(state.get("notes", []) or []) + [self._make_note("analyze_patch", result.error or "", limit=2200)],
                }
            notes = list(state.get("notes", []) or [])
            notes.append(self._make_note("analyze_patch", result.output or "", limit=2600))
            return {
                "analysis_text": result.output or "",
                "analysis_metadata": dict(result.metadata or {}),
                "notes": notes,
                "route": "plan",
            }

        def plan(state: GenerateWorkflowState) -> GenerateWorkflowState:
            model_turns = int(state.get("model_turns", 0) or 0) + 1
            if model_turns > int(request.max_iterations or self.max_iterations):
                return {
                    "route": "finish",
                    "model_turns": model_turns - 1,
                    "error_message": f"达到最大 generate 轮次 ({request.max_iterations})",
                    "final_message": "达到最大 generate 轮次。",
                }

            prompt = self._render_plan_prompt(
                task_prompt=task_prompt,
                patch_text=str(state.get("patch_text", "") or ""),
                analysis_text=str(state.get("analysis_text", "") or ""),
            )
            self._emit_progress("plan_started", iteration=model_turns)
            raw_text = self._invoke_json_prompt(system_prompt, prompt)
            parsed_plan, parse_error = self._parse_plan(raw_text)
            notes = list(state.get("notes", []) or [])
            if parse_error:
                notes.append(self._make_note("plan.parse_error", raw_text or parse_error, limit=1800))
                parsed_plan = self._fallback_plan(
                    analyzer=request.analyzer,
                    patch_text=str(state.get("patch_text", "") or ""),
                    analysis_metadata=state.get("analysis_metadata", {}) or {},
                )

            checker_name = self._sanitize_checker_name(
                str(parsed_plan.get("checker_name", "") or ""),
                default=self._default_checker_name(request.analyzer),
            )
            parsed_plan["checker_name"] = checker_name

            self._emit_progress(
                "plan_completed",
                iteration=model_turns,
                checker_name=checker_name,
                knowledge_query=parsed_plan.get("knowledge_query", ""),
            )
            return {
                "plan": parsed_plan,
                "checker_name": checker_name,
                "model_turns": model_turns,
                "raw_plan_text": raw_text[:2000],
                "final_message": str(parsed_plan.get("summary", "") or "").strip(),
                "notes": notes,
                "route": "search_knowledge",
            }

        def search_knowledge(state: GenerateWorkflowState) -> GenerateWorkflowState:
            plan_data = dict(state.get("plan", {}) or {})
            query = str(plan_data.get("knowledge_query", "") or "").strip()
            result = toolkit.search_knowledge(query=query, top_k=3)
            notes = list(state.get("notes", []) or [])
            if result.success:
                notes.append(self._make_note(f"search_knowledge:{query}", result.output or "", limit=2600))
                knowledge_text = result.output or ""
                knowledge_metadata = dict(result.metadata or {})
            else:
                notes.append(self._make_note(f"search_knowledge:{query}", result.error or "", limit=1800))
                knowledge_text = result.error or result.output or ""
                knowledge_metadata = {}

            return {
                "knowledge_text": knowledge_text,
                "knowledge_metadata": knowledge_metadata,
                "notes": notes,
                "route": "rag_check",
            }

        def rag_check(state: GenerateWorkflowState) -> GenerateWorkflowState:
            model_turns = int(state.get("model_turns", 0) or 0) + 1
            prompt = self._render_rag_check_prompt(
                patch_text=str(state.get("patch_text", "") or ""),
                analysis_text=str(state.get("analysis_text", "") or ""),
                knowledge_text=str(state.get("knowledge_text", "") or ""),
            )
            self._emit_progress("rag_check_started", iteration=model_turns)
            raw_text = self._invoke_json_prompt(system_prompt, prompt)
            rag_result, parse_error = self._parse_rag_check(raw_text)
            notes = list(state.get("notes", []) or [])
            if parse_error:
                notes.append(self._make_note("rag_check.parse_error", raw_text or parse_error, limit=1800))
                rag_result = {"match": False, "reason": parse_error, "reuse_strategy": "自己生成"}

            notes.append(self._make_note("rag_check", json.dumps(rag_result, ensure_ascii=False), limit=1000))
            self._emit_progress(
                "rag_check_completed",
                iteration=model_turns,
                match=rag_result.get("match", False),
                reason=rag_result.get("reason", ""),
            )
            return {
                "model_turns": model_turns,
                "rag_match": rag_result.get("match", False),
                "rag_check_result": json.dumps(rag_result, ensure_ascii=False),
                "rag_check": rag_result,
                "notes": notes,
                "route": "draft",
            }

        def draft(state: GenerateWorkflowState) -> GenerateWorkflowState:
            model_turns = int(state.get("model_turns", 0) or 0) + 1
            if model_turns > int(request.max_iterations or self.max_iterations):
                return {
                    "route": "finish",
                    "model_turns": model_turns - 1,
                    "error_message": f"达到最大 generate 轮次 ({request.max_iterations})",
                    "final_message": "达到最大 generate 轮次。",
                }

            checker_name = self._sanitize_checker_name(
                str(state.get("checker_name", "") or ""),
                default=self._default_checker_name(request.analyzer),
            )
            artifact_path = self._artifact_path(request, checker_name)
            prompt = self._render_draft_prompt(
                task_prompt=task_prompt,
                request=request,
                checker_name=checker_name,
                artifact_path=artifact_path,
                patch_text=str(state.get("patch_text", "") or ""),
                analysis_text=str(state.get("analysis_text", "") or ""),
                knowledge_text=str(state.get("knowledge_text", "") or ""),
                rag_match=state.get("rag_match", False),
                rag_check_result=str(state.get("rag_check_result", "") or ""),
                notes=list(state.get("notes", []) or []),
            )
            self._emit_progress("draft_started", iteration=model_turns, checker_name=checker_name)
            raw_text = self._invoke_json_prompt(system_prompt, prompt)
            draft_payload, parse_error = self._parse_draft(raw_text)
            notes = list(state.get("notes", []) or [])
            if parse_error:
                return {
                    "route": "finish",
                    "model_turns": model_turns,
                    "raw_draft_text": raw_text[:2000],
                    "error_message": parse_error,
                    "final_message": "模型未返回可解析的首稿。",
                    "notes": notes + [self._make_note("draft.parse_error", raw_text or parse_error, limit=1800)],
                }

            content = str(draft_payload.get("content", "") or "")
            if not content.strip():
                return {
                    "route": "finish",
                    "model_turns": model_turns,
                    "raw_draft_text": raw_text[:2000],
                    "error_message": "模型未提供首稿内容。",
                    "final_message": "模型未提供首稿内容。",
                    "notes": notes,
                }

            checker_name = self._sanitize_checker_name(
                str(draft_payload.get("checker_name", "") or checker_name),
                default=checker_name,
            )
            artifact_path = self._artifact_path(request, checker_name)

            # CodeQL 需要 generate_codeql_query 包装
            if request.analyzer != "csa":
                plan_data = dict(state.get("plan", {}) or {})
                generated_query = toolkit.generate_codeql_query(
                    query_name=checker_name,
                    vulnerability_type=str(plan_data.get("vulnerability_type", "") or "unknown"),
                    description=str(plan_data.get("query_description", "") or checker_name),
                    pattern_description=str(plan_data.get("pattern_description", "") or ""),
                    custom_query=content,
                )
                notes.append(self._make_note("draft.generate_codeql_query", generated_query.output or generated_query.error or "", limit=2200))
                if not generated_query.success:
                    return {
                        "route": "draft",
                        "model_turns": model_turns,
                        "raw_draft_text": raw_text[:2000],
                        "checker_name": checker_name,
                        "notes": notes,
                    }
                content = str((generated_query.metadata or {}).get("query_code", "") or content)

            write_result = toolkit.write_artifact(artifact_path, content)
            if not write_result.success:
                return {
                    "route": "finish",
                    "model_turns": model_turns,
                    "raw_draft_text": raw_text[:2000],
                    "error_message": write_result.error or "首稿写入失败",
                    "final_message": "首稿写入失败。",
                    "notes": notes + [self._make_note("draft.write_artifact", write_result.error or "", limit=1800)],
                }

            resolved_artifact_path = str((write_result.metadata or {}).get("path", "") or artifact_path)
            self._emit_progress(
                "draft_completed",
                iteration=model_turns,
                checker_name=checker_name,
                artifact_path=resolved_artifact_path,
            )
            return {
                "route": "validate",
                "model_turns": model_turns,
                "checker_name": checker_name,
                "artifact_path": resolved_artifact_path,
                "artifact_text": content,
                "raw_draft_text": raw_text[:2000],
                "final_message": str(draft_payload.get("summary", "") or "").strip(),
                "notes": notes,
            }

        def validate(state: GenerateWorkflowState) -> GenerateWorkflowState:
            notes = list(state.get("notes", []) or [])
            artifact_path = str(state.get("artifact_path", "") or "").strip()
            checker_name = self._sanitize_checker_name(
                str(state.get("checker_name", "") or ""),
                default=self._default_checker_name(request.analyzer),
            )
            if not artifact_path:
                return {
                    "route": "finish",
                    "error_message": "缺少当前产物路径。",
                    "final_message": "缺少当前产物路径。",
                    "notes": notes,
                }

            read_result = toolkit.read_artifact(artifact_path)
            if not read_result.success:
                return {
                    "route": "finish",
                    "error_message": read_result.error or "无法读取当前产物",
                    "final_message": "无法读取当前产物。",
                    "notes": notes + [self._make_note("validate.read_artifact", read_result.error or "", limit=1800)],
                }

            artifact_text = read_result.output or ""

            # CSA: LSP -> Review -> Compile
            if request.analyzer == "csa":
                lsp_result = toolkit.lsp_validate_code(
                    code=artifact_text,
                    file_name=Path(artifact_path).name,
                    check_level="quick",
                )
                notes.append(self._make_note("validate.lsp_validate", lsp_result.output or lsp_result.error or "", limit=2200))
                if not lsp_result.success:
                    failure_update = self._failure_state_update(
                        state,
                        title="validate.lsp_validate",
                        text=lsp_result.output or lsp_result.error or "",
                    )
                    return {
                        "route": "repair_decide",
                        "artifact_text": artifact_text,
                        "notes": notes,
                        **failure_update,
                    }

                if self.artifact_review_required:
                    review_result = toolkit.review_artifact(
                        artifact_path=artifact_path,
                        analyzer=request.analyzer,
                        source_code=artifact_text,
                        review_mode="generate",
                    )
                    notes.append(self._make_note("validate.review_artifact", review_result.output or review_result.error or "", limit=2200))
                    if not review_result.success:
                        failure_update = self._failure_state_update(
                            state,
                            title="validate.review_artifact",
                            text=review_result.output or review_result.error or "",
                        )
                        return {
                            "route": "repair_decide",
                            "artifact_text": artifact_text,
                            "notes": notes,
                            **failure_update,
                        }

                compile_result = toolkit.compile_artifact(
                    artifact_path=artifact_path,
                    checker_name=checker_name,
                )
                notes.append(self._make_note("validate.compile_artifact", compile_result.output or compile_result.error or "", limit=2200))
                if not compile_result.success:
                    failure_update = self._failure_state_update(
                        state,
                        title="validate.compile_artifact",
                        text=compile_result.output or compile_result.error or "",
                    )
                    return {
                        "route": "repair_decide",
                        "artifact_text": artifact_text,
                        "notes": notes,
                        **failure_update,
                    }
            else:
                # CodeQL: Review -> Analyze
                if self.artifact_review_required:
                    review_result = toolkit.review_artifact(
                        artifact_path=artifact_path,
                        analyzer=request.analyzer,
                        source_code=artifact_text,
                        review_mode="generate",
                    )
                    notes.append(self._make_note("validate.review_artifact", review_result.output or review_result.error or "", limit=2200))
                    if not review_result.success:
                        failure_update = self._failure_state_update(
                            state,
                            title="validate.review_artifact",
                            text=review_result.output or review_result.error or "",
                        )
                        return {
                            "route": "repair_decide",
                            "artifact_text": artifact_text,
                            "notes": notes,
                            **failure_update,
                        }

                analyze_result = toolkit.analyze_artifact(artifact_path=artifact_path)
                notes.append(self._make_note("validate.codeql_analyze", analyze_result.output or analyze_result.error or "", limit=2200))
                if not analyze_result.success:
                    failure_update = self._failure_state_update(
                        state,
                        title="validate.codeql_analyze",
                        text=analyze_result.output or analyze_result.error or "",
                    )
                    return {
                        "route": "repair_decide",
                        "artifact_text": artifact_text,
                        "notes": notes,
                        **failure_update,
                    }

            return {
                "route": "finish",
                "artifact_text": artifact_text,
                "notes": notes,
                "final_message": str(state.get("final_message", "") or "").strip() or "当前候选已通过本地验证。",
            }

        def repair_decide(state: GenerateWorkflowState) -> GenerateWorkflowState:
            model_turns = int(state.get("model_turns", 0) or 0) + 1
            repeated_failure_count = int(state.get("repeated_failure_count", 0) or 0)

            # 检测重复失败循环：同一错误重复3次以上，终止
            if repeated_failure_count >= 3:
                return {
                    "route": "finish",
                    "model_turns": model_turns - 1,
                    "error_message": f"检测到重复修复失败 ({repeated_failure_count} 次)，终止修复循环。",
                    "final_message": "修复无法收敛，请检查生成的代码或增加 API 知识。",
                }

            if model_turns > int(request.max_iterations or self.max_iterations):
                return {
                    "route": "finish",
                    "model_turns": model_turns - 1,
                    "error_message": f"达到最大 generate 轮次 ({request.max_iterations})",
                    "final_message": "达到最大 generate 轮次，仍未通过本地验证。",
                }

            prompt = self._render_repair_prompt(
                task_prompt=task_prompt,
                request=request,
                checker_name=str(state.get("checker_name", "") or ""),
                artifact_path=str(state.get("artifact_path", "") or ""),
                artifact_text=str(state.get("artifact_text", "") or ""),
                patch_text=str(state.get("patch_text", "") or ""),
                latest_failure_title=str(state.get("latest_failure_title", "") or ""),
                latest_failure_text=str(state.get("latest_failure_text", "") or ""),
            )
            self._emit_progress("repair_decision_started", iteration=model_turns)
            raw_text = self._invoke_json_prompt(system_prompt, prompt)
            decision, parse_error = self._parse_decision(raw_text)
            if parse_error:
                return {
                    "route": "finish",
                    "model_turns": model_turns,
                    "raw_decision_text": raw_text[:2000],
                    "error_message": parse_error,
                    "final_message": "模型未返回可解析的修复决策。",
                    "notes": list(state.get("notes", []) or []) + [self._make_note("repair.parse_error", raw_text or parse_error, limit=1800)],
                }

            self._emit_progress(
                "repair_decision_completed",
                iteration=model_turns,
                action=decision.get("action", ""),
                summary=decision.get("summary", ""),
            )
            return {
                "route": self._route_from_decision(decision),
                "model_turns": model_turns,
                "decision": decision,
                "raw_decision_text": raw_text[:2000],
                "final_message": str(decision.get("summary", "") or "").strip(),
            }

        def apply_patch(state: GenerateWorkflowState) -> GenerateWorkflowState:
            decision = dict(state.get("decision", {}) or {})
            edits = list(decision.get("edits", []) or [])
            artifact_path = str(state.get("artifact_path", "") or "").strip()
            if not edits:
                return {
                    "route": "finish",
                    "error_message": "模型未提供修复 edits。",
                    "final_message": "模型未提供修复 edits。",
                }
            if not artifact_path:
                return {
                    "route": "finish",
                    "error_message": "缺少当前产物路径。",
                    "final_message": "缺少当前产物路径。",
                }

            notes = list(state.get("notes", []) or [])
            synthesized = self._build_patch_from_exact_edits(
                file_name=Path(artifact_path).name,
                original_text=str(state.get("artifact_text", "") or ""),
                edits=edits,
            )
            if synthesized["error"]:
                notes.append(self._make_note("repair.exact_edits", str(synthesized["error"]), limit=1800))
                return {
                    "route": "repair_decide",
                    "notes": notes,
                    "latest_patch_result": str(synthesized["error"]),
                }

            patch = str(synthesized["patch"] or "").strip()
            resulting_content = str(synthesized["resulting_content"] or "")

            # CSA: preflight LSP
            if request.analyzer == "csa" and resulting_content.strip():
                lsp_result = toolkit.lsp_validate_code(
                    code=resulting_content,
                    file_name=Path(artifact_path).name,
                    check_level="quick",
                )
                notes.append(self._make_note("repair.preflight_lsp", lsp_result.output or lsp_result.error or "", limit=2200))
                if not lsp_result.success:
                    return {
                        "route": "repair_decide",
                        "notes": notes,
                    }

            write_result = toolkit.write_artifact(
                path=artifact_path,
                content=resulting_content,
            )
            notes.append(self._make_note("repair.write_artifact", write_result.output or write_result.error or "", limit=2200))

            if not write_result.success:
                return {
                    "route": "repair_decide",
                    "notes": notes,
                    "latest_patch_result": write_result.output or write_result.error or "",
                }
            return {
                "route": "validate",
                "artifact_text": resulting_content,
                "notes": notes,
                "latest_patch_result": "edits applied",
            }

        def finish(state: GenerateWorkflowState) -> GenerateWorkflowState:
            return {"route": "finish"}

        # 构建图
        graph = StateGraph(GenerateWorkflowState)
        graph.add_node("bootstrap", bootstrap)
        graph.add_node("analyze_patch", analyze_patch)
        graph.add_node("plan", plan)
        graph.add_node("search_knowledge", search_knowledge)
        graph.add_node("rag_check", rag_check)
        graph.add_node("draft", draft)
        graph.add_node("validate", validate)
        graph.add_node("repair_decide", repair_decide)
        graph.add_node("apply_patch", apply_patch)
        graph.add_node("finish", finish)

        graph.add_edge(START, "bootstrap")
        graph.add_conditional_edges(
            "bootstrap",
            lambda state: str(state.get("route", "finish") or "finish"),
            {"analyze_patch": "analyze_patch", "finish": "finish"},
        )
        graph.add_conditional_edges(
            "analyze_patch",
            lambda state: str(state.get("route", "finish") or "finish"),
            {"plan": "plan", "finish": "finish"},
        )
        graph.add_conditional_edges(
            "plan",
            lambda state: str(state.get("route", "finish") or "finish"),
            {"search_knowledge": "search_knowledge", "finish": "finish"},
        )
        graph.add_conditional_edges(
            "search_knowledge",
            lambda state: str(state.get("route", "finish") or "finish"),
            {"rag_check": "rag_check", "finish": "finish"},
        )
        graph.add_conditional_edges(
            "rag_check",
            lambda state: str(state.get("route", "finish") or "finish"),
            {"draft": "draft", "finish": "finish"},
        )
        graph.add_conditional_edges(
            "draft",
            lambda state: str(state.get("route", "finish") or "finish"),
            {"draft": "draft", "validate": "validate", "finish": "finish"},
        )
        graph.add_conditional_edges(
            "validate",
            lambda state: str(state.get("route", "finish") or "finish"),
            {"repair_decide": "repair_decide", "finish": "finish"},
        )
        graph.add_conditional_edges(
            "repair_decide",
            lambda state: str(state.get("route", "finish") or "finish"),
            {"apply_patch": "apply_patch", "finish": "finish"},
        )
        graph.add_conditional_edges(
            "apply_patch",
            lambda state: str(state.get("route", "finish") or "finish"),
            {"validate": "validate", "repair_decide": "repair_decide", "finish": "finish"},
        )
        graph.add_edge("finish", END)
        return graph.compile()

    # ===== 辅助方法 =====

    def _finalize_result(
        self,
        tracker: GenerationTracker,
        final_state: Dict[str, Any],
        error_message: str = "",
    ) -> GenerationResult:
        request = tracker.request
        artifact_path = str(final_state.get("artifact_path", "") or "").strip()
        checker_name = self._sanitize_checker_name(
            str(final_state.get("checker_name", "") or ""),
            default=Path(artifact_path).stem if artifact_path else self._default_checker_name(request.analyzer),
        )
        final_message = str(final_state.get("final_message", "") or "").strip()
        if not error_message:
            error_message = str(final_state.get("error_message", "") or "").strip()

        checker_code = ""
        if artifact_path and Path(artifact_path).exists():
            checker_code = Path(artifact_path).read_text(encoding="utf-8")

        if request.analyzer == "csa":
            output_path = tracker.last_compile_output_path
            success = bool(
                output_path
                and Path(output_path).exists()
                and tracker.last_lsp_ok
                and (tracker.last_review_ok or not self.artifact_review_required)
                and not error_message
            )
        else:
            output_path = artifact_path
            success = bool(
                output_path
                and Path(output_path).exists()
                and tracker.last_codeql_ok
                and (tracker.last_review_ok or not self.artifact_review_required)
                and not error_message
            )

        if not success and not error_message:
            if tracker.last_tool_error:
                error_message = tracker.last_tool_error
            elif request.analyzer == "csa":
                error_message = "CSA 首稿或修复候选未通过本地验证。"
            else:
                error_message = "CodeQL 首稿或修复候选未通过本地验证。"

        result = GenerationResult(
            success=success,
            checker_name=checker_name,
            checker_code=checker_code,
            output_path=output_path,
            iterations=int(final_state.get("model_turns", 0) or 0),
            compile_attempts=tracker.compile_attempts,
            error_message=error_message,
            final_message=final_message,
            history=list(tracker.history),
            metadata={
                "tool_history": list(tracker.history),
                "workflow": "langgraph_generate_v2",
                "notes": list(final_state.get("notes", []) or []),
                "plan": dict(final_state.get("plan", {}) or {}),
                "rag_match": bool(final_state.get("rag_match", False)),
                "rag_check_result": str(final_state.get("rag_check_result", "") or ""),
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
            "generate.agent.system",
            {
                "ANALYZER_NAME": self._analyzer_display_name(),
                "MAX_KNOWLEDGE_SEARCH_CALLS": self.max_knowledge_search_calls,
            },
            strict=True,
        )

    def _render_task_prompt(self, request: GenerationRequest) -> str:
        return self.prompt_repository.render(
            "generate.agent.task",
            {
                "ANALYZER_ID": request.analyzer,
                "ANALYZER_NAME": self._analyzer_display_name(),
                "WORK_DIR": request.work_dir,
                "PATCH_PATH": request.patch_path,
                "VALIDATE_PATH": request.validate_path or "未提供",
                "MAX_ITERATIONS": int(request.max_iterations or self.max_iterations),
                "ANALYZER_POLICY": self._render_analyzer_policy(request.analyzer),
                "EXTRA_CONTEXT": request.extra_context or "无额外上下文",
            },
            strict=True,
        )

    def _render_plan_prompt(self, task_prompt: str, patch_text: str, analysis_text: str) -> str:
        return self.prompt_repository.render(
            "generate.agent.plan",
            {
                "TASK_PROMPT": task_prompt,
                "PATCH_TEXT": patch_text,
                "ANALYSIS_TEXT": analysis_text,
            },
            strict=True,
        )

    def _render_rag_check_prompt(self, patch_text: str, analysis_text: str, knowledge_text: str) -> str:
        return self.prompt_repository.render(
            "generate.agent.rag_check",
            {
                "PATCH_TEXT": patch_text,
                "ANALYSIS_TEXT": analysis_text,
                "KNOWLEDGE_TEXT": knowledge_text or "无检索结果",
            },
            strict=True,
        )

    def _render_draft_prompt(
        self,
        task_prompt: str,
        request: GenerationRequest,
        checker_name: str,
        artifact_path: str,
        patch_text: str,
        analysis_text: str,
        knowledge_text: str,
        rag_match: bool,
        rag_check_result: str,
        notes: List[str],
    ) -> str:
        return self.prompt_repository.render(
            "generate.agent.draft",
            {
                "TASK_PROMPT": task_prompt,
                "CHECKER_NAME": checker_name,
                "ARTIFACT_PATH": artifact_path,
                "PATCH_TEXT": patch_text,
                "ANALYSIS_TEXT": analysis_text,
                "KNOWLEDGE_TEXT": knowledge_text or "无检索结果",
                "RAG_MATCH": "符合" if rag_match else "不符合",
                "RAG_CHECK_RESULT": rag_check_result,
                "REFERENCE_SKELETON": self._render_reference_skeleton(request.analyzer),
                "NOTES": self._render_notes(notes),
            },
            strict=True,
        )

    def _render_repair_prompt(
        self,
        task_prompt: str,
        request: GenerationRequest,
        checker_name: str,
        artifact_path: str,
        artifact_text: str,
        patch_text: str,
        latest_failure_title: str,
        latest_failure_text: str,
    ) -> str:
        return self.prompt_repository.render(
            "generate.agent.repair",
            {
                "TASK_PROMPT": task_prompt,
                "CHECKER_NAME": checker_name,
                "ARTIFACT_PATH": artifact_path,
                "ARTIFACT_TEXT": artifact_text,
                "PATCH_TEXT": patch_text,
                "LATEST_FAILURE_TITLE": latest_failure_title or "无",
                "LATEST_FAILURE_TEXT": latest_failure_text or "无",
            },
            strict=True,
        )

    def _render_analyzer_policy(self, analyzer: str) -> str:
        prompt_id = "generate.agent.analyzer.csa" if str(analyzer or "").strip().lower() == "csa" else "generate.agent.analyzer.codeql"
        return self.prompt_repository.render(prompt_id, {}, strict=True)

    def _render_reference_skeleton(self, analyzer: str) -> str:
        prompt_id = "generate.agent.reference.csa" if str(analyzer or "").strip().lower() == "csa" else "generate.agent.reference.codeql"
        return self.prompt_repository.render(prompt_id, {}, strict=True)

    def _invoke_json_prompt(self, system_prompt: str, prompt: str) -> str:
        messages = [
            SystemMessage(content=system_prompt),
            HumanMessage(content=prompt),
        ]
        model = self.model
        bound = None
        if hasattr(model, "bind"):
            try:
                bound = model.bind(response_format={"type": "json_object"})
            except Exception:
                bound = None
        if bound is not None and hasattr(bound, "invoke"):
            try:
                return self._extract_raw_response_text(bound.invoke(messages))
            except Exception as exc:
                self._emit_progress("model_bind_fallback", error=str(exc))

        if hasattr(model, "invoke"):
            return self._extract_raw_response_text(model.invoke(messages))

        if hasattr(model, "generate"):
            prompt_text = f"{system_prompt}\n\n{prompt}"
            return str(model.generate(prompt_text) or "")

        raise TypeError("generate agent 的 llm_override 不支持 bind/invoke/generate 接口。")

    def _extract_raw_response_text(self, response: Any) -> str:
        if response is None:
            return ""
        if isinstance(response, str):
            return response
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

    def _parse_plan(self, raw_content: Any) -> tuple[GeneratePlan, str]:
        parsed, error = self._parse_json_dict(raw_content)
        if error:
            return {}, error
        plan: GeneratePlan = {
            "summary": str(parsed.get("summary", "") or "").strip(),
            "checker_name": str(parsed.get("checker_name", "") or "").strip(),
            "knowledge_query": str(parsed.get("knowledge_query", "") or "").strip(),
            "vulnerability_type": str(parsed.get("vulnerability_type", "") or "unknown").strip(),
            "query_description": str(parsed.get("query_description", "") or "").strip(),
            "pattern_description": str(parsed.get("pattern_description", "") or "").strip(),
        }
        return plan, ""

    def _parse_rag_check(self, raw_content: Any) -> tuple[RagCheckResult, str]:
        parsed, error = self._parse_json_dict(raw_content)
        if error:
            return {}, error
        result: RagCheckResult = {
            "match": bool(parsed.get("match", False)),
            "reason": str(parsed.get("reason", "") or "").strip(),
            "reuse_strategy": str(parsed.get("reuse_strategy", "") or "").strip(),
        }
        return result, ""

    def _parse_draft(self, raw_content: Any) -> tuple[GenerateDraft, str]:
        parsed, error = self._parse_json_dict(raw_content)
        if error:
            return {}, error
        draft: GenerateDraft = {
            "summary": str(parsed.get("summary", "") or "").strip(),
            "checker_name": str(parsed.get("checker_name", "") or "").strip(),
            "content": str(parsed.get("content", "") or ""),
        }
        return draft, ""

    def _parse_decision(self, raw_content: Any) -> tuple[GenerateDecision, str]:
        parsed, error = self._parse_json_dict(raw_content)
        if error:
            return {}, error

        action = str(parsed.get("action", "") or "").strip()
        if action not in {"apply_patch", "finish"}:
            return {}, f"模型返回了不支持的 action: {action or '空'}"

        edits: List[Dict[str, str]] = []
        raw_edits = parsed.get("edits", [])
        if isinstance(raw_edits, list):
            for item in raw_edits[:6]:
                if not isinstance(item, dict):
                    continue
                old_snippet = str(item.get("old_snippet", "") or "")
                new_snippet = str(item.get("new_snippet", "") or "")
                if not old_snippet:
                    continue
                edits.append({
                    "old_snippet": old_snippet,
                    "new_snippet": new_snippet,
                })

        if action == "apply_patch" and not edits:
            return {}, "模型返回了 apply_patch，但没有提供任何有效 edits。"

        decision: GenerateDecision = {
            "action": action,
            "summary": str(parsed.get("summary", "") or "").strip(),
            "edits": edits,
        }
        return decision, ""

    def _parse_json_dict(self, raw_content: Any) -> tuple[Dict[str, Any], str]:
        content = self._stringify_message_content(raw_content).strip()
        if not content:
            return {}, "模型返回了空响应。"

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
            return {}, "模型未返回可解析的 JSON。"
        return parsed, ""

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

    def _fallback_plan(
        self,
        analyzer: str,
        patch_text: str,
        analysis_metadata: Dict[str, Any],
    ) -> GeneratePlan:
        checker_name = self._default_checker_name(analyzer)
        return {
            "summary": "使用补丁分析结果进入 generate 流程。",
            "checker_name": checker_name,
            "knowledge_query": f"{analyzer} {self._guess_patch_topic(patch_text)} skeleton",
            "vulnerability_type": self._guess_vulnerability_type(analysis_metadata, patch_text),
            "query_description": checker_name,
            "pattern_description": "",
        }

    def _guess_patch_topic(self, patch_text: str) -> str:
        lowered = str(patch_text or "").lower()
        if any(token in lowered for token in ("strcpy", "strcat", "memcpy", "sprintf")):
            return "buffer overflow"
        if any(token in lowered for token in ("free(", "delete", "dangling")):
            return "use after free"
        if "null" in lowered:
            return "null dereference"
        return "patch guided"

    def _guess_vulnerability_type(self, analysis_metadata: Dict[str, Any], patch_text: str) -> str:
        patterns = analysis_metadata.get("vulnerability_patterns", []) if isinstance(analysis_metadata, dict) else []
        if isinstance(patterns, list):
            for item in patterns:
                if isinstance(item, dict):
                    candidate = str(item.get("pattern_type") or item.get("type") or "").strip()
                    if candidate:
                        return candidate
        topic = self._guess_patch_topic(patch_text)
        if "buffer" in topic:
            return "buffer_overflow"
        if "free" in topic:
            return "use_after_free"
        if "null" in topic:
            return "null_dereference"
        return "unknown"

    def _default_checker_name(self, analyzer: str) -> str:
        return "PatchGuidedChecker" if str(analyzer or "").strip().lower() == "csa" else "PatchGuidedQuery"

    def _sanitize_checker_name(self, raw_name: str, default: str) -> str:
        token = re.sub(r"[^A-Za-z0-9_]", "", str(raw_name or "").strip())
        if not token:
            token = str(default or "").strip() or "PatchGuidedChecker"
        if token[0].isdigit():
            token = f"A{token}"
        return token

    def _artifact_path(self, request: GenerationRequest, checker_name: str) -> str:
        suffix = ".cpp" if request.analyzer == "csa" else ".ql"
        return str(Path(request.work_dir).expanduser().resolve() / f"{checker_name}{suffix}")

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

    def _build_patch_from_exact_edits(
        self,
        file_name: str,
        original_text: str,
        edits: List[Dict[str, str]],
    ) -> Dict[str, str]:
        original = str(original_text or "")
        updated = original
        if not edits:
            return {"patch": "", "resulting_content": "", "error": "未提供任何 edits。"}

        for index, edit in enumerate(edits, start=1):
            old = str((edit or {}).get("old_snippet", "") or "")
            new = str((edit or {}).get("new_snippet", "") or "")
            if not old:
                return {"patch": "", "resulting_content": "", "error": f"第 {index} 个 edit 的 old_snippet 为空。"}

            occurrences = updated.count(old)
            if occurrences == 0:
                return {"patch": "", "resulting_content": "", "error": f"第 {index} 个 edit 的 old_snippet 未命中。"}
            if occurrences > 1:
                return {"patch": "", "resulting_content": "", "error": f"第 {index} 个 edit 的 old_snippet 命中 {occurrences} 次，不唯一。"}
            updated = updated.replace(old, new, 1)

        patch = self._build_unified_diff(file_name=file_name, original_text=original, desired_text=updated)
        if not patch.strip():
            return {"patch": "", "resulting_content": "", "error": "edits 未产生实际修改。"}
        return {"patch": patch, "resulting_content": updated, "error": ""}

    def _failure_state_update(
        self,
        state: GenerateWorkflowState,
        title: str,
        text: str,
    ) -> Dict[str, Any]:
        failure_text = str(text or "").strip()
        failure_lines = self._extract_failure_lines(failure_text)
        previous_key = str(state.get("latest_failure_title", "") or "")
        repeated_failure_count = int(state.get("repeated_failure_count", 0) or 0)
        if title and title == previous_key:
            repeated_failure_count += 1
        else:
            repeated_failure_count = 1 if title else 0

        return {
            "latest_failure_title": title,
            "latest_failure_text": failure_text,
            "latest_failure_lines": failure_lines,
            "repeated_failure_count": repeated_failure_count,
        }

    def _extract_failure_lines(self, text: str) -> List[int]:
        patterns = [
            re.compile(r":(?P<line>\d+):\d+:\s*(?:error|warning|note):", flags=re.IGNORECASE),
            re.compile(r"\[line\s+(?P<line>\d+)\]", flags=re.IGNORECASE),
        ]
        lines: List[int] = []
        seen = set()
        for pattern in patterns:
            for match in pattern.finditer(str(text or "")):
                line = int(match.group("line"))
                if line > 0 and line not in seen:
                    seen.add(line)
                    lines.append(line)
        return lines[:8]

    def _route_from_decision(self, decision: GenerateDecision) -> str:
        action = str(decision.get("action", "") or "").strip()
        return "apply_patch" if action == "apply_patch" else "finish"

    def _render_notes(self, notes: List[str]) -> str:
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