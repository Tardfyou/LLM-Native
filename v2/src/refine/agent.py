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
from ..llm.usage import extract_usage_from_response, merge_usages
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
    edits: List[Dict[str, str]]
    evidence_types: List[str]


class RefinementRepairDecision(TypedDict, total=False):
    action: str
    summary: str
    edits: List[Dict[str, str]]


class RefinementWorkflowState(TypedDict, total=False):
    artifact_text: str
    patch_text: str
    context_notes: List[str]
    decision: RefinementDecision
    repair_decision: RefinementRepairDecision
    model_turns: int
    patch_applied: bool
    route: str
    error_message: str
    final_message: str
    raw_decision_text: str
    raw_repair_text: str
    failure_type: str
    collected_evidence: Dict[str, Any]
    latest_failure_title: str
    latest_failure_text: str
    latest_failure_lines: List[int]
    repeated_failure_count: int
    failure_bucket_counts: Dict[str, int]
    minimal_recovery_attempts: Dict[str, int]
    baseline_review_passed: bool
    accepted_without_changes: bool
    model_requested_stop: bool
    validation_rounds: int
    last_decision_action: str
    last_repair_action: str


class LangChainRefinementAgent:
    _PHASE_TEMPERATURES = {
        "decide": ("refine_decision_temperature", 0.08),
        "repair": ("refine_repair_temperature", 0.04),
    }

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
        # 大轮迭代次数（默认2轮）
        refine_config = self.config.get("refine", {}) or {}
        self.max_rounds = max(1, min(int(refine_config.get("max_rounds", 2)), 3))
        gate_config = ((self.config.get("quality_gates", {}) or {}).get("artifact_review", {}) or {})
        self.artifact_review_required = bool(gate_config.get("enabled", True))
        self._phase_temperatures = {
            phase: self._resolve_phase_temperature(temperature_key, default_temperature)
            for phase, (temperature_key, default_temperature) in self._PHASE_TEMPERATURES.items()
        }
        if llm_override is not None:
            self._phase_models = {phase: llm_override for phase in self._PHASE_TEMPERATURES}
        elif self._has_llm_config():
            self._phase_models = {
                phase: build_langchain_chat_model(
                    config=self.config,
                    temperature_override=self._phase_temperatures[phase],
                    default_temperature=default_temperature,
                )
                for phase, (_, default_temperature) in self._PHASE_TEMPERATURES.items()
            }
        else:
            self._phase_models = {}
        self.model = self._phase_models.get("decide")
        self._current_llm_usage: List[Dict[str, Any]] = []

    def run(self, request: RefinementRequest) -> RefinementResult:
        self._current_llm_usage = []
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
                    "repair_decision": {},
                    "model_turns": 0,
                    "patch_applied": False,
                    "route": "bootstrap",
                    "error_message": "",
                    "final_message": "",
                    "raw_decision_text": "",
                    "raw_repair_text": "",
                    "failure_type": "",
                    "collected_evidence": {},
                    "latest_failure_title": "",
                    "latest_failure_text": "",
                    "latest_failure_lines": [],
                    "repeated_failure_count": 0,
                    "failure_bucket_counts": {},
                    "minimal_recovery_attempts": {},
                    "baseline_review_passed": False,
                    "accepted_without_changes": False,
                    "model_requested_stop": False,
                    "validation_rounds": 0,
                    "last_decision_action": "",
                    "last_repair_action": "",
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
            if str(request.baseline_validation_summary or "").strip():
                notes.append(self._make_note(
                    "baseline.validation_summary",
                    request.baseline_validation_summary,
                    limit=2200,
                ))
            notes.extend(self._bootstrap_reference_notes(request, toolkit, patch_text))

            baseline_review_passed = False
            if self.artifact_review_required:
                baseline_review = toolkit.review_artifact()
                notes.append(self._make_note("bootstrap.review_artifact", baseline_review, limit=2200))
                baseline_review_passed = not self._is_error_text(baseline_review)

            structural_candidate = ""
            if not baseline_review_passed and self._structural_candidate_enabled(request, artifact_text, patch_text):
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
                                        "baseline_review_passed": baseline_review_passed,
                                        "patch_applied": True,
                                        "route": "validate",
                                        "final_message": "已应用基于 patch 机制的结构修复候选。",
                                    }
            return {
                "artifact_text": artifact_text,
                "patch_text": patch_text,
                "context_notes": notes,
                "baseline_review_passed": baseline_review_passed,
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
            raw_text = self._invoke_json_prompt(system_prompt, prompt, phase="decide")
            decision, parse_error = self._parse_decision(raw_text)
            if parse_error:
                raw_preview = raw_text[:2000]
                self._emit_progress(
                    "decision_parse_failed",
                    iteration=model_turns,
                    error=parse_error,
                    raw_preview=raw_preview,
                )
                if request.analyzer == "codeql":
                    recovery_key = self._minimal_recovery_key("decide", "parse")
                    recovery_attempts = dict(state.get("minimal_recovery_attempts", {}) or {})
                    if self._can_attempt_minimal_recovery(state, recovery_key):
                        recovery_attempts = self._consume_minimal_recovery_attempt(state, recovery_key)
                        recovery_decision, recovery_raw, recovery_error = self._attempt_codeql_minimal_recovery(
                            system_prompt=system_prompt,
                            base_prompt=prompt,
                            phase="decide",
                            failure_title="decision.parse_error",
                            failure_text=raw_preview or parse_error,
                            repair_mode=False,
                        )
                        notes = list(state.get("context_notes", []) or [])
                        notes.append(self._make_note("decision.parse_error", raw_preview or "空响应", limit=2000))
                        if recovery_error:
                            notes.append(self._make_note("decision.minimal_recovery_failed", recovery_raw or recovery_error, limit=2000))
                            return {
                                "model_turns": model_turns,
                                "route": "decide",
                                "failure_type": "decision_parse_error",
                                "minimal_recovery_attempts": recovery_attempts,
                                "context_notes": notes,
                                "raw_decision_text": raw_preview,
                                **self._failure_state_update(
                                    state,
                                    title="decision.parse_error",
                                    text=parse_error,
                                    failure_type="decision_parse_error",
                                ),
                            }

                        summary = str(recovery_decision.get("summary", "") or "").strip()
                        notes.append(self._make_note("decision.minimal_recovery", recovery_raw, limit=2000))
                        return {
                            "decision": recovery_decision,
                            "model_turns": model_turns,
                            "route": self._route_from_decision(recovery_decision),
                            "final_message": summary or str(state.get("final_message", "") or ""),
                            "raw_decision_text": recovery_raw[:2000],
                            "accepted_without_changes": False,
                            "model_requested_stop": str(recovery_decision.get("action", "") or "").strip() == "finish",
                            "last_decision_action": str(recovery_decision.get("action", "") or "").strip(),
                            "minimal_recovery_attempts": recovery_attempts,
                            "context_notes": notes,
                        }
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
            accepted_without_changes = (
                str(decision.get("action", "") or "").strip() == "finish"
                and not bool(state.get("patch_applied", False))
                and bool(state.get("baseline_review_passed", False))
            )
            return {
                "decision": decision,
                "model_turns": model_turns,
                "route": self._route_from_decision(decision),
                "final_message": summary or str(state.get("final_message", "") or ""),
                "raw_decision_text": raw_text[:2000],
                "accepted_without_changes": accepted_without_changes,
                "model_requested_stop": str(decision.get("action", "") or "").strip() == "finish",
                "last_decision_action": str(decision.get("action", "") or "").strip(),
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

        def request_evidence(state: RefinementWorkflowState) -> RefinementWorkflowState:
            from ..evidence.evidence_tools import EvidenceQueryTools
            from ..core.evidence_schema import EvidenceBundle
            from ..evidence.normalizer import EvidenceNormalizer

            decision = dict(state.get("decision", {}) or {})
            evidence_types = list(decision.get("evidence_types", []) or [])

            if not evidence_types:
                return self._append_error_note(
                    state,
                    title="request_evidence",
                    error_message="模型请求 request_evidence，但未提供 evidence_types。",
                )

            raw_bundle = request.evidence_bundle_raw if isinstance(request.evidence_bundle_raw, dict) else {}
            bundle = EvidenceNormalizer.from_raw_bundle(raw_bundle)
            if not getattr(bundle, "records", None):
                bundle = EvidenceBundle(records=[])

            # 获取项目根目录
            project_root = None
            if request.evidence_dir:
                project_root = Path(request.evidence_dir).expanduser().resolve()
            elif request.validate_path:
                validate_path = Path(request.validate_path)
                project_root = validate_path if validate_path.is_dir() else validate_path.parent

            # 使用证据工具获取请求的证据
            tools = EvidenceQueryTools(bundle, project_root)
            collected = tools.get_evidence_by_types(evidence_types)

            # 格式化证据内容
            evidence_notes: List[str] = []
            for ev_type, ev_data in collected.items():
                if ev_data:
                    formatted = self._format_evidence(ev_type, ev_data)
                    evidence_notes.append(self._make_note(f"evidence:{ev_type}", formatted, limit=3000))

            notes = list(state.get("context_notes", []) or []) + evidence_notes
            return {
                "context_notes": notes,
                "collected_evidence": collected,
                "route": "decide",
            }

        def apply_patch(state: RefinementWorkflowState) -> RefinementWorkflowState:
            decision = dict(state.get("decision", {}) or {})
            edits = list(decision.get("edits", []) or [])
            notes = list(state.get("context_notes", []) or [])
            original_text = str(state.get("artifact_text", "") or "")
            recovery_attempts = dict(state.get("minimal_recovery_attempts", {}) or {})
            recovery_key = self._minimal_recovery_key("decide", "apply")

            if not edits:
                return self._append_error_note(
                    state,
                    title="apply_patch",
                    error_message="模型请求 apply_patch，但未提供唯一 edits。",
                )
            synthesized = self._build_patch_from_exact_edits(
                file_name=Path(request.target_path).name,
                original_text=original_text,
                edits=edits,
            )
            if synthesized["error"]:
                notes.append(self._make_note("decide.exact_edits", str(synthesized["error"]), limit=1800))
                if request.analyzer == "codeql" and self._can_attempt_minimal_recovery(state, recovery_key):
                    recovery_attempts = self._consume_minimal_recovery_attempt(state, recovery_key)
                    recovery_decision, recovery_raw, recovery_error = self._attempt_codeql_minimal_recovery(
                        system_prompt=system_prompt,
                        base_prompt=self._render_decision_prompt(
                            task_prompt=task_prompt,
                            artifact_text=original_text,
                            patch_text=str(state.get("patch_text", "") or ""),
                            context_notes=notes,
                            iteration=int(state.get("model_turns", 0) or 0) or 1,
                            max_iterations=int(request.max_iterations or self.max_iterations),
                        ),
                        phase="decide",
                        failure_title="apply_patch.exact_edits",
                        failure_text=str(synthesized["error"] or ""),
                        repair_mode=False,
                    )
                    notes.append(self._make_note("apply_patch.minimal_recovery", recovery_raw or recovery_error, limit=1800))
                    if not recovery_error and str(recovery_decision.get("action", "") or "").strip() == "apply_patch":
                        edits = list(recovery_decision.get("edits", []) or [])
                        synthesized = self._build_patch_from_exact_edits(
                            file_name=Path(request.target_path).name,
                            original_text=original_text,
                            edits=edits,
                        )
                    elif not recovery_error and str(recovery_decision.get("action", "") or "").strip() == "validate":
                        return {
                            "context_notes": notes,
                            "route": "validate",
                            "minimal_recovery_attempts": recovery_attempts,
                        }
                if synthesized["error"]:
                    return {
                        "context_notes": notes,
                        "route": "decide",
                        "failure_type": "apply_patch_failure",
                        "minimal_recovery_attempts": recovery_attempts,
                        **self._failure_state_update(
                            state,
                            title="apply_patch.exact_edits",
                            text=str(synthesized["error"] or ""),
                            failure_type="apply_patch_failure",
                        ),
                    }
            patch = str(synthesized["patch"] or "").strip()
            resulting_content = str(synthesized["resulting_content"] or "")

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
                                "accepted_without_changes": False,
                                "route": "validate" if request.analyzer == "codeql" else "decide",
                                "minimal_recovery_attempts": recovery_attempts,
                            }
                else:
                    notes.append(
                        self._make_note(
                            "apply_patch_fallback_skipped",
                            "resulting_content rewrites too much of the artifact; refusing to synthesize a whole-file fallback diff.",
                            limit=1200,
                        )
                    )
                if request.analyzer == "codeql" and self._can_attempt_minimal_recovery(state, recovery_key):
                    recovery_attempts = self._consume_minimal_recovery_attempt(state, recovery_key)
                    recovery_decision, recovery_raw, recovery_error = self._attempt_codeql_minimal_recovery(
                        system_prompt=system_prompt,
                        base_prompt=self._render_decision_prompt(
                            task_prompt=task_prompt,
                            artifact_text=original_text,
                            patch_text=str(state.get("patch_text", "") or ""),
                            context_notes=notes,
                            iteration=int(state.get("model_turns", 0) or 0) or 1,
                            max_iterations=int(request.max_iterations or self.max_iterations),
                        ),
                        phase="decide",
                        failure_title="apply_patch.protocol_failure",
                        failure_text=result,
                        repair_mode=False,
                    )
                    notes.append(self._make_note("apply_patch.minimal_recovery", recovery_raw or recovery_error, limit=2000))
                    if not recovery_error and str(recovery_decision.get("action", "") or "").strip() == "apply_patch":
                        recovered_synth = self._build_patch_from_exact_edits(
                            file_name=Path(request.target_path).name,
                            original_text=original_text,
                            edits=list(recovery_decision.get("edits", []) or []),
                        )
                        if not recovered_synth["error"]:
                            recovered_result = toolkit.apply_artifact_patch(
                                patch=str(recovered_synth["patch"] or "").strip(),
                                resulting_content=str(recovered_synth["resulting_content"] or ""),
                            )
                            notes.append(self._make_note("apply_patch.minimal_recovery_apply", recovered_result, limit=2000))
                            if not self._is_error_text(recovered_result):
                                artifact_text = toolkit.read_artifact()
                                if not self._is_error_text(artifact_text):
                                    return {
                                        "artifact_text": artifact_text,
                                        "context_notes": notes,
                                        "patch_applied": True,
                                        "accepted_without_changes": False,
                                        "route": "validate" if request.analyzer == "codeql" else "decide",
                                        "minimal_recovery_attempts": recovery_attempts,
                                    }
                    elif not recovery_error and str(recovery_decision.get("action", "") or "").strip() == "validate":
                        return {
                            "context_notes": notes,
                            "route": "validate",
                            "minimal_recovery_attempts": recovery_attempts,
                        }
                return {
                    "context_notes": notes,
                    "route": "decide",
                    "failure_type": "apply_patch_failure",
                    "minimal_recovery_attempts": recovery_attempts,
                    **self._failure_state_update(
                        state,
                        title="apply_patch",
                        text=result,
                        failure_type="apply_patch_failure",
                    ),
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
                "accepted_without_changes": False,
                "route": "validate" if request.analyzer == "codeql" else "decide",
                "minimal_recovery_attempts": recovery_attempts,
            }

        def repair_decide(state: RefinementWorkflowState) -> RefinementWorkflowState:
            model_turns = int(state.get("model_turns", 0) or 0) + 1
            repeated_failure_count = int(state.get("repeated_failure_count", 0) or 0)
            current_failure_type = str(state.get("failure_type", "") or "")
            current_bucket = self._failure_bucket_for(
                current_failure_type,
                title=str(state.get("latest_failure_title", "") or ""),
                text=str(state.get("latest_failure_text", "") or ""),
            )
            failure_bucket_counts = dict(state.get("failure_bucket_counts", {}) or {})
            current_bucket_failures = int(failure_bucket_counts.get(current_bucket, 0) or 0)

            if current_bucket_failures >= self._failure_bucket_limit(current_bucket):
                return {
                    "route": "finish",
                    "model_turns": model_turns - 1,
                    "error_message": (
                        f"检测到 {current_bucket or 'unknown'} 类修复失败累计 {current_bucket_failures} 次，"
                        "终止当前精炼修复循环。"
                    ),
                    "final_message": "修复无法收敛，请检查当前 artifact 与失败信息。",
                }

            if model_turns > int(request.max_iterations or self.max_iterations):
                return {
                    "route": "finish",
                    "model_turns": model_turns - 1,
                    "error_message": f"达到最大精炼轮次 ({request.max_iterations})",
                    "final_message": "达到最大精炼轮次，仍未通过本地验证。",
                }

            prompt = self._render_repair_prompt(
                task_prompt=task_prompt,
                artifact_path=request.target_path,
                artifact_text=str(state.get("artifact_text", "") or ""),
                latest_failure_title=str(state.get("latest_failure_title", "") or ""),
                latest_failure_text=str(state.get("latest_failure_text", "") or ""),
                latest_failure_lines=list(state.get("latest_failure_lines", []) or []),
            )
            self._emit_progress("repair_decision_started", iteration=model_turns)
            raw_text = self._invoke_json_prompt(system_prompt, prompt, phase="repair")
            decision, parse_error = self._parse_repair_decision(raw_text)
            if parse_error:
                raw_preview = raw_text[:2000]
                if request.analyzer == "codeql":
                    recovery_key = self._minimal_recovery_key("repair", "parse")
                    recovery_attempts = dict(state.get("minimal_recovery_attempts", {}) or {})
                    if self._can_attempt_minimal_recovery(state, recovery_key):
                        recovery_attempts = self._consume_minimal_recovery_attempt(state, recovery_key)
                        recovery_decision, recovery_raw, recovery_error = self._attempt_codeql_minimal_recovery(
                            system_prompt=system_prompt,
                            base_prompt=prompt,
                            phase="repair",
                            failure_title="repair.parse_error",
                            failure_text=raw_preview or parse_error,
                            repair_mode=True,
                        )
                        notes = list(state.get("context_notes", []) or [])
                        notes.append(self._make_note("repair.parse_error", raw_preview or parse_error, limit=1800))
                        if recovery_error:
                            notes.append(self._make_note("repair.minimal_recovery_failed", recovery_raw or recovery_error, limit=1800))
                            return {
                                "route": "repair_decide",
                                "model_turns": model_turns,
                                "minimal_recovery_attempts": recovery_attempts,
                                "context_notes": notes,
                                "failure_type": "repair_parse_error",
                                "raw_repair_text": raw_preview,
                                **self._failure_state_update(
                                    state,
                                    title="repair.parse_error",
                                    text=parse_error,
                                    failure_type="repair_parse_error",
                                ),
                            }

                        summary = str(recovery_decision.get("summary", "") or "").strip()
                        notes.append(self._make_note("repair.minimal_recovery", recovery_raw, limit=1800))
                        return {
                            "repair_decision": recovery_decision,
                            "model_turns": model_turns,
                            "route": self._route_from_repair_decision(recovery_decision),
                            "final_message": summary or str(state.get("final_message", "") or ""),
                            "raw_repair_text": recovery_raw[:2000],
                            "model_requested_stop": str(recovery_decision.get("action", "") or "").strip() == "finish",
                            "last_repair_action": str(recovery_decision.get("action", "") or "").strip(),
                            "minimal_recovery_attempts": recovery_attempts,
                            "context_notes": notes,
                        }
                return {
                    "route": "finish",
                    "model_turns": model_turns,
                    "raw_repair_text": raw_preview,
                    "error_message": parse_error,
                    "final_message": "模型未返回可解析的 refine 修复决策。",
                    "context_notes": list(state.get("context_notes", []) or [])
                    + [self._make_note("repair.parse_error", raw_preview or parse_error, limit=1800)],
                }

            summary = str(decision.get("summary", "") or "").strip()
            self._emit_progress(
                "repair_decision_completed",
                iteration=model_turns,
                action=decision.get("action", ""),
                summary=summary,
            )
            return {
                "repair_decision": decision,
                "model_turns": model_turns,
                "route": self._route_from_repair_decision(decision),
                "final_message": summary or str(state.get("final_message", "") or ""),
                "raw_repair_text": raw_text[:2000],
                "model_requested_stop": str(decision.get("action", "") or "").strip() == "finish",
                "last_repair_action": str(decision.get("action", "") or "").strip(),
            }

        def apply_repair(state: RefinementWorkflowState) -> RefinementWorkflowState:
            decision = dict(state.get("repair_decision", {}) or {})
            edits = list(decision.get("edits", []) or [])
            if not edits:
                return {
                    "route": "finish",
                    "error_message": "模型未提供 refine repair edits。",
                    "final_message": "模型未提供 refine repair edits。",
                }

            notes = list(state.get("context_notes", []) or [])
            recovery_attempts = dict(state.get("minimal_recovery_attempts", {}) or {})
            recovery_key = self._minimal_recovery_key("repair", "apply")
            synthesized = self._build_patch_from_exact_edits(
                file_name=Path(request.target_path).name,
                original_text=str(state.get("artifact_text", "") or ""),
                edits=edits,
            )
            if synthesized["error"]:
                notes.append(self._make_note("repair.exact_edits", str(synthesized["error"]), limit=1800))
                if request.analyzer == "codeql" and self._can_attempt_minimal_recovery(state, recovery_key):
                    recovery_attempts = self._consume_minimal_recovery_attempt(state, recovery_key)
                    recovery_decision, recovery_raw, recovery_error = self._attempt_codeql_minimal_recovery(
                        system_prompt=system_prompt,
                        base_prompt=self._render_repair_prompt(
                            task_prompt=task_prompt,
                            artifact_path=request.target_path,
                            artifact_text=str(state.get("artifact_text", "") or ""),
                            latest_failure_title="repair.exact_edits",
                            latest_failure_text=str(synthesized["error"] or ""),
                            latest_failure_lines=list(state.get("latest_failure_lines", []) or []),
                        ),
                        phase="repair",
                        failure_title="repair.exact_edits",
                        failure_text=str(synthesized["error"] or ""),
                        repair_mode=True,
                    )
                    notes.append(self._make_note("repair.minimal_recovery", recovery_raw or recovery_error, limit=1800))
                    if not recovery_error and str(recovery_decision.get("action", "") or "").strip() == "apply_patch":
                        synthesized = self._build_patch_from_exact_edits(
                            file_name=Path(request.target_path).name,
                            original_text=str(state.get("artifact_text", "") or ""),
                            edits=list(recovery_decision.get("edits", []) or []),
                        )
                if synthesized["error"]:
                    return {
                        "route": "repair_decide",
                        "context_notes": notes,
                        "failure_type": "repair_apply_patch_failure",
                        "minimal_recovery_attempts": recovery_attempts,
                        **self._failure_state_update(
                            state,
                            title="repair.exact_edits",
                            text=str(synthesized["error"] or ""),
                            failure_type="repair_apply_patch_failure",
                        ),
                    }

            patch = str(synthesized["patch"] or "").strip()
            resulting_content = str(synthesized["resulting_content"] or "")
            preflight_issues = self._preflight_candidate_issues(request, resulting_content)
            if preflight_issues:
                notes.append(
                    self._make_note(
                        "repair.preflight_candidate_checks",
                        "ERROR: " + "\n".join(f"- {issue}" for issue in preflight_issues),
                        limit=2000,
                    )
                )
                return {
                    "route": "repair_decide",
                    "context_notes": notes,
                }

            if request.analyzer == "csa" and resulting_content.strip():
                preflight_lsp = toolkit.lsp_validate_code(
                    code=resulting_content,
                    check_level="quick",
                    file_name=Path(request.target_path).name,
                )
                notes.append(self._make_note("repair.preflight_lsp", preflight_lsp, limit=2000))
                if self._is_error_text(preflight_lsp):
                    return {
                        "route": "repair_decide",
                        "context_notes": notes,
                    }

            result = toolkit.apply_artifact_patch(patch=patch, resulting_content=resulting_content)
            notes.append(self._make_note("repair.apply_patch", result, limit=2000))
            if self._is_error_text(result):
                if request.analyzer == "codeql" and self._can_attempt_minimal_recovery(state, recovery_key):
                    recovery_attempts = self._consume_minimal_recovery_attempt(state, recovery_key)
                    recovery_decision, recovery_raw, recovery_error = self._attempt_codeql_minimal_recovery(
                        system_prompt=system_prompt,
                        base_prompt=self._render_repair_prompt(
                            task_prompt=task_prompt,
                            artifact_path=request.target_path,
                            artifact_text=str(state.get("artifact_text", "") or ""),
                            latest_failure_title="repair.apply_patch",
                            latest_failure_text=result,
                            latest_failure_lines=list(state.get("latest_failure_lines", []) or []),
                        ),
                        phase="repair",
                        failure_title="repair.apply_patch",
                        failure_text=result,
                        repair_mode=True,
                    )
                    notes.append(self._make_note("repair.minimal_recovery", recovery_raw or recovery_error, limit=1800))
                    if not recovery_error and str(recovery_decision.get("action", "") or "").strip() == "apply_patch":
                        recovered_synth = self._build_patch_from_exact_edits(
                            file_name=Path(request.target_path).name,
                            original_text=str(state.get("artifact_text", "") or ""),
                            edits=list(recovery_decision.get("edits", []) or []),
                        )
                        if not recovered_synth["error"]:
                            recovered_result = toolkit.apply_artifact_patch(
                                patch=str(recovered_synth["patch"] or "").strip(),
                                resulting_content=str(recovered_synth["resulting_content"] or ""),
                            )
                            notes.append(self._make_note("repair.minimal_recovery_apply", recovered_result, limit=1800))
                            if not self._is_error_text(recovered_result):
                                artifact_text = toolkit.read_artifact()
                                if not self._is_error_text(artifact_text):
                                    return {
                                        "artifact_text": artifact_text,
                                        "context_notes": notes,
                                        "patch_applied": True,
                                        "accepted_without_changes": False,
                                        "route": "validate",
                                        "minimal_recovery_attempts": recovery_attempts,
                                    }
                return {
                    "route": "repair_decide",
                    "context_notes": notes,
                    "failure_type": "repair_apply_patch_failure",
                    "minimal_recovery_attempts": recovery_attempts,
                    **self._failure_state_update(
                        state,
                        title="repair.apply_patch",
                        text=result,
                        failure_type="repair_apply_patch_failure",
                    ),
                }

            artifact_text = toolkit.read_artifact()
            if self._is_error_text(artifact_text):
                return {
                    "artifact_text": str(state.get("artifact_text", "") or ""),
                    "context_notes": notes + [self._make_note("repair.post_patch.read_artifact", artifact_text)],
                    "route": "finish",
                    "error_message": artifact_text.removeprefix("ERROR: ").strip(),
                    "final_message": "修复补丁已落盘，但无法重新读取工作副本。",
                }
            return {
                "artifact_text": artifact_text,
                "context_notes": notes,
                "patch_applied": True,
                "accepted_without_changes": False,
                "route": "validate",
                "minimal_recovery_attempts": recovery_attempts,
            }

        def validate(state: RefinementWorkflowState) -> RefinementWorkflowState:
            notes = list(state.get("context_notes", []) or [])

            if request.analyzer == "csa":
                lsp = toolkit.lsp_validate_artifact(check_level="quick")
                notes.append(self._make_note("validate.lsp_validate_artifact", lsp, limit=2000))
                if self._is_error_text(lsp):
                    failure_update = self._failure_state_update(
                        state,
                        title="validate.lsp_validate_artifact",
                        text=lsp,
                        failure_type="syntax_error",
                    )
                    return {
                        "context_notes": notes,
                        "route": "repair_decide",
                        "failure_type": "syntax_error",
                        **failure_update,
                    }

                if self.artifact_review_required:
                    review_result = toolkit.review_artifact()
                    notes.append(self._make_note("validate.review_artifact", review_result, limit=2200))
                    if self._is_error_text(review_result):
                        failure_update = self._failure_state_update(
                            state,
                            title="validate.review_artifact",
                            text=review_result,
                            failure_type="review_failure",
                        )
                        return {
                            "context_notes": notes,
                            "route": "repair_decide",
                            "failure_type": "review_failure",
                            **failure_update,
                        }

                compile_result = toolkit.compile_artifact()
                notes.append(self._make_note("validate.compile_artifact", compile_result, limit=2200))
                if self._is_error_text(compile_result):
                    failure_update = self._failure_state_update(
                        state,
                        title="validate.compile_artifact",
                        text=compile_result,
                        failure_type="compile_failure",
                    )
                    return {
                        "context_notes": notes,
                        "route": "repair_decide",
                        "failure_type": "compile_failure",
                        **failure_update,
                    }

                if toolkit.has_tool("semantic_validate"):
                    semantic_result = toolkit.semantic_validate_artifact()
                    notes.append(self._make_note("validate.semantic_validate_artifact", semantic_result, limit=2400))
                    if self._is_error_text(semantic_result):
                        failure_update = self._failure_state_update(
                            state,
                            title="validate.semantic_validate_artifact",
                            text=semantic_result,
                            failure_type="semantic_validation_failure",
                        )
                        return {
                            "context_notes": notes,
                            "route": "repair_decide",
                            "failure_type": "semantic_validation_failure",
                            **failure_update,
                        }
                else:
                    semantic_result = "ERROR: 未注册 semantic_validate，无法执行 CSA 功能验证。"
                    notes.append(self._make_note("validate.semantic_validate_artifact", semantic_result, limit=1200))
                    failure_update = self._failure_state_update(
                        state,
                        title="validate.semantic_validate_artifact",
                        text=semantic_result,
                        failure_type="semantic_validation_failure",
                    )
                    return {
                        "context_notes": notes,
                        "route": "finish",
                        "error_message": "未注册 semantic_validate，无法完成 CSA 功能验证。",
                        "final_message": "CSA 已通过 LSP、审查和编译前置门，但缺少功能验证工具。",
                        "failure_type": "semantic_validation_failure",
                        **failure_update,
                    }
            else:
                if self.artifact_review_required:
                    review_result = toolkit.review_artifact()
                    notes.append(self._make_note("validate.review_artifact", review_result, limit=2200))
                    if self._is_error_text(review_result):
                        failure_update = self._failure_state_update(
                            state,
                            title="validate.review_artifact",
                            text=review_result,
                            failure_type="review_failure",
                        )
                        return {
                            "context_notes": notes,
                            "route": "repair_decide",
                            "failure_type": "review_failure",
                            **failure_update,
                        }

                analyze_result = toolkit.analyze_artifact()
                notes.append(self._make_note("validate.analyze_artifact", analyze_result, limit=2200))
                if self._is_error_text(analyze_result):
                    failure_update = self._failure_state_update(
                        state,
                        title="validate.analyze_artifact",
                        text=analyze_result,
                        failure_type="analyze_failure",
                    )
                    return {
                        "context_notes": notes,
                        "route": "repair_decide",
                        "failure_type": "analyze_failure",
                        **failure_update,
                    }

            validation_rounds = int(state.get("validation_rounds", 0) or 0) + 1
            final_message = str(state.get("final_message", "") or "").strip() or (
                "当前候选已通过本地验证与结构审查。"
                if self.artifact_review_required
                else "当前候选已通过本地验证。"
            )
            if validation_rounds < self.max_rounds:
                notes.append(self._make_note(
                    f"validation.round_{validation_rounds}_passed",
                    (
                        "本大轮验证已通过；下一步回到 decide，只允许判断当前新基线是否已经足够好，"
                        "或开始下一轮语义增强。上一大轮的 LSP/review/compile/analyze 修复循环已闭合。"
                    ),
                    limit=1200,
                ))
                return {
                    "context_notes": notes,
                    "route": "decide",
                    "validation_rounds": validation_rounds,
                    "repeated_failure_count": 0,
                    "failure_bucket_counts": dict(state.get("failure_bucket_counts", {}) or {}),
                    "latest_failure_title": "",
                    "latest_failure_text": "",
                    "latest_failure_lines": [],
                    "final_message": final_message,
                }

            return {
                "context_notes": notes,
                "route": "finish",
                "validation_rounds": validation_rounds,
                "repeated_failure_count": 0,
                "failure_bucket_counts": dict(state.get("failure_bucket_counts", {}) or {}),
                "latest_failure_title": "",
                "latest_failure_text": "",
                "latest_failure_lines": [],
                "final_message": final_message,
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
        graph.add_node("request_evidence", request_evidence)
        graph.add_node("apply_patch", apply_patch)
        graph.add_node("repair_decide", repair_decide)
        graph.add_node("apply_repair", apply_repair)
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
                "request_evidence": "request_evidence",  # 新增
                "apply_patch": "apply_patch",
                "validate": "validate",
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
            "request_evidence",
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
            "repair_decide",
            lambda state: str(state.get("route", "finish") or "finish"),
            {
                "apply_repair": "apply_repair",
                "finish": "finish",
            },
        )
        graph.add_conditional_edges(
            "apply_repair",
            lambda state: str(state.get("route", "finish") or "finish"),
            {
                "validate": "validate",
                "repair_decide": "repair_decide",
                "finish": "finish",
            },
        )
        graph.add_conditional_edges(
            "validate",
            lambda state: str(state.get("route", "finish") or "finish"),
            {
                "repair_decide": "repair_decide",
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

        accepted_without_changes = bool(final_state.get("accepted_without_changes", False))
        if request.analyzer == "csa":
            output_path = tracker.last_compile_output_path
            semantic_required = any(item.get("tool_name") == "semantic_validate" for item in tracker.history)
            semantic_ok = tracker.last_semantic_ok if semantic_required else True
            success = bool(output_path and Path(output_path).exists() and tracker.last_review_ok and semantic_ok and not error_message)
            if not success and accepted_without_changes:
                output_path = str(target_path)
                success = bool(target_path.exists() and tracker.last_review_ok and not error_message)
        else:
            output_path = str(target_path)
            success = bool(target_path.exists() and tracker.last_codeql_ok and tracker.last_review_ok and not error_message)
            if not success and accepted_without_changes:
                success = bool(target_path.exists() and tracker.last_review_ok and not error_message)

        if not success and not error_message:
            if tracker.last_tool_error:
                error_message = tracker.last_tool_error
            elif not tracker.last_review_ok:
                error_message = "结构审查未通过"
            elif accepted_without_changes:
                error_message = "基线质量评估未通过"
            elif request.analyzer == "csa":
                error_message = "结构审查或编译未通过"
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
                "last_semantic_ok": tracker.last_semantic_ok,
                "validation_rounds": int(final_state.get("validation_rounds", 0) or 0),
                "workflow": "langgraph_refine",
                "context_notes": list(final_state.get("context_notes", []) or []),
                "raw_decision_text": str(final_state.get("raw_decision_text", "") or ""),
                "raw_repair_text": str(final_state.get("raw_repair_text", "") or ""),
                "accepted_without_changes": accepted_without_changes,
                "model_requested_stop": bool(final_state.get("model_requested_stop", False)),
                "last_decision_action": str(final_state.get("last_decision_action", "") or ""),
                "last_repair_action": str(final_state.get("last_repair_action", "") or ""),
                "llm_usage": self._summarize_llm_usage(),
                "llm_usage_by_phase": self._llm_usage_by_phase(),
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
                "EVIDENCE_DIR": request.evidence_dir or "未提供",
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

    def _render_repair_prompt(
        self,
        task_prompt: str,
        artifact_path: str,
        artifact_text: str,
        latest_failure_title: str,
        latest_failure_text: str,
        latest_failure_lines: List[int],
    ) -> str:
        return self.prompt_repository.render(
            "refine.agent.repair",
            {
                "TASK_PROMPT": task_prompt,
                "ARTIFACT_PATH": artifact_path,
                "ARTIFACT_TEXT": artifact_text,
                "LATEST_FAILURE_TITLE": latest_failure_title or "无",
                "LATEST_FAILURE_TEXT": latest_failure_text or "无",
                "LATEST_FAILURE_LINES": ", ".join(str(line) for line in latest_failure_lines) or "无",
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
        reference_root = str(request.evidence_dir or request.validate_path or "").strip()
        if not reference_root:
            return notes

        for relative_path in self._extract_patch_target_paths(patch_text)[:2]:
            candidate = Path(reference_root) / relative_path
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
            "validate": "validate",
            "read_reference_file": "read_reference",
            "list_reference_dir": "list_reference",
            "request_evidence": "request_evidence",
            "finish": "finish",
        }
        return mapping.get(action, "finish")

    def _route_from_repair_decision(self, decision: RefinementRepairDecision) -> str:
        action = str(decision.get("action", "") or "").strip()
        return "apply_repair" if action == "apply_patch" else "finish"

    def _failure_bucket_for(self, failure_type: str, title: str = "", text: str = "") -> str:
        normalized_type = str(failure_type or "").strip().lower()
        normalized_title = str(title or "").strip().lower()
        normalized_text = str(text or "").strip().lower()

        if normalized_type == "semantic_validation_failure":
            execution_markers = (
                "扫描失败",
                "execution_failed",
                "semantic_execution_error",
                "功能验证执行失败",
                "assertion",
                "stack dump",
                "segmentation fault",
                "core dumped",
                "command failed",
                "no such file or directory",
                "not found",
                "failed to open",
                "unable to load",
            )
            if any(marker in normalized_text for marker in execution_markers):
                return "execution"

        if normalized_type in {
            "decision_parse_error",
            "repair_parse_error",
            "protocol_failure",
            "apply_patch_failure",
            "repair_apply_patch_failure",
        }:
            return "protocol"
        if normalized_type in {"syntax_error", "compile_failure"}:
            return "compile"
        if normalized_type == "analyze_failure":
            compile_markers = (
                "语法检查失败",
                "query compile",
                "compile",
                "cannot be resolved",
                "could not resolve",
                "unexpected input",
                "no viable parse",
                "missing one of",
            )
            if any(marker in normalized_text for marker in compile_markers):
                return "compile"
            return "semantic"
        if normalized_type == "review_failure":
            return "protocol"
        if any(token in normalized_title for token in ("parse", "exact_edits", "apply_patch")):
            return "protocol"
        return "semantic"

    def _failure_bucket_limit(self, bucket: str) -> int:
        if bucket == "execution":
            # Validator/runtime failures are often recoverable and should not consume
            # the same budget as true semantic misses.
            return 10
        return 3

    def _minimal_recovery_key(self, phase: str, failure_kind: str) -> str:
        return f"{str(phase or '').strip().lower()}::{str(failure_kind or '').strip().lower()}"

    def _can_attempt_minimal_recovery(self, state: RefinementWorkflowState, key: str) -> bool:
        attempts = dict(state.get("minimal_recovery_attempts", {}) or {})
        return int(attempts.get(key, 0) or 0) < 1

    def _consume_minimal_recovery_attempt(
        self,
        state: RefinementWorkflowState,
        key: str,
    ) -> Dict[str, int]:
        attempts = dict(state.get("minimal_recovery_attempts", {}) or {})
        attempts[key] = int(attempts.get(key, 0) or 0) + 1
        return attempts

    def _build_codeql_minimal_recovery_prompt(
        self,
        *,
        base_prompt: str,
        failure_title: str,
        failure_text: str,
        phase: str,
    ) -> str:
        recovery_lines = [
            "",
            "---",
            "这是一次 CodeQL 最小恢复重试。",
            f"失败类型: {failure_title or 'unknown'}",
            "只修刚才的协议/编辑失败，不要扩大语义改动面。",
            "硬性要求:",
            "- 只返回一个合法 JSON 对象",
            "- 若返回 `apply_patch`，`edits` 最多 2 个",
            "- 每个 `old_snippet` 必须直接来自当前工作副本，且足够具体以唯一命中",
            "- 不要重写整文件，不要发明新的 helper / predicate / API",
        ]
        if str(phase or "").strip().lower() == "decide":
            recovery_lines.append("- 如果当前只差本地验证，允许直接返回 `validate`")
        else:
            recovery_lines.append("- repair 阶段只允许围绕最新失败做最小修复")
        if failure_text:
            trimmed = str(failure_text or "").strip()
            if len(trimmed) > 1200:
                trimmed = trimmed[:1200] + "\n...[truncated]"
            recovery_lines.extend([
                "",
                "上一轮失败详情:",
                trimmed,
            ])
        return str(base_prompt or "") + "\n".join(recovery_lines)

    def _attempt_codeql_minimal_recovery(
        self,
        *,
        system_prompt: str,
        base_prompt: str,
        phase: str,
        failure_title: str,
        failure_text: str,
        repair_mode: bool = False,
    ) -> tuple[Dict[str, Any], str, str]:
        recovery_prompt = self._build_codeql_minimal_recovery_prompt(
            base_prompt=base_prompt,
            failure_title=failure_title,
            failure_text=failure_text,
            phase=phase,
        )
        raw_text = self._invoke_json_prompt(system_prompt, recovery_prompt, phase=phase)
        if repair_mode:
            parsed, parse_error = self._parse_repair_decision(raw_text)
        else:
            parsed, parse_error = self._parse_decision(raw_text)
        return parsed, raw_text, parse_error

    def _parse_decision(self, raw_content: Any) -> tuple[RefinementDecision, str]:
        parsed, error = self._parse_json_dict(raw_content)
        if error:
            salvaged = self._salvage_partial_decision(raw_content)
            if salvaged:
                return salvaged, ""
            return {}, error.replace("空响应", "空决策").replace("可解析的 JSON", "可解析的 JSON 决策")

        action = str(parsed.get("action", "") or "").strip()
        valid_actions = {
            "apply_patch",
            "validate",
            "read_reference_file",
            "list_reference_dir",
            "request_evidence",
            "finish",
        }
        if action not in valid_actions:
            return {}, f"模型返回了不支持的 refine action: {action or '空'}"

        decision: RefinementDecision = {
            "action": action,
            "summary": str(parsed.get("summary", "") or "").strip(),
            "path": str(parsed.get("path", "") or "").strip(),
            "recursive": bool(parsed.get("recursive", False)),
            "edits": [],
            "evidence_types": list(parsed.get("evidence_types", []) or []),
        }
        raw_edits = parsed.get("edits", [])
        if isinstance(raw_edits, list):
            for item in raw_edits[:8]:
                if not isinstance(item, dict):
                    continue
                old_snippet = str(item.get("old_snippet", "") or "")
                new_snippet = str(item.get("new_snippet", "") or "")
                if not old_snippet:
                    continue
                decision["edits"].append({
                    "old_snippet": old_snippet,
                    "new_snippet": new_snippet,
                })
        if action == "apply_patch" and not decision["edits"]:
            return {}, "模型返回了 apply_patch，但没有提供任何有效 edits。"
        return decision, ""

    def _parse_repair_decision(self, raw_content: Any) -> tuple[RefinementRepairDecision, str]:
        parsed, error = self._parse_json_dict(raw_content)
        if error:
            return {}, error

        action = str(parsed.get("action", "") or "").strip()
        if action not in {"apply_patch", "finish"}:
            return {}, f"模型返回了不支持的 refine repair action: {action or '空'}"

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

        decision: RefinementRepairDecision = {
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

    def _salvage_partial_decision(self, raw_content: Any) -> RefinementDecision:
        content = self._stringify_message_content(raw_content).strip()
        if not content:
            return {}

        valid_actions = {
            "apply_patch",
            "validate",
            "read_reference_file",
            "list_reference_dir",
            "request_evidence",
            "finish",
        }
        action = self._extract_json_field(content, "action")
        if not isinstance(action, str):
            return {}
        action = action.strip()
        if action not in valid_actions:
            return {}

        summary = self._extract_json_field(content, "summary")
        path = self._extract_json_field(content, "path")
        recursive = self._extract_json_field(content, "recursive")
        evidence_types = self._extract_json_field(content, "evidence_types")
        raw_edits = self._extract_json_field(content, "edits")

        normalized_evidence_types: List[str] = []
        if isinstance(evidence_types, list):
            normalized_evidence_types = [str(item).strip() for item in evidence_types if str(item).strip()]

        normalized_edits: List[Dict[str, str]] = []
        if isinstance(raw_edits, list):
            for item in raw_edits[:8]:
                if not isinstance(item, dict):
                    continue
                old_snippet = str(item.get("old_snippet", "") or "")
                new_snippet = str(item.get("new_snippet", "") or "")
                if not old_snippet:
                    continue
                normalized_edits.append({
                    "old_snippet": old_snippet,
                    "new_snippet": new_snippet,
                })

        decision: RefinementDecision = {
            "action": action,
            "summary": str(summary or "").strip() if isinstance(summary, str) else "",
            "path": str(path or "").strip() if isinstance(path, str) else "",
            "recursive": bool(recursive) if isinstance(recursive, bool) else False,
            "edits": normalized_edits,
            "evidence_types": normalized_evidence_types,
        }

        if action == "request_evidence" and not normalized_evidence_types:
            return {}
        if action == "apply_patch" and not normalized_edits:
            return {}
        return decision

    def _extract_json_field(self, content: str, key: str) -> Any:
        match = re.search(rf'"{re.escape(str(key))}"\s*:', str(content or ""))
        if not match:
            return None
        tail = str(content or "")[match.end():].lstrip()
        if not tail:
            return None
        try:
            value, _ = json.JSONDecoder().raw_decode(tail)
            return value
        except Exception:
            return None

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

    def _failure_state_update(
        self,
        state: RefinementWorkflowState,
        title: str,
        text: str,
        failure_type: str = "",
    ) -> Dict[str, Any]:
        failure_text = str(text or "").strip()
        failure_lines = self._extract_failure_lines(failure_text)
        previous_key = str(state.get("latest_failure_title", "") or "")
        repeated_failure_count = int(state.get("repeated_failure_count", 0) or 0)
        if title and title == previous_key:
            repeated_failure_count += 1
        else:
            repeated_failure_count = 1 if title else 0

        bucket = self._failure_bucket_for(failure_type, title, failure_text)
        failure_bucket_counts = dict(state.get("failure_bucket_counts", {}) or {})
        if bucket:
            failure_bucket_counts[bucket] = int(failure_bucket_counts.get(bucket, 0) or 0) + 1

        return {
            "latest_failure_title": title,
            "latest_failure_text": failure_text,
            "latest_failure_lines": failure_lines,
            "repeated_failure_count": repeated_failure_count,
            "failure_bucket_counts": failure_bucket_counts,
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

    def _invoke_json_prompt(self, system_prompt: str, prompt: str, *, phase: str) -> str:
        messages = [
            SystemMessage(content=system_prompt),
            HumanMessage(content=prompt),
        ]
        model = self._get_phase_model(phase)
        phase_temperature = self._phase_temperatures.get(phase)
        model_name = self._resolve_model_name(model)
        bound = None
        if hasattr(model, "bind"):
            try:
                bound = model.bind(response_format={"type": "json_object"})
            except Exception:
                bound = None
        if bound is not None and hasattr(bound, "invoke"):
            try:
                return self._invoke_with_usage(
                    invoker=bound,
                    messages=messages,
                    phase=phase,
                    model_name=model_name,
                )
            except Exception as exc:
                self._emit_progress("model_bind_fallback", phase=phase, error=str(exc))

        if hasattr(model, "invoke"):
            return self._invoke_with_usage(
                invoker=model,
                messages=messages,
                phase=phase,
                model_name=model_name,
            )

        if hasattr(model, "generate"):
            self._emit_progress("agent_think_started", phase=phase, model=model_name)
            self._emit_progress("agent_llm_call_started", phase=phase, model=model_name)
            prompt_text = f"{system_prompt}\n\n{prompt}"
            content = str(model.generate(prompt_text, temperature=phase_temperature) or "")
            usage = {}
            if hasattr(model, "get_last_usage"):
                try:
                    usage = dict(model.get_last_usage() or {})
                except Exception:
                    usage = {}
            self._record_llm_usage(phase=phase, usage=usage)
            self._emit_progress("agent_llm_call_completed", phase=phase, model=model_name, llm_usage=usage)
            self._emit_progress("agent_think_completed", phase=phase, model=model_name, llm_usage=usage)
            return content

        raise TypeError("refine agent 的 llm_override 不支持 bind/invoke/generate 接口。")

    def _invoke_with_usage(
        self,
        invoker: Any,
        messages: List[Any],
        *,
        phase: str,
        model_name: str,
    ) -> str:
        self._emit_progress("agent_think_started", phase=phase, model=model_name)
        self._emit_progress("agent_llm_call_started", phase=phase, model=model_name)
        response = invoker.invoke(messages)
        usage = extract_usage_from_response(response, fallback_model=model_name)
        self._record_llm_usage(phase=phase, usage=usage)
        self._emit_progress("agent_llm_call_completed", phase=phase, model=model_name, llm_usage=usage)
        self._emit_progress("agent_think_completed", phase=phase, model=model_name, llm_usage=usage)
        return self._extract_raw_response_text(response)

    def _record_llm_usage(self, *, phase: str, usage: Dict[str, Any]):
        normalized = dict(usage or {})
        normalized["phase"] = phase
        self._current_llm_usage.append(normalized)

    def _summarize_llm_usage(self) -> Dict[str, Any]:
        usage = merge_usages(self._current_llm_usage)
        usage["phases"] = len({str(item.get("phase", "") or "").strip() for item in self._current_llm_usage if str(item.get("phase", "") or "").strip()})
        return usage

    def _llm_usage_by_phase(self) -> Dict[str, Any]:
        grouped: Dict[str, List[Dict[str, Any]]] = {}
        for item in self._current_llm_usage:
            phase = str(item.get("phase", "") or "unknown").strip() or "unknown"
            grouped.setdefault(phase, []).append(item)
        return {phase: merge_usages(items) for phase, items in grouped.items()}

    def _get_phase_model(self, phase: str) -> Any:
        model = self._phase_models.get(phase)
        if model is not None:
            return model

        temperature_key, default_temperature = self._PHASE_TEMPERATURES.get(phase, ("refine_decision_temperature", 0.08))
        model = build_langchain_chat_model(
            config=self.config,
            temperature_override=self._resolve_phase_temperature(temperature_key, default_temperature),
            default_temperature=default_temperature,
        )
        self._phase_models[phase] = model
        if phase == "decide" and self.model is None:
            self.model = model
        return model

    def _resolve_model_name(self, model: Any) -> str:
        for attr in ("model_name", "model", "primary_model"):
            token = str(getattr(model, attr, "") or "").strip()
            if token:
                return token
        return ""

    def _has_llm_config(self) -> bool:
        llm_config = self.config.get("llm", {}) if isinstance(self.config.get("llm", {}), dict) else {}
        return bool(llm_config)

    def _resolve_phase_temperature(self, temperature_key: str, default_temperature: float) -> float:
        agent_config = self.config.get("agent", {}) if isinstance(self.config.get("agent", {}), dict) else {}
        temperature = agent_config.get(temperature_key)
        if temperature is None:
            temperature = agent_config.get("refine_temperature")
        if temperature is None:
            temperature = agent_config.get("temperature")
        if temperature is None:
            temperature = default_temperature
        return float(temperature)

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

    def _format_evidence(self, evidence_type: str, evidence_data: Any) -> str:
        """格式化证据内容为可读文本"""
        import json

        if not evidence_data:
            return "无数据"

        if isinstance(evidence_data, dict):
            if evidence_data.get("available") is False:
                return f"不可用: {evidence_data.get('message', '未知原因')}"

            # 格式化字典类型的证据
            parts: List[str] = []
            for key, value in evidence_data.items():
                if key == "available":
                    continue
                if isinstance(value, (dict, list)):
                    try:
                        formatted = json.dumps(value, ensure_ascii=False, indent=2)
                    except Exception:
                        formatted = str(value)
                    parts.append(f"**{key}**:\n{formatted}")
                else:
                    parts.append(f"**{key}**: {value}")
            return "\n\n".join(parts)

        if isinstance(evidence_data, list):
            if not evidence_data:
                return "空列表"
            try:
                return json.dumps(evidence_data, ensure_ascii=False, indent=2)
            except Exception:
                return "\n".join(str(item) for item in evidence_data)

        return str(evidence_data)

    def _analyzer_display_name(self) -> str:
        return "CSA (Clang Static Analyzer)" if self.analyzer == "csa" else "CodeQL"
