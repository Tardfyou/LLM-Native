"""
CSA-oriented evidence collection.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from ...core.analyzer_base import AnalyzerContext
from ...core.evidence_schema import EvidenceAnchor, EvidenceBundle, EvidenceSlice
from .artifact_extractor import MEMORY_APIS, ProjectArtifactExtractor, SourceArtifactContext
from .base import EvidenceCollector


class CSAPathEvidenceCollector(EvidenceCollector):
    """Collect path-sensitive evidence hints for CSA synthesis."""

    analyzer_id = "csa"
    BUFFER_RISKY_APIS = frozenset({"strcpy", "strcat", "sprintf", "memcpy", "memmove"})
    BOUNDED_WRITE_APIS = frozenset({"memcpy", "memmove", "snprintf", "strncpy", "strncat"})
    SIZE_ROLE_TOKENS = ("len", "size", "bytes", "capacity", "cap", "limit", "written", "status")
    _CONTROL_TOKENS = {
        "if",
        "else",
        "while",
        "for",
        "return",
        "sizeof",
        "int",
        "long",
        "short",
        "char",
        "void",
        "const",
        "unsigned",
        "signed",
        "struct",
        "static",
        "auto",
        "case",
    }
    LIFECYCLE_HINT_RE = re.compile(
        r"(?i)^(?:"
        r"alloc|calloc|malloc|realloc|new|create|init|open|acquire|retain|attach|register|"
        r"get|find|lookup|fetch|borrow|spawn|start|"
        r"destroy|release|free|delete|close|drop|put|reset|expire|sweep|flush|shutdown|stop|teardown"
        r")[_A-Za-z0-9]*$"
    )

    def collect(self, context: AnalyzerContext) -> EvidenceBundle:
        records = []
        missing_evidence: List[str] = []
        requirements = self._evidence_requirements(context)
        extractor = ProjectArtifactExtractor()
        source_contexts, artifact_meta = extractor.collect_source_contexts(context)
        project_info = artifact_meta.get("project_info", {}) or {}
        build_system = str(project_info.get("build_system") or "unknown")
        runtime_artifacts = extractor.collect_csa_runtime_artifacts(context, source_contexts)
        patch_contracts = self._patch_contracts(context, source_contexts)

        for requirement in requirements:
            evidence_type = str(requirement.get("evidence_type", ""))
            if evidence_type == "path_guard":
                guard_records = self._guard_records(source_contexts, runtime_artifacts, requirement.get("reason", ""))
                for index, item in enumerate(guard_records):
                    records.append(self._record(
                        f"csa_guard_{index}",
                        "path_guard",
                        context,
                        item["payload"],
                        line=item["line"],
                        artifact=item["artifact"],
                        confidence=item["confidence"],
                        file=str(item["payload"].get("source_file", "") or self._primary_file(context)),
                        function=str((item["payload"].get("functions", []) or [""])[0]),
                        evidence_slice=item.get("evidence_slice"),
                    ))
                if not guard_records:
                    missing_evidence.append("path_guard")

            elif evidence_type in {"context_summary", "slice_summary"}:
                summary_record = self._context_summary_record(
                    context,
                    source_contexts,
                    runtime_artifacts,
                    project_info,
                    patch_contracts,
                    requirement.get("reason", ""),
                )
                if summary_record is not None:
                    records.append(self._record(
                        "csa_context_0",
                        "context_summary",
                        context,
                        summary_record["payload"],
                        line=summary_record["line"],
                        artifact=summary_record["artifact"],
                        confidence=summary_record["confidence"],
                        file=str(summary_record["payload"].get("source_file", "") or self._primary_file(context)),
                        function=str(((summary_record["payload"].get("focus_functions", []) or [""])[0]) or self._primary_function(context)),
                        evidence_slice=summary_record.get("evidence_slice"),
                    ))
                else:
                    missing_evidence.append("context_summary")

            elif evidence_type == "semantic_slice":
                semantic_records = self._semantic_slice_records(
                    context,
                    patch_contracts,
                    requirement.get("reason", ""),
                )
                for index, item in enumerate(semantic_records):
                    records.append(self._record(
                        f"csa_semantic_slice_{index}",
                        "semantic_slice",
                        context,
                        item["payload"],
                        line=item["line"],
                        artifact=item["artifact"],
                        confidence=item["confidence"],
                        file=str(item["payload"].get("source_file", "") or self._primary_file(context)),
                        function=str(item["payload"].get("function", "") or self._primary_function(context)),
                        evidence_slice=item.get("evidence_slice"),
                    ))
                if not semantic_records:
                    missing_evidence.append("semantic_slice")

            elif evidence_type == "state_transition":
                state_records = self._state_records(source_contexts, runtime_artifacts, requirement.get("reason", ""))
                for index, item in enumerate(state_records):
                    records.append(self._record(
                        f"csa_state_{index}",
                        "state_transition",
                        context,
                        item["payload"],
                        line=item["line"],
                        artifact=item["artifact"],
                        confidence=item["confidence"],
                        file=str(item["payload"].get("source_file", "") or self._primary_file(context)),
                        function=str((item["payload"].get("functions", []) or [""])[0]),
                        evidence_slice=item.get("evidence_slice"),
                    ))
                if not state_records:
                    missing_evidence.append("state_transition")

            elif evidence_type == "allocation_lifecycle":
                lifecycle = self._lifecycle_record(source_contexts, runtime_artifacts, requirement.get("reason", ""))
                if lifecycle is not None:
                    records.append(self._record(
                        "csa_lifecycle_0",
                        "allocation_lifecycle",
                        context,
                        lifecycle["payload"],
                        line=lifecycle["line"],
                        artifact=lifecycle["artifact"],
                        confidence=lifecycle["confidence"],
                        file=str(lifecycle["payload"].get("source_file", "") or self._primary_file(context)),
                        function=str((lifecycle["payload"].get("functions", []) or [""])[0]),
                        evidence_slice=lifecycle.get("evidence_slice"),
                    ))
                else:
                    missing_evidence.append("allocation_lifecycle")

            elif evidence_type == "diagnostic":
                records.append(self._record(
                    "csa_diag_0",
                    "diagnostic",
                    context,
                    {
                        "reason": requirement.get("reason", ""),
                        "summary": (
                            f"CSA runtime artifacts: cfg_snapshots={len(runtime_artifacts.get('cfg_snapshots', []) or [])}, "
                            f"call_edges={len(runtime_artifacts.get('call_edges', []) or [])}, "
                            f"build={build_system}, compile_commands={bool(project_info.get('has_compile_commands'))}."
                        ),
                        "compile_commands_path": project_info.get("compile_commands_path", ""),
                        "build_system": build_system,
                        "clang_path": runtime_artifacts.get("clang_path", ""),
                        "coverage_status": "full" if runtime_artifacts.get("available") else "partial",
                    },
                    artifact="clang-analyzer:runtime-summary",
                    confidence=0.78 if runtime_artifacts.get("available") else 0.68,
                    evidence_slice=EvidenceSlice(
                        kind="context_summary",
                        anchor=EvidenceAnchor(
                            patch_file="",
                            hunk_index=0,
                            source_line=0,
                        ),
                        summary=(
                            f"CSA build={build_system}, cfg_snapshots={len(runtime_artifacts.get('cfg_snapshots', []) or [])}, "
                            f"call_edges={len(runtime_artifacts.get('call_edges', []) or [])}"
                        ),
                        verifier="clang-analyzer" if runtime_artifacts.get("available") else "project-build",
                        extraction_method="runtime_artifacts",
                        coverage_status="full" if runtime_artifacts.get("available") else "partial",
                    ),
                ))

        return EvidenceBundle(
            records=records,
            missing_evidence=sorted(set(missing_evidence)),
            collected_analyzers=[self.analyzer_id] if records else [],
        )

    def _guard_records(
        self,
        source_contexts: List[SourceArtifactContext],
        runtime_artifacts: Dict[str, object],
        reason: str,
    ) -> List[dict]:
        records: List[dict] = []
        seen = set()
        for item in source_contexts[:4]:
            runtime = self._match_runtime_snapshot(item, runtime_artifacts)
            cfg_branches = list((runtime or {}).get("branch_kinds", []) or [])
            guards = self._relevant_guards(item, runtime)
            if not guards and cfg_branches:
                guards = [f"CFG branches: {', '.join(cfg_branches[:3])}"]
            if not guards and item.lock_calls:
                guards = [f"lock discipline around {', '.join(item.lock_calls[:2])}"]

            for guard in guards[:2]:
                key = (item.relative_file, item.function_name or "", guard)
                if key in seen:
                    continue
                seen.add(key)
                records.append({
                    "line": item.anchor_line,
                    "artifact": "clang-analyzer:debug-cfg" if runtime else "compile-db/source-window:path-guard",
                    "confidence": 0.9 if runtime and cfg_branches else (0.84 if item.compile_command else 0.77),
                    "payload": {
                        "reason": reason,
                        "guard_expr": guard,
                        "summary": (
                            f"{item.function_name or 'scope'} in {item.relative_file} "
                            f"guards shared state near line {item.anchor_line}"
                        ),
                        "state_before": self._state_before(item, runtime),
                        "state_after": self._state_after(item, runtime, guard, item.state_ops),
                        "functions": [item.function_name] if item.function_name else [],
                        "globals": item.globals[:5],
                        "tracked_symbols": self._tracked_symbols(item, runtime),
                        "buffer_fields": self._buffer_fields(item, runtime),
                        "call_targets": self._merged_call_targets(item, runtime),
                        "call_edges": list((runtime or {}).get("call_edges", []) or [])[:6],
                        "cfg_branch_kinds": cfg_branches[:4],
                        "branch_conditions": list((runtime or {}).get("branch_conditions", []) or [])[:4],
                        "state_statements": list((runtime or {}).get("state_statements", []) or [])[:6],
                        "compile_command_preview": item.compile_command_preview(),
                        "source_file": item.relative_file,
                        "source_excerpt": item.source_excerpt,
                        "summary_line": item.anchor_line,
                        "coverage_status": "full" if runtime else "partial",
                    },
                    "evidence_slice": self._build_slice(
                        item=item,
                        runtime=runtime,
                        kind="path_witness",
                        summary=(
                            f"{item.function_name or 'scope'} in {item.relative_file} "
                            f"guards shared state near line {item.anchor_line}"
                        ),
                        guards=[guard],
                        state_transitions=self._state_after(item, runtime, guard, item.state_ops),
                        api_terms=item.memory_ops + item.lock_calls,
                        coverage_status="full" if runtime else "partial",
                    ),
                })
        return records

    def _relevant_guards(
        self,
        item: SourceArtifactContext,
        runtime: Optional[Dict[str, object]],
    ) -> List[str]:
        support_tokens = self._guard_support_tokens(item, runtime)
        relevant: List[str] = []
        for guard in item.guard_exprs:
            guard_text = str(guard or "").strip()
            if not guard_text:
                continue
            identifiers = [
                token
                for token in re.findall(r"\b([A-Za-z_]\w*)\b", guard_text)
                if token not in {"if", "sizeof", "NULL"}
            ]
            if not support_tokens:
                relevant.append(guard_text)
                continue
            if identifiers and all(token in support_tokens for token in identifiers):
                relevant.append(guard_text)
        return self._dedupe(relevant)[:2]

    def _guard_support_tokens(
        self,
        item: SourceArtifactContext,
        runtime: Optional[Dict[str, object]],
    ) -> List[str]:
        tokens: List[str] = []
        tokens.extend(item.parameters)
        for field in self._buffer_fields(item, runtime):
            tokens.append(field)
            tokens.append(field.split("->")[-1])
        return self._dedupe(tokens)

    def _context_summary_record(
        self,
        context: AnalyzerContext,
        source_contexts: List[SourceArtifactContext],
        runtime_artifacts: Dict[str, object],
        project_info: Dict[str, Any],
        patch_contracts: List[Dict[str, Any]],
        reason: str,
    ) -> Optional[Dict[str, Any]]:
        contract_summaries = [str(item.get("summary", "") or "").strip() for item in patch_contracts if str(item.get("summary", "") or "").strip()]
        contract_types = self._dedupe([str(item.get("contract_type", "") or "").strip() for item in patch_contracts if str(item.get("contract_type", "") or "").strip()])
        focus_functions = self._dedupe([str(item.get("function", "") or "").strip() for item in patch_contracts if str(item.get("function", "") or "").strip()])
        barrier_guards = self._dedupe([guard for item in patch_contracts for guard in (item.get("guards", []) or []) if str(guard).strip()])[:6]
        added_apis = self._dedupe([api for item in patch_contracts for api in (item.get("added_calls", []) or []) if str(api).strip()])[:8]
        removed_risky = self._dedupe([api for item in patch_contracts for api in (item.get("removed_calls", []) or []) if str(api).strip()])[:8]
        target_files = self._dedupe([str(item.relative_file).strip() for item in source_contexts if str(item.relative_file).strip()])[:8]

        summary_parts: List[str] = []
        if contract_summaries:
            summary_parts.append(f"contracts={len(contract_summaries)}")
        if barrier_guards:
            summary_parts.append(f"barriers={'; '.join(barrier_guards[:2])}")
        if added_apis:
            summary_parts.append(f"safe_apis={', '.join(added_apis[:4])}")
        if removed_risky:
            summary_parts.append(f"removed_sinks={', '.join(removed_risky[:4])}")
        if not summary_parts and not target_files:
            return None

        coverage_status = "full" if contract_summaries else ("partial" if target_files else "missing")
        payload = {
            "reason": reason,
            "summary": " | ".join(summary_parts),
            "contract_types": contract_types,
            "focus_functions": focus_functions,
            "barrier_guards": barrier_guards,
            "removed_risky_calls": removed_risky,
            "added_safe_apis": added_apis,
            "target_files": target_files,
            "build_system": project_info.get("build_system", "unknown"),
            "compile_commands_path": project_info.get("compile_commands_path", ""),
            "cfg_snapshots": len(runtime_artifacts.get("cfg_snapshots", []) or []),
            "call_edges": len(runtime_artifacts.get("call_edges", []) or []),
            "coverage_status": coverage_status,
            "source_file": target_files[0] if target_files else "",
            "contract_summaries": contract_summaries[:4],
        }
        return {
            "line": int((patch_contracts[0].get("line", 0) if patch_contracts else 0) or 0),
            "artifact": "patch-diff:contract-summary",
            "confidence": 0.9 if contract_summaries else 0.72,
            "payload": payload,
            "evidence_slice": EvidenceSlice(
                kind="context_summary",
                anchor=EvidenceAnchor(
                    patch_file=str(patch_contracts[0].get("patch_file", "") if patch_contracts else ""),
                    hunk_index=int((patch_contracts[0].get("hunk_index", 0) if patch_contracts else 0) or 0),
                    source_line=int((patch_contracts[0].get("line", 0) if patch_contracts else 0) or 0),
                ),
                summary=str(payload.get("summary", "") or ""),
                statements=list(contract_summaries[:4]),
                guards=barrier_guards[:4],
                call_boundary=target_files[:6],
                call_edges=list(runtime_artifacts.get("call_edges", []) or [])[:6],
                api_terms=added_apis[:4] + removed_risky[:2],
                related_symbols=focus_functions[:6],
                verifier="patch-diff",
                extraction_method="patch_hunk_contracts+source_context",
                coverage_status=coverage_status,
            ),
        }

    def _semantic_slice_records(
        self,
        context: AnalyzerContext,
        patch_contracts: List[Dict[str, Any]],
        reason: str,
    ) -> List[Dict[str, Any]]:
        records: List[Dict[str, Any]] = []
        for item in patch_contracts[:4]:
            summary = str(item.get("summary", "") or "").strip()
            if not summary:
                continue
            payload = {
                "reason": reason,
                "summary": summary,
                "contract_type": str(item.get("contract_type", "") or ""),
                "same_call_binding": str(item.get("same_call_binding", "") or ""),
                "trigger_contract": str(item.get("trigger_contract", "") or ""),
                "silence_contract": str(item.get("silence_contract", "") or ""),
                "guard_exprs": list(item.get("guards", []) or [])[:4],
                "removed_calls": list(item.get("removed_calls", []) or [])[:6],
                "added_calls": list(item.get("added_calls", []) or [])[:6],
                "tracked_symbols": list(item.get("symbols", []) or [])[:8],
                "buffer_fields": list(item.get("buffer_fields", []) or [])[:6],
                "source_file": str(item.get("source_file", "") or ""),
                "function": str(item.get("function", "") or ""),
                "source_excerpt": str(item.get("source_excerpt", "") or ""),
                "coverage_status": str(item.get("coverage_status", "") or "partial"),
            }
            records.append({
                "line": int(item.get("line", 0) or 0),
                "artifact": "patch-diff:semantic-contract",
                "confidence": 0.92 if payload["coverage_status"] == "full" else 0.82,
                "payload": payload,
                "evidence_slice": EvidenceSlice(
                    kind="semantic_slice",
                    anchor=EvidenceAnchor(
                        patch_file=str(item.get("patch_file", "") or ""),
                        hunk_index=int(item.get("hunk_index", 0) or 0),
                        source_line=int(item.get("line", 0) or 0),
                    ),
                    summary=summary,
                    statements=list(item.get("statements", []) or [])[:6],
                    guards=list(item.get("guards", []) or [])[:4],
                    call_boundary=list(item.get("added_calls", []) or [])[:4],
                    call_edges=list(item.get("call_edges", []) or [])[:6],
                    state_transitions=[
                        str(item.get("trigger_contract", "") or ""),
                        str(item.get("silence_contract", "") or ""),
                    ],
                    api_terms=list(item.get("added_calls", []) or [])[:4] + list(item.get("removed_calls", []) or [])[:2],
                    related_symbols=list(item.get("symbols", []) or [])[:6],
                    verifier="patch-diff",
                    extraction_method="patch_hunk_contracts",
                    coverage_status=str(item.get("coverage_status", "") or "partial"),
                ),
            })
        return records

    def _patch_contracts(
        self,
        context: AnalyzerContext,
        source_contexts: List[SourceArtifactContext],
    ) -> List[Dict[str, Any]]:
        extractor = ProjectArtifactExtractor()
        contracts: List[Dict[str, Any]] = []
        for patch_file in extractor.parse_patch(context.patch_path):
            patch_path = str(patch_file.get("old_path") or patch_file.get("new_path") or "")
            for hunk_index, hunk in enumerate(patch_file.get("hunks", []) or []):
                removed_lines = list(hunk.get("removed_lines", []) or [])
                added_lines = list(hunk.get("added_lines", []) or [])
                removed_calls = self._extract_patch_calls(removed_lines)
                added_calls = self._extract_patch_calls(added_lines)
                guards = self._extract_patch_guards(added_lines)
                if not removed_calls and not added_calls and not guards:
                    continue

                source_item = self._match_hunk_context(
                    source_contexts,
                    patch_path,
                    int(hunk.get("old_start", 0) or hunk.get("new_start", 0) or 0),
                )
                function_name = str(source_item.function_name if source_item else "")
                source_excerpt = str(source_item.source_excerpt if source_item else "")
                source_file = str(source_item.relative_file if source_item else patch_path)
                statements = [line.strip() for line in added_lines if str(line).strip()][:6]
                symbols = self._interesting_tokens("\n".join(guards + added_lines))
                buffer_fields = self._dedupe(re.findall(r"[A-Za-z_]\w*->\w+", "\n".join(guards + added_lines)))[:6]
                contract_type = ""
                trigger_contract = ""
                silence_contract = ""
                same_call_binding = ""

                if (
                    any(api in self.BUFFER_RISKY_APIS for api in removed_calls)
                    and any(api in self.BOUNDED_WRITE_APIS for api in added_calls)
                    and any(self._looks_like_bounds_guard(expr) for expr in guards)
                ):
                    contract_type = "bounded_write_barrier"
                    trigger_contract = "report only when the write lacks a matching length/capacity barrier"
                    silence_contract = "stay silent when the same size carrier is compared against destination capacity before the current bounded write"
                    same_call_binding = "bind guard operands to the same destination field/parameter and the same size carrier used by the current write"
                elif "snprintf" in added_calls and self._has_checked_format_barrier(added_lines, guards):
                    contract_type = "checked_format_barrier"
                    trigger_contract = "report only when formatting/build logic lacks a checked bounded API barrier"
                    silence_contract = "stay silent when snprintf return value is checked against the same output capacity before control continues"
                    same_call_binding = "bind the checked return value and capacity parameter to the same output buffer call"
                elif guards and (removed_calls or added_calls):
                    contract_type = "patch_barrier"
                    trigger_contract = "report when a risky write proceeds without the patch-style barrier"
                    silence_contract = "stay silent when the nearby guard proves the current write is blocked or bounded"
                    same_call_binding = "tie the guard to the current write operands instead of any unrelated if-statement"

                if not contract_type:
                    continue

                summary = self._contract_summary(
                    function_name=function_name,
                    source_file=source_file,
                    contract_type=contract_type,
                    guards=guards,
                    removed_calls=removed_calls,
                    added_calls=added_calls,
                )
                contracts.append({
                    "patch_file": patch_path,
                    "hunk_index": hunk_index,
                    "line": int(hunk.get("new_start", 0) or hunk.get("old_start", 0) or 0),
                    "function": function_name,
                    "source_file": source_file,
                    "source_excerpt": source_excerpt,
                    "summary": summary,
                    "contract_type": contract_type,
                    "guards": guards[:4],
                    "removed_calls": removed_calls[:6],
                    "added_calls": added_calls[:6],
                    "symbols": symbols[:8],
                    "buffer_fields": buffer_fields,
                    "statements": statements,
                    "call_edges": [f"{function_name} -> {api}" for api in added_calls[:3]] if function_name else [],
                    "trigger_contract": trigger_contract,
                    "silence_contract": silence_contract,
                    "same_call_binding": same_call_binding,
                    "coverage_status": "full" if guards else "partial",
                })
        deduped: List[Dict[str, Any]] = []
        seen = set()
        for item in contracts:
            key = (
                item.get("source_file", ""),
                item.get("function", ""),
                item.get("summary", ""),
            )
            if key in seen:
                continue
            seen.add(key)
            deduped.append(item)
        return deduped[:6]

    def _extract_patch_calls(self, lines: List[str]) -> List[str]:
        calls: List[str] = []
        for line in lines:
            for name in re.findall(r"\b([A-Za-z_]\w*)\s*\(", str(line or "")):
                token = str(name).strip()
                if token and token not in self._CONTROL_TOKENS and token not in calls:
                    calls.append(token)
        return calls

    def _extract_patch_guards(self, lines: List[str]) -> List[str]:
        guards: List[str] = []
        for line in lines:
            match = re.search(r"\bif\s*\((.+)\)", str(line or "").strip())
            if match:
                guard = match.group(1).strip()
                if guard and guard not in guards:
                    guards.append(guard)
        return guards[:6]

    def _looks_like_bounds_guard(self, expr: str) -> bool:
        lowered = str(expr or "").strip().lower()
        if not lowered:
            return False
        if "sizeof" in lowered:
            return True
        if any(token in lowered for token in ("capacity", "out_size", "limit", "bytes", "len", "size")) and any(op in lowered for op in (">", "<")):
            return True
        return False

    def _has_checked_format_barrier(self, added_lines: List[str], guards: List[str]) -> bool:
        added_text = "\n".join(str(line or "") for line in added_lines)
        guard_text = "\n".join(str(guard or "") for guard in guards).lower()
        if "snprintf" not in added_text:
            return False
        return bool(
            "written" in guard_text
            and ("out_size" in guard_text or "capacity" in guard_text or "size" in guard_text)
            and any(op in guard_text for op in ("< 0", ">=", ">"))
        )

    def _match_hunk_context(
        self,
        source_contexts: List[SourceArtifactContext],
        patch_file: str,
        line: int,
    ) -> Optional[SourceArtifactContext]:
        candidates = [
            item
            for item in source_contexts
            if item.relative_file == patch_file or item.patch_file == patch_file
        ]
        if not candidates:
            return None
        return min(
            candidates,
            key=lambda item: abs(int(item.anchor_line or 0) - int(line or 0)),
        )

    def _interesting_tokens(self, text: str) -> List[str]:
        tokens: List[str] = []
        for raw in re.findall(r"\b([A-Za-z_]\w*)\b", text or ""):
            token = str(raw).strip()
            lowered = token.lower()
            if not token or lowered in self._CONTROL_TOKENS:
                continue
            if token not in tokens:
                tokens.append(token)
        return tokens

    def _contract_summary(
        self,
        *,
        function_name: str,
        source_file: str,
        contract_type: str,
        guards: List[str],
        removed_calls: List[str],
        added_calls: List[str],
    ) -> str:
        scope = function_name or source_file or "scope"
        if contract_type == "bounded_write_barrier":
            return (
                f"{scope} replaces {', '.join(removed_calls[:2]) or 'risky writes'} with "
                f"{', '.join(added_calls[:2]) or 'bounded writes'} and introduces guard "
                f"`{guards[0] if guards else 'unknown'}` that must stay bound to the same call."
            )
        if contract_type == "checked_format_barrier":
            return (
                f"{scope} switches to checked formatting via {', '.join(added_calls[:1]) or 'bounded formatting'}; "
                f"return-value guard `{guards[0] if guards else 'unknown'}` is the patched silence condition."
            )
        return (
            f"{scope} adds patch barrier `{guards[0] if guards else 'unknown'}` around "
            f"{', '.join(added_calls[:2] or removed_calls[:2]) or 'the affected sink'}."
        )

    def _state_records(
        self,
        source_contexts: List[SourceArtifactContext],
        runtime_artifacts: Dict[str, object],
        reason: str,
    ) -> List[dict]:
        records: List[dict] = []
        seen = set()
        for item in source_contexts[:4]:
            runtime = self._match_runtime_snapshot(item, runtime_artifacts)
            transition_parts = []
            if item.lock_calls:
                transition_parts.append(f"locks={', '.join(item.lock_calls[:2])}")
            if item.state_ops:
                transition_parts.append(f"state_ops={'; '.join(item.state_ops[:2])}")
            if runtime and runtime.get("call_edges"):
                transition_parts.append(f"cfg_calls={'; '.join((runtime.get('call_edges') or [])[:2])}")
            if item.memory_ops:
                transition_parts.append(f"memory_ops={', '.join(item.memory_ops[:3])}")
            if not transition_parts:
                continue

            key = (item.relative_file, item.function_name or "", "|".join(transition_parts))
            if key in seen:
                continue
            seen.add(key)
            records.append({
                "line": item.anchor_line,
                "artifact": "clang-analyzer:symbolic-state" if runtime else "compile-db/source-window:symbolic-state",
                "confidence": 0.88 if runtime and runtime.get("call_edges") else 0.81,
                "payload": {
                    "reason": reason,
                    "summary": (
                        f"{item.function_name or 'scope'} in {item.relative_file}: "
                        + " | ".join(transition_parts)
                    ),
                    "state_before": self._state_before(item, runtime),
                    "state_after": self._state_after(
                        item,
                        runtime,
                        "",
                        list(item.state_ops[:3]) + list((runtime or {}).get("state_statements", []) or [])[:3],
                    ),
                    "functions": [item.function_name] if item.function_name else [],
                    "globals": item.globals[:5],
                    "tracked_symbols": self._tracked_symbols(item, runtime),
                    "buffer_fields": self._buffer_fields(item, runtime),
                    "call_targets": self._merged_call_targets(item, runtime),
                    "call_edges": list((runtime or {}).get("call_edges", []) or [])[:6],
                    "cfg_branch_kinds": list((runtime or {}).get("branch_kinds", []) or [])[:4],
                    "branch_conditions": list((runtime or {}).get("branch_conditions", []) or [])[:4],
                    "state_statements": list((runtime or {}).get("state_statements", []) or [])[:8],
                    "return_statements": list((runtime or {}).get("return_statements", []) or [])[:4],
                    "source_file": item.relative_file,
                    "source_excerpt": item.source_excerpt,
                    "coverage_status": "full" if runtime else "partial",
                },
                "evidence_slice": self._build_slice(
                    item=item,
                    runtime=runtime,
                    kind="state_witness",
                    summary=(
                        f"{item.function_name or 'scope'} in {item.relative_file}: "
                        + " | ".join(transition_parts)
                    ),
                    state_transitions=self._state_after(
                        item,
                        runtime,
                        "",
                        list(item.state_ops[:3]) + list((runtime or {}).get("state_statements", []) or [])[:3],
                    ),
                    api_terms=item.memory_ops + item.lock_calls,
                    coverage_status="full" if runtime else "partial",
                ),
            })
        return records

    def _lifecycle_record(
        self,
        source_contexts: List[SourceArtifactContext],
        runtime_artifacts: Dict[str, object],
        reason: str,
    ) -> Optional[dict]:
        best_candidate: Optional[dict] = None
        best_score = -1
        for item in source_contexts:
            runtime = self._match_runtime_snapshot(item, runtime_artifacts)
            runtime_calls = list((runtime or {}).get("call_targets", []) or [])
            operations = self._lifecycle_operations(item, runtime_calls)
            if not item.function_name or not operations:
                continue

            acquisition_ops = [op for op in operations if self._is_lifecycle_acquire(op)]
            release_ops = [op for op in operations if self._is_lifecycle_release(op)]
            transition_ops = [op for op in operations if op not in acquisition_ops and op not in release_ops]
            score = len(release_ops) * 5 + len(acquisition_ops) * 3 + len(transition_ops)
            if runtime:
                score += 2

            candidate = {
                "line": item.anchor_line,
                "artifact": "clang-analyzer:lifecycle" if runtime else "source-window:lifecycle-summary",
                "confidence": 0.9 if runtime and runtime_calls else 0.86,
                "payload": {
                    "reason": reason,
                    "summary": (
                        f"{item.function_name or 'scope'} in {item.relative_file} reaches "
                        f"{', '.join(operations[:3])}"
                    ),
                    "operations": operations[:6],
                    "acquisition_ops": acquisition_ops[:4],
                    "release_ops": release_ops[:4],
                    "transition_ops": transition_ops[:4],
                    "state_before": self._state_before(item, runtime),
                    "state_after": self._state_after(item, runtime, "", operations),
                    "functions": [item.function_name] if item.function_name else [],
                    "globals": item.globals[:5],
                    "tracked_symbols": self._tracked_symbols(item, runtime),
                    "buffer_fields": self._buffer_fields(item, runtime),
                    "call_edges": list((runtime or {}).get("call_edges", []) or [])[:6],
                    "source_file": item.relative_file,
                    "source_excerpt": item.source_excerpt,
                    "coverage_status": "full" if runtime else "partial",
                },
                "evidence_slice": self._build_slice(
                    item=item,
                    runtime=runtime,
                    kind="lifecycle_witness",
                    summary=(
                        f"{item.function_name or 'scope'} in {item.relative_file} reaches "
                        f"{', '.join(operations[:3])}"
                    ),
                    state_transitions=self._state_after(item, runtime, "", operations),
                    api_terms=operations,
                    coverage_status="full" if runtime else "partial",
                ),
            }
            if score > best_score:
                best_candidate = candidate
                best_score = score
        return best_candidate

    def _lifecycle_operations(
        self,
        item: SourceArtifactContext,
        runtime_calls: List[str],
    ) -> List[str]:
        operations: List[str] = []
        operations.extend(item.memory_ops)
        operations.extend(item.call_targets)
        operations.extend(runtime_calls)
        operations.extend(item.state_ops)
        return [
            op
            for op in self._dedupe(operations)
            if self._is_lifecycle_hint(op)
        ][:8]

    def _is_lifecycle_hint(self, token: str) -> bool:
        normalized = str(token or "").strip()
        if not normalized:
            return False
        if normalized in MEMORY_APIS:
            return True
        return bool(self.LIFECYCLE_HINT_RE.match(normalized))

    def _is_lifecycle_release(self, token: str) -> bool:
        normalized = str(token or "").strip().lower()
        return normalized.startswith((
            "destroy",
            "release",
            "free",
            "delete",
            "close",
            "drop",
            "reset",
            "expire",
            "sweep",
            "flush",
            "shutdown",
            "stop",
            "teardown",
        ))

    def _is_lifecycle_acquire(self, token: str) -> bool:
        normalized = str(token or "").strip().lower()
        return normalized.startswith((
            "alloc",
            "calloc",
            "malloc",
            "realloc",
            "new",
            "create",
            "init",
            "open",
            "acquire",
            "retain",
            "attach",
            "register",
            "get",
            "find",
            "lookup",
            "fetch",
            "borrow",
            "spawn",
            "start",
        ))

    def _match_runtime_snapshot(
        self,
        item: SourceArtifactContext,
        runtime_artifacts: Dict[str, object],
    ) -> Optional[Dict[str, object]]:
        snapshots = list(runtime_artifacts.get("cfg_snapshots", []) or [])
        for snapshot in snapshots:
            if not isinstance(snapshot, dict):
                continue
            if snapshot.get("source_file") == item.relative_file and snapshot.get("function_name") == item.function_name:
                return snapshot
        for snapshot in snapshots:
            if not isinstance(snapshot, dict):
                continue
            if snapshot.get("source_file") == item.relative_file:
                return snapshot
        return None

    def _merged_call_targets(
        self,
        item: SourceArtifactContext,
        runtime: Optional[Dict[str, object]],
    ) -> List[str]:
        merged = list(item.call_targets)
        merged.extend(list((runtime or {}).get("call_targets", []) or []))
        return self._dedupe(merged)[:8]

    def _tracked_symbols(
        self,
        item: SourceArtifactContext,
        runtime: Optional[Dict[str, object]],
    ) -> List[str]:
        symbols: List[str] = []
        symbols.extend(item.parameters)
        symbols.extend(item.globals)
        symbols.extend(self._buffer_fields(item, runtime))
        return self._dedupe(symbols)[:8]

    def _buffer_fields(
        self,
        item: SourceArtifactContext,
        runtime: Optional[Dict[str, object]],
    ) -> List[str]:
        fields = list((runtime or {}).get("field_accesses", []) or [])
        fields.extend(self._extract_pointer_fields(item.source_excerpt))
        return self._dedupe(fields)[:6]

    def _state_before(
        self,
        item: SourceArtifactContext,
        runtime: Optional[Dict[str, object]],
    ) -> List[str]:
        state: List[str] = []
        for param in item.parameters[:3]:
            state.append(f"input({param})")
        for symbol in item.globals[:2]:
            state.append(f"shared({symbol})")
        for field in self._buffer_fields(item, runtime)[:2]:
            state.append(f"buffer({field})")
        merged_calls = self._merged_call_targets(item, runtime)
        if merged_calls:
            state.append(f"sinks({', '.join(merged_calls[:2])})")
        return self._dedupe(state)[:6]

    def _state_after(
        self,
        item: SourceArtifactContext,
        runtime: Optional[Dict[str, object]],
        guard_expr: str,
        operations: List[str],
    ) -> List[str]:
        state: List[str] = []
        fields = self._buffer_fields(item, runtime)
        if guard_expr:
            state.append(f"guard({guard_expr})")
            if "sizeof" in guard_expr:
                state.append("bounded_by_size")
                for field in fields[:2]:
                    field_name = field.split("->")[-1]
                    if field_name and field_name in guard_expr:
                        state.append(f"bounded({field})")
        for op in operations[:3]:
            state.append(f"transition({op})")
        if item.lock_calls:
            state.append(f"locked({', '.join(item.lock_calls[:2])})")
        return self._dedupe(state)[:6]

    def _extract_pointer_fields(self, source_excerpt: str) -> List[str]:
        return [
            token
            for token in re.findall(r"[A-Za-z_]\w*->\w+", source_excerpt or "")
        ]

    def _dedupe(self, items: List[str]) -> List[str]:
        seen = set()
        deduped: List[str] = []
        for item in items:
            token = str(item).strip()
            if token and token not in seen:
                seen.add(token)
                deduped.append(token)
        return deduped

    def _build_slice(
        self,
        item: SourceArtifactContext,
        runtime: Optional[Dict[str, object]],
        kind: str,
        summary: str,
        *,
        guards: Optional[List[str]] = None,
        state_transitions: Optional[List[str]] = None,
        api_terms: Optional[List[str]] = None,
        coverage_status: str = "partial",
    ) -> EvidenceSlice:
        runtime_calls = list((runtime or {}).get("call_targets", []) or [])
        call_edges = list((runtime or {}).get("call_edges", []) or [])[:8]
        call_boundary = self._merged_call_targets(item, runtime)[:6]
        statements = [
            line.strip()
            for line in (item.source_excerpt or "").splitlines()
            if line.strip()
        ][:6]
        related_symbols = self._tracked_symbols(item, runtime)
        deduped_guards = self._dedupe(list(guards or []) + list((runtime or {}).get("branch_conditions", []) or [])[:3])
        deduped_transitions = self._dedupe(list(state_transitions or []) + list((runtime or {}).get("state_statements", []) or [])[:4])
        deduped_api_terms = self._dedupe(list(api_terms or []) + runtime_calls)

        return EvidenceSlice(
            kind=kind,
            anchor=EvidenceAnchor(
                patch_file=item.patch_file,
                hunk_index=item.hunk_index,
                source_line=item.anchor_line,
            ),
            summary=summary,
            statements=statements,
            guards=deduped_guards[:4],
            call_boundary=call_boundary,
            call_edges=call_edges,
            state_transitions=deduped_transitions[:6],
            api_terms=deduped_api_terms[:6],
            related_symbols=related_symbols[:6],
            verifier="clang-analyzer" if runtime else "source-window",
            extraction_method="runtime_cfg+source_window" if runtime else "source_window",
            coverage_status=coverage_status,
        )
