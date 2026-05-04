"""
CSA-oriented evidence collection.
"""

from __future__ import annotations

import re
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from ...core.analyzer_base import AnalyzerContext
from ...core.evidence_schema import EvidenceAnchor, EvidenceBundle, EvidenceSlice
from .artifact_extractor import MEMORY_APIS, ProjectArtifactExtractor, SourceArtifactContext
from .base import EvidenceCollector


class CSAPathEvidenceCollector(EvidenceCollector):
    """Collect path-sensitive evidence hints for CSA synthesis."""

    analyzer_id = "csa"
    supported_types = ["semantic_slice", "path_guard", "state_transition", "allocation_lifecycle"]
    RESOURCE_LIFECYCLE_APIS = frozenset({"malloc", "calloc", "realloc", "free", "delete"})
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
        r"spawn|"
        r"destroy|release|free|delete|close|drop|put|reset|expire|sweep|flush|shutdown|stop|teardown"
        r")[_A-Za-z0-9]*$"
    )

    def collect(self, context: AnalyzerContext) -> EvidenceBundle:
        records = []
        missing_evidence: List[str] = []
        requirements = self._evidence_requirements(context)
        extractor = ProjectArtifactExtractor()
        source_contexts, artifact_meta = extractor.collect_source_contexts(context)
        runtime_artifacts = extractor.collect_csa_runtime_artifacts(context, source_contexts)
        patch_contracts = self._patch_contracts(context, source_contexts)
        validation_findings = self._load_validation_findings(context, source_contexts)

        for requirement in requirements:
            evidence_type = str(requirement.get("evidence_type", ""))
            if evidence_type == "path_guard":
                guard_records = self._guard_records(
                    source_contexts,
                    runtime_artifacts,
                    patch_contracts,
                    requirement.get("reason", ""),
                )
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
                state_records = self._state_records(
                    source_contexts,
                    runtime_artifacts,
                    patch_contracts,
                    requirement.get("reason", ""),
                )
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
                lifecycle = self._lifecycle_record(
                    source_contexts,
                    runtime_artifacts,
                    patch_contracts,
                    requirement.get("reason", ""),
                )
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

        if missing_evidence:
            recovered = self._validation_backed_records(
                context=context,
                missing_evidence=missing_evidence,
                source_contexts=source_contexts,
                runtime_artifacts=runtime_artifacts,
                patch_contracts=patch_contracts,
                validation_findings=validation_findings,
            )
            recovered_types = {str(item.get("evidence_type", "") or "") for item in recovered}
            for index, item in enumerate(recovered):
                evidence_type = str(item.get("evidence_type", "") or "")
                if not evidence_type:
                    continue
                records.append(self._record(
                    f"csa_validation_{evidence_type}_{index}",
                    evidence_type,
                    context,
                    item["payload"],
                    line=item["line"],
                    column=item.get("column", 0),
                    artifact=item["artifact"],
                    confidence=item["confidence"],
                    file=str(item["payload"].get("source_file", "") or self._primary_file(context)),
                    function=str((item["payload"].get("functions", []) or [""])[0]),
                    evidence_slice=item.get("evidence_slice"),
                ))
            missing_evidence = [
                evidence_type
                for evidence_type in missing_evidence
                if evidence_type not in recovered_types
            ]

        return EvidenceBundle(
            records=records,
            missing_evidence=sorted(set(missing_evidence)),
            collected_analyzers=[self.analyzer_id] if records else [],
        )

    def _guard_records(
        self,
        source_contexts: List[SourceArtifactContext],
        runtime_artifacts: Dict[str, object],
        patch_contracts: List[Dict[str, Any]],
        reason: str,
    ) -> List[dict]:
        records: List[dict] = []
        seen = set()
        for item in patch_contracts:
            if str(item.get("contract_type", "") or "") not in {
                "bounded_write_barrier",
                "checked_format_barrier",
                "patch_barrier",
            }:
                continue
            function_name = str(item.get("function", "") or "").strip()
            source_file = str(item.get("source_file", "") or "")
            guards = [str(guard).strip() for guard in (item.get("guards", []) or []) if str(guard).strip()]
            if not guards:
                continue
            tracked_symbols = [str(symbol).strip() for symbol in (item.get("symbols", []) or []) if str(symbol).strip()]
            buffer_fields = [str(field).strip() for field in (item.get("buffer_fields", []) or []) if str(field).strip()]
            removed_calls = [str(call).strip() for call in (item.get("removed_calls", []) or []) if str(call).strip()]
            added_calls = [str(call).strip() for call in (item.get("added_calls", []) or []) if str(call).strip()]
            sink_calls = [str(call).strip() for call in (item.get("sink_calls", []) or []) if str(call).strip()]
            call_targets = sink_calls[:4] or added_calls[:4] or removed_calls[:4]
            state_before = [
                *[f"input({symbol})" for symbol in tracked_symbols[:2]],
                *[f"buffer({field})" for field in buffer_fields[:2]],
                *[f"risky({call})" for call in removed_calls[:2]],
            ]
            state_before = self._dedupe(state_before)[:6]

            for guard in guards[:2]:
                key = (source_file, function_name, guard)
                if key in seen:
                    continue
                seen.add(key)
                summary = (
                    f"{function_name or source_file or 'scope'} introduces patch guard `{guard}` "
                    f"before {', '.join(call_targets[:2] or ['the current sink'])}."
                )
                state_after = self._dedupe(
                    [f"guard({guard})"]
                    + [f"current_call({call})" for call in call_targets[:2]]
                )[:6]
                records.append({
                    "line": int(item.get("line", 0) or 0),
                    "artifact": "patch-diff:path-guard",
                    "confidence": 0.92,
                    "payload": {
                        "reason": reason,
                        "guard_expr": guard,
                        "summary": summary,
                        "state_before": state_before,
                        "state_after": state_after,
                        "functions": [function_name] if function_name else [],
                        "globals": [],
                        "tracked_symbols": tracked_symbols[:6],
                        "buffer_fields": buffer_fields[:4],
                        "call_targets": call_targets[:4],
                        "call_edges": list(item.get("call_edges", []) or [])[:6],
                        "cfg_branch_kinds": ["if"],
                        "branch_conditions": [guard],
                        "state_statements": list(item.get("statements", []) or [])[:6],
                        "compile_command_preview": "",
                        "source_file": source_file,
                        "source_excerpt": str(item.get("source_excerpt", "") or ""),
                        "summary_line": int(item.get("line", 0) or 0),
                        "coverage_status": str(item.get("coverage_status", "") or "partial"),
                    },
                    "evidence_slice": EvidenceSlice(
                        kind="path_witness",
                        anchor=EvidenceAnchor(
                            patch_file=str(item.get("patch_file", "") or ""),
                            hunk_index=int(item.get("hunk_index", 0) or 0),
                            source_line=int(item.get("line", 0) or 0),
                        ),
                        summary=summary,
                        statements=list(item.get("statements", []) or [])[:6],
                        guards=[guard],
                        call_boundary=call_targets[:4],
                        call_edges=list(item.get("call_edges", []) or [])[:6],
                        state_transitions=state_after,
                        api_terms=(sink_calls[:3] or added_calls[:3] or removed_calls[:2]),
                        related_symbols=tracked_symbols[:6],
                        verifier="patch-diff",
                        extraction_method="patch_hunk_contracts",
                        coverage_status=str(item.get("coverage_status", "") or "partial"),
                    ),
                })
        if records:
            return records

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

    def _load_validation_findings(
        self,
        context: AnalyzerContext,
        source_contexts: List[SourceArtifactContext],
    ) -> List[Dict[str, Any]]:
        """Load existing CSA validation diagnostics for patch-touched files."""
        result_path = Path(context.output_dir or ".").resolve() / "result.json"
        if not result_path.exists():
            return []

        try:
            payload = json.loads(result_path.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            return []

        validation = payload.get("validation", {}) or {}
        diagnostics = validation.get("diagnostics", []) or []
        if not isinstance(diagnostics, list):
            return []

        source_by_resolved = {
            str(Path(item.resolved_file).resolve()): item
            for item in source_contexts
            if item.resolved_file
        }
        source_by_relative = {
            str(item.relative_file or item.patch_file or ""): item
            for item in source_contexts
            if str(item.relative_file or item.patch_file or "")
        }
        checker_name = str(payload.get("checker_name", "") or "")

        findings: List[Dict[str, Any]] = []
        for diagnostic in diagnostics:
            if not isinstance(diagnostic, dict):
                continue
            raw_file = str(diagnostic.get("file_path", "") or "")
            if not raw_file:
                continue

            resolved_file = str(Path(raw_file).expanduser().resolve())
            source_item = source_by_resolved.get(resolved_file)
            if source_item is None:
                source_item = source_by_relative.get(raw_file)
            if source_item is None:
                continue

            findings.append({
                "source_file": source_item.relative_file,
                "resolved_file": source_item.resolved_file,
                "line": int(diagnostic.get("line", 0) or 0),
                "column": int(diagnostic.get("column", 0) or 0),
                "severity": str(diagnostic.get("severity", "") or ""),
                "message": str(diagnostic.get("message", "") or ""),
                "source": str(diagnostic.get("source", "") or "csa"),
                "checker": str(diagnostic.get("checker", "") or diagnostic.get("check_name", "") or checker_name),
                "context": source_item,
            })

        return sorted(
            findings,
            key=lambda item: (
                str(item.get("source_file", "")),
                int(item.get("line", 0) or 0),
                str(item.get("message", "")),
            ),
        )[:24]

    def _validation_backed_records(
        self,
        *,
        context: AnalyzerContext,
        missing_evidence: List[str],
        source_contexts: List[SourceArtifactContext],
        runtime_artifacts: Dict[str, object],
        patch_contracts: List[Dict[str, Any]],
        validation_findings: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        if not missing_evidence:
            return []
        if not validation_findings and not source_contexts and not patch_contracts:
            return []

        records: List[Dict[str, Any]] = []
        for evidence_type in self._dedupe(missing_evidence):
            finding = self._best_validation_finding(evidence_type, validation_findings, source_contexts)
            source_item = self._source_item_for_finding(finding, source_contexts)
            patch_contract = self._best_patch_contract_for_item(source_item, patch_contracts)
            runtime = self._match_runtime_snapshot(source_item, runtime_artifacts) if source_item is not None else None
            recovered = self._record_from_validation_context(
                evidence_type=evidence_type,
                finding=finding,
                source_item=source_item,
                runtime=runtime,
                patch_contract=patch_contract,
                context=context,
            )
            if recovered is not None:
                records.append(recovered)
        return records

    def _best_validation_finding(
        self,
        evidence_type: str,
        validation_findings: List[Dict[str, Any]],
        source_contexts: List[SourceArtifactContext],
    ) -> Optional[Dict[str, Any]]:
        if not validation_findings:
            return None

        lifecycle_terms = (
            "free",
            "delete",
            "double",
            "use after",
            "null",
            "dereference",
            "leak",
            "released",
            "dead store",
        )
        guard_terms = ("bound", "overflow", "out of", "null", "dereference", "warning")

        def score(item: Dict[str, Any]) -> int:
            message = str(item.get("message", "") or "").lower()
            value = 0
            if evidence_type == "allocation_lifecycle" and any(term in message for term in lifecycle_terms):
                value += 10
            if evidence_type in {"path_guard", "state_transition"} and any(term in message for term in guard_terms):
                value += 6
            if source_contexts:
                line = int(item.get("line", 0) or 0)
                ctx = self._source_item_for_finding(item, source_contexts)
                if ctx is not None and int(ctx.function_start_line or 0) <= line <= int(ctx.function_end_line or line):
                    value += 3
            return value

        return max(validation_findings, key=score)

    def _source_item_for_finding(
        self,
        finding: Optional[Dict[str, Any]],
        source_contexts: List[SourceArtifactContext],
    ) -> Optional[SourceArtifactContext]:
        if finding is None:
            return source_contexts[0] if source_contexts else None

        source_file = str(finding.get("source_file", "") or "")
        line = int(finding.get("line", 0) or 0)
        same_file = [
            item for item in source_contexts
            if str(item.relative_file or item.patch_file or "") == source_file
        ]
        if not same_file:
            return source_contexts[0] if source_contexts else None

        containing = [
            item for item in same_file
            if int(item.function_start_line or 0) > 0
            and int(item.function_start_line or 0) <= line <= int(item.function_end_line or line)
        ]
        if containing:
            return min(containing, key=lambda item: abs(int(item.anchor_line or 0) - line))
        return min(same_file, key=lambda item: abs(int(item.anchor_line or 0) - line))

    def _best_patch_contract_for_item(
        self,
        source_item: Optional[SourceArtifactContext],
        patch_contracts: List[Dict[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        if not patch_contracts:
            return None
        if source_item is None:
            return patch_contracts[0]
        same_file = [
            item for item in patch_contracts
            if str(item.get("source_file", "") or "") in {source_item.relative_file, source_item.patch_file}
        ]
        if not same_file:
            return patch_contracts[0]
        if source_item.function_name:
            same_function = [
                item for item in same_file
                if str(item.get("function", "") or "") == source_item.function_name
            ]
            if same_function:
                return same_function[0]
        return same_file[0]

    def _record_from_validation_context(
        self,
        *,
        evidence_type: str,
        finding: Optional[Dict[str, Any]],
        source_item: Optional[SourceArtifactContext],
        runtime: Optional[Dict[str, object]],
        patch_contract: Optional[Dict[str, Any]],
        context: AnalyzerContext,
    ) -> Optional[Dict[str, Any]]:
        if source_item is None and patch_contract is None and finding is None:
            return None

        source_file = str(
            (finding or {}).get("source_file", "")
            or (source_item.relative_file if source_item else "")
            or (patch_contract or {}).get("source_file", "")
            or self._primary_file(context)
        )
        line = int(
            (finding or {}).get("line", 0)
            or (source_item.anchor_line if source_item else 0)
            or (patch_contract or {}).get("line", 0)
            or 0
        )
        column = int((finding or {}).get("column", 0) or 0)
        function_name = str(
            (source_item.function_name if source_item else "")
            or (patch_contract or {}).get("function", "")
            or self._primary_function(context)
        )
        diagnostic_message = str((finding or {}).get("message", "") or "")
        checker = str((finding or {}).get("checker", "") or "")
        source_excerpt = str(
            (source_item.source_excerpt if source_item else "")
            or (patch_contract or {}).get("source_excerpt", "")
        )
        guards = self._dedupe(
            list((source_item.guard_exprs if source_item else []) or [])
            + list((patch_contract or {}).get("guards", []) or [])
            + list((runtime or {}).get("branch_conditions", []) or [])
        )[:6]
        call_targets = self._dedupe(
            list((source_item.call_targets if source_item else []) or [])
            + list((patch_contract or {}).get("sink_calls", []) or [])
            + list((patch_contract or {}).get("added_calls", []) or [])
            + list((patch_contract or {}).get("removed_calls", []) or [])
            + list((runtime or {}).get("call_targets", []) or [])
        )[:8]
        tracked_symbols = self._dedupe(
            list((source_item.parameters if source_item else []) or [])
            + list((source_item.globals if source_item else []) or [])
            + list((patch_contract or {}).get("symbols", []) or [])
            + list((patch_contract or {}).get("widened_variables", []) or [])
        )[:8]
        state_statements = self._dedupe(
            list((source_item.state_ops if source_item else []) or [])
            + list((patch_contract or {}).get("state_resets", []) or [])
            + list((patch_contract or {}).get("arithmetic_operations", []) or [])
            + list((runtime or {}).get("state_statements", []) or [])
        )[:8]
        operations = self._dedupe(
            list((source_item.memory_ops if source_item else []) or [])
            + [call for call in call_targets if self._is_lifecycle_hint(call)]
            + state_statements
        )[:8]

        if evidence_type == "path_guard":
            summary = (
                f"CSA validation reaches {source_file}:{line}"
                + (f" in {function_name}" if function_name else "")
                + (f" with guards {', '.join(guards[:2])}" if guards else " with patch-local control context")
            )
            state_after = self._dedupe(
                [f"guard({guard})" for guard in guards[:2]]
                + [f"diagnostic({diagnostic_message})" if diagnostic_message else "diagnostic(csa)"]
            )[:6]
            kind = "path_witness"
            payload_extra = {
                "guard_expr": guards[0] if guards else "",
                "cfg_branch_kinds": list((runtime or {}).get("branch_kinds", []) or [])[:4],
                "branch_conditions": guards[:4],
            }
        elif evidence_type == "semantic_slice":
            summary = (
                f"CSA validation diagnostic anchors the patch-local semantic slice at {source_file}:{line}"
            )
            state_after = [f"diagnostic({diagnostic_message})"] if diagnostic_message else ["diagnostic(csa)"]
            kind = "semantic_slice"
            payload_extra = {
                "contract_type": str((patch_contract or {}).get("contract_type", "") or ""),
                "guard_exprs": guards[:4],
                "sink_calls": call_targets[:4],
            }
        elif evidence_type == "state_transition":
            summary = (
                f"{function_name or 'scope'} in {source_file} has CSA-observed state near line {line}"
            )
            state_after = self._dedupe(
                [f"transition({entry})" for entry in state_statements[:3]]
                + [f"call({call})" for call in call_targets[:2]]
                + ([f"diagnostic({diagnostic_message})"] if diagnostic_message else [])
            )[:6]
            kind = "state_witness"
            payload_extra = {
                "cfg_branch_kinds": list((runtime or {}).get("branch_kinds", []) or [])[:4],
                "branch_conditions": guards[:4],
            }
        elif evidence_type == "allocation_lifecycle":
            summary = (
                f"{function_name or 'scope'} in {source_file} provides CSA-backed pointer/resource lifecycle context near line {line}"
            )
            state_after = self._dedupe(
                [f"operation({entry})" for entry in operations[:4]]
                + ([f"diagnostic({diagnostic_message})"] if diagnostic_message else [])
            )[:6]
            kind = "lifecycle_witness"
            payload_extra = {
                "operations": operations[:6],
                "acquisition_ops": [op for op in operations if self._is_lifecycle_acquire(op)][:4],
                "release_ops": [op for op in operations if self._is_lifecycle_release(op)][:4],
            }
        else:
            return None

        state_before = []
        if source_item is not None:
            state_before = self._state_before(source_item, runtime)
        if not state_before:
            state_before = self._dedupe(
                [f"input({symbol})" for symbol in tracked_symbols[:3]]
                + [f"call({call})" for call in call_targets[:2]]
            )[:6]

        payload = {
            "reason": "Recovered from existing CSA validation diagnostics without rerunning patch planning.",
            "summary": summary,
            "diagnostic_message": diagnostic_message,
            "diagnostic_checker": checker,
            "state_before": state_before,
            "state_after": state_after,
            "functions": [function_name] if function_name else [],
            "globals": list((source_item.globals if source_item else []) or [])[:5],
            "tracked_symbols": tracked_symbols[:6],
            "buffer_fields": self._buffer_fields(source_item, runtime) if source_item is not None else [],
            "call_targets": call_targets[:6],
            "call_edges": list((runtime or {}).get("call_edges", []) or [])[:6],
            "state_statements": state_statements[:6],
            "source_file": source_file,
            "source_excerpt": source_excerpt,
            "coverage_status": "full" if finding is not None else "partial",
            **payload_extra,
        }

        return {
            "evidence_type": evidence_type,
            "line": line,
            "column": column,
            "artifact": "csa-validation:result-json",
            "confidence": 0.86 if finding is not None else 0.72,
            "payload": payload,
            "evidence_slice": EvidenceSlice(
                kind=kind,
                anchor=EvidenceAnchor(
                    patch_file=source_file,
                    hunk_index=int((patch_contract or {}).get("hunk_index", 0) or (source_item.hunk_index if source_item else 0) or 0),
                    source_line=line,
                ),
                summary=summary,
                statements=[
                    entry.strip()
                    for entry in source_excerpt.splitlines()
                    if entry.strip()
                ][:6],
                guards=guards[:4],
                call_boundary=call_targets[:6],
                call_edges=list((runtime or {}).get("call_edges", []) or [])[:6],
                state_transitions=state_after,
                api_terms=self._dedupe(operations + call_targets)[:6],
                related_symbols=tracked_symbols[:6],
                verifier="csa-validation",
                extraction_method="existing_result_json+source_window",
                coverage_status="full" if finding is not None else "partial",
            ),
        }

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
                "widened_variables": list(item.get("widened_variables", []) or [])[:8],
                "state_resets": list(item.get("state_resets", []) or [])[:6],
                "old_numeric_type": str(item.get("old_numeric_type", "") or ""),
                "new_numeric_type": str(item.get("new_numeric_type", "") or ""),
                "numeric_domain_change": str(item.get("numeric_domain_change", "") or ""),
                "arithmetic_operations": list(item.get("arithmetic_operations", []) or [])[:6],
                "sink_calls": list(item.get("sink_calls", []) or [])[:4],
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
                    call_boundary=list(item.get("sink_calls", []) or item.get("added_calls", []) or [])[:4],
                    call_edges=list(item.get("call_edges", []) or [])[:6],
                    state_transitions=[
                        str(item.get("numeric_domain_change", "") or ""),
                        str(item.get("trigger_contract", "") or ""),
                        str(item.get("silence_contract", "") or ""),
                        *[f"transition({reset})" for reset in (item.get("state_resets", []) or [])[:2]],
                    ],
                    api_terms=(
                        list(item.get("sink_calls", []) or [])[:3]
                        + list(item.get("added_calls", []) or [])[:3]
                        + list(item.get("removed_calls", []) or [])[:2]
                    ),
                    related_symbols=list(item.get("widened_variables", []) or item.get("symbols", []) or [])[:6],
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
                segments = self._split_hunk_contract_segments(
                    source_contexts=source_contexts,
                    patch_file=patch_path,
                    hunk_index=hunk_index,
                    hunk=hunk,
                )
                for segment in segments:
                    removed_lines = list(segment.get("removed_lines", []) or [])
                    added_lines = list(segment.get("added_lines", []) or [])
                    removed_calls = self._extract_patch_calls(removed_lines)
                    added_calls = self._extract_patch_calls(added_lines)
                    guards = self._extract_patch_guards(added_lines)
                    widenings = self._extract_type_widenings(removed_lines, added_lines)
                    state_resets = self._extract_state_resets(added_lines)

                    source_item = segment.get("source_context")
                    if not source_item:
                        source_item = self._match_hunk_context(
                            source_contexts,
                            patch_path,
                            int(segment.get("anchor_line", 0) or hunk.get("old_start", 0) or hunk.get("new_start", 0) or 0),
                            hunk_index=hunk_index,
                            preferred_calls=removed_calls + added_calls,
                            preferred_guards=guards,
                        )
                    function_name = str(source_item.function_name if source_item else "")
                    source_excerpt = str(source_item.source_excerpt if source_item else "")
                    source_file = str(source_item.relative_file if source_item else patch_path)
                    context_sink_calls = self._context_sink_calls(source_item, function_name)
                    widened_variables = self._dedupe(
                        [
                            str(var).strip()
                            for item in widenings
                            for var in (item.get("variables", []) or [])
                            if str(var).strip()
                        ]
                    )[:8]
                    symbols = self._interesting_tokens("\n".join(guards + added_lines + state_resets)) + widened_variables
                    symbols = self._dedupe(symbols)[:8]
                    arithmetic_operations = self._arithmetic_operations(source_excerpt, widened_variables)
                    sink_calls = self._sink_calls(source_excerpt, widened_variables)
                    if not sink_calls:
                        sink_calls = context_sink_calls[:4]
                    statements = (
                        [line.strip() for line in added_lines if str(line).strip()]
                        + arithmetic_operations
                    )[:6]
                    buffer_fields = self._dedupe(re.findall(r"[A-Za-z_]\w*->\w+", "\n".join(guards + added_lines + state_resets)))[:6]
                    contract_type = ""
                    trigger_contract = ""
                    silence_contract = ""
                    same_call_binding = ""
                    numeric_domain_change = ""

                    if not removed_calls and not added_calls and not guards and not widenings and not state_resets:
                        continue

                    if widenings:
                        contract_type = "counter_widening_barrier"
                        numeric_domain_change = self._numeric_domain_change(widenings)
                        trigger_contract = "report when size or escape-count arithmetic stays in the narrow integer domain before the downstream sizing or allocation sink"
                        silence_contract = "stay silent when the same accumulator chain is widened before the sink consumes the derived size"
                        same_call_binding = "bind widened variables to the same accumulator updates and the same downstream sink argument"
                    elif state_resets and not guards:
                        contract_type = "state_reset_barrier"
                        trigger_contract = "report when released or invalidated state remains reachable through the stale field or handle"
                        silence_contract = "stay silent when the same stale handle is cleared to a sentinel before later consumers run"
                        same_call_binding = "bind the invalidation writeback to the same released object field or handle"
                    elif "snprintf" in (added_calls + sink_calls) and self._has_checked_format_barrier(added_lines, guards):
                        contract_type = "checked_format_barrier"
                        trigger_contract = "report only when formatting/build logic lacks a checked bounded API barrier"
                        silence_contract = "stay silent when snprintf return value is checked against the same output capacity before control continues"
                        same_call_binding = "bind the checked return value and capacity parameter to the same output buffer call"
                    elif (
                        any(api in self.BUFFER_RISKY_APIS for api in removed_calls)
                        and any(api in self.BOUNDED_WRITE_APIS for api in added_calls)
                        and any(self._looks_like_bounds_guard(expr) for expr in guards)
                    ):
                        contract_type = "bounded_write_barrier"
                        trigger_contract = "report only when the write lacks a matching length/capacity barrier"
                        silence_contract = "stay silent when the same size carrier is compared against destination capacity before the current bounded write"
                        same_call_binding = "bind guard operands to the same destination field/parameter and the same size carrier used by the current write"
                    elif guards and (removed_calls or added_calls or sink_calls):
                        contract_type = "patch_barrier"
                        trigger_contract = "report when a risky write proceeds without the patch-style barrier"
                        silence_contract = "stay silent when the nearby guard proves the current write is blocked or bounded"
                        same_call_binding = "tie the guard to the current downstream sink or protected state transition instead of any unrelated if-statement"

                    if not contract_type:
                        continue

                    if contract_type == "checked_format_barrier":
                        sink_calls = self._dedupe(
                            [call for call in added_calls if call == "snprintf"]
                            + sink_calls
                        )[:4]

                    summary = self._contract_summary(
                        function_name=function_name,
                        source_file=source_file,
                        contract_type=contract_type,
                        guards=guards,
                        removed_calls=removed_calls,
                        added_calls=added_calls,
                        sink_calls=sink_calls,
                        state_resets=state_resets,
                    )
                    call_edge_terms = (
                        sink_calls[:3]
                        or context_sink_calls[:3]
                        or added_calls[:3]
                        or (source_item.call_targets[:3] if source_item and contract_type == "state_reset_barrier" else [])
                    )
                    contracts.append({
                        "patch_file": patch_path,
                        "hunk_index": hunk_index,
                        "line": int(segment.get("anchor_line", 0) or hunk.get("new_start", 0) or hunk.get("old_start", 0) or 0),
                        "function": function_name,
                        "source_file": source_file,
                        "source_excerpt": source_excerpt,
                        "summary": summary,
                        "contract_type": contract_type,
                        "guards": guards[:4],
                        "removed_calls": removed_calls[:6],
                        "added_calls": added_calls[:6],
                        "symbols": symbols[:8],
                        "widened_variables": widened_variables[:8],
                        "state_resets": state_resets[:6],
                        "old_numeric_type": str(widenings[0].get("old_type", "") if widenings else ""),
                        "new_numeric_type": str(widenings[0].get("new_type", "") if widenings else ""),
                        "numeric_domain_change": numeric_domain_change,
                        "arithmetic_operations": arithmetic_operations[:6],
                        "sink_calls": sink_calls[:4],
                        "buffer_fields": buffer_fields,
                        "statements": statements,
                        "call_edges": [
                            f"{function_name} -> {api}"
                            for api in call_edge_terms
                        ] if function_name else [],
                        "trigger_contract": trigger_contract,
                        "silence_contract": silence_contract,
                        "same_call_binding": same_call_binding,
                        "coverage_status": "full" if widenings or guards or state_resets else "partial",
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

    def _context_sink_calls(
        self,
        source_item: Optional[SourceArtifactContext],
        function_name: str,
    ) -> List[str]:
        if source_item is None:
            return []
        function_name = str(function_name or "").strip()
        calls = [
            str(token).strip()
            for token in (source_item.call_targets or [])
            if str(token).strip() and str(token).strip() != function_name
        ]
        return self._dedupe(calls)[:6]

    def _split_hunk_contract_segments(
        self,
        *,
        source_contexts: List[SourceArtifactContext],
        patch_file: str,
        hunk_index: int,
        hunk: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        ordered_lines = list(hunk.get("ordered_lines", []) or [])
        if not ordered_lines:
            return []

        candidates = [
            item
            for item in source_contexts
            if item.relative_file == patch_file or item.patch_file == patch_file
        ]
        same_hunk = [
            item
            for item in candidates
            if int(item.hunk_index or 0) == int(hunk_index or 0)
        ]
        if same_hunk:
            candidates = same_hunk

        deduped_contexts: List[SourceArtifactContext] = []
        seen_contexts = set()
        for item in sorted(
            candidates,
            key=lambda ctx: (
                int(ctx.function_start_line or 0),
                int(ctx.anchor_line or 0),
                str(ctx.function_name or ""),
            ),
        ):
            key = (
                str(item.relative_file or item.patch_file or ""),
                str(item.function_name or ""),
                int(item.function_start_line or 0),
                int(item.function_end_line or 0),
                int(item.anchor_line or 0) if not item.function_name else 0,
            )
            if key in seen_contexts:
                continue
            seen_contexts.add(key)
            deduped_contexts.append(item)

        segments: List[Dict[str, Any]] = []
        segment_by_key: Dict[str, Dict[str, Any]] = {}
        fallback_segment: Optional[Dict[str, Any]] = None

        def ensure_segment(
            source_item: Optional[SourceArtifactContext],
            anchor_line: int,
        ) -> Dict[str, Any]:
            nonlocal fallback_segment
            if source_item is None:
                if fallback_segment is None:
                    fallback_segment = {
                        "source_context": None,
                        "anchor_line": int(anchor_line or hunk.get("new_start", 0) or hunk.get("old_start", 0) or 0),
                        "removed_lines": [],
                        "added_lines": [],
                        "context_lines": [],
                    }
                    segments.append(fallback_segment)
                elif anchor_line and not int(fallback_segment.get("anchor_line", 0) or 0):
                    fallback_segment["anchor_line"] = int(anchor_line)
                return fallback_segment

            segment_key = self._segment_key(source_item)
            segment = segment_by_key.get(segment_key)
            if segment is None:
                segment = {
                    "source_context": source_item,
                    "anchor_line": int(anchor_line or source_item.anchor_line or source_item.function_start_line or 0),
                    "removed_lines": [],
                    "added_lines": [],
                    "context_lines": [],
                }
                segment_by_key[segment_key] = segment
                segments.append(segment)
            elif anchor_line and not int(segment.get("anchor_line", 0) or 0):
                segment["anchor_line"] = int(anchor_line)
            return segment

        old_cursor = int(hunk.get("old_start", 0) or 0)
        new_cursor = int(hunk.get("new_start", 0) or 0)
        current_context: Optional[SourceArtifactContext] = None

        for entry in ordered_lines:
            kind = str((entry or {}).get("kind", "") or "")
            text = str((entry or {}).get("text", "") or "")
            if kind not in {"context", "removed", "added"}:
                continue

            if kind == "removed":
                primary_line = old_cursor
                secondary_line = new_cursor
            elif kind == "added":
                primary_line = new_cursor
                secondary_line = old_cursor
            else:
                primary_line = old_cursor or new_cursor
                secondary_line = new_cursor or old_cursor

            resolved_context = self._resolve_segment_context(
                deduped_contexts,
                kind=kind,
                primary_line=primary_line,
                secondary_line=secondary_line,
                current_context=current_context,
                text=text,
            )
            segment = ensure_segment(resolved_context, primary_line or secondary_line)
            if resolved_context is not None:
                current_context = resolved_context

            if kind == "removed":
                segment["removed_lines"].append(text)
                if text.strip() and not int(segment.get("anchor_line", 0) or 0):
                    segment["anchor_line"] = int(primary_line or secondary_line or 0)
            elif kind == "added":
                segment["added_lines"].append(text)
                if text.strip() and not int(segment.get("anchor_line", 0) or 0):
                    segment["anchor_line"] = int(primary_line or secondary_line or 0)
            else:
                segment["context_lines"].append(text)

            if kind in {"context", "removed"}:
                old_cursor += 1
            if kind in {"context", "added"}:
                new_cursor += 1

        changed_segments = [
            item
            for item in segments
            if list(item.get("removed_lines", []) or []) or list(item.get("added_lines", []) or [])
        ]
        if changed_segments:
            return changed_segments

        return [{
            "source_context": None,
            "anchor_line": int(hunk.get("new_start", 0) or hunk.get("old_start", 0) or 0),
            "removed_lines": list(hunk.get("removed_lines", []) or []),
            "added_lines": list(hunk.get("added_lines", []) or []),
            "context_lines": list(hunk.get("context_lines", []) or []),
        }]

    def _segment_key(self, item: SourceArtifactContext) -> str:
        scope_start = int(item.function_start_line or 0)
        scope_end = int(item.function_end_line or 0)
        anchor = int(item.anchor_line or 0)
        function_name = str(item.function_name or "")
        relative_file = str(item.relative_file or item.patch_file or "")
        if function_name:
            return f"{relative_file}:{function_name}:{scope_start}:{scope_end}"
        return f"{relative_file}:anchor:{anchor}"

    def _resolve_segment_context(
        self,
        candidates: List[SourceArtifactContext],
        *,
        kind: str,
        primary_line: int,
        secondary_line: int,
        current_context: Optional[SourceArtifactContext],
        text: str,
    ) -> Optional[SourceArtifactContext]:
        if not candidates:
            return None

        signature_context = self._context_for_signature_text(candidates, text)
        if signature_context is not None:
            return signature_context

        if kind == "added" and current_context is not None:
            return current_context

        for line in (primary_line, secondary_line):
            resolved = self._context_for_line(candidates, int(line or 0))
            if resolved is not None:
                return resolved

        if current_context is not None:
            return current_context
        if len(candidates) == 1:
            return candidates[0]

        hint_tokens = set(self._interesting_tokens(text))
        anchor_line = int(primary_line or secondary_line or 0)
        return max(
            candidates,
            key=lambda item: (
                len(hint_tokens.intersection(
                    set(item.call_targets)
                    | set(item.parameters)
                    | {str(item.function_name or "")}
                )),
                -abs(int(item.anchor_line or 0) - anchor_line),
                int(item.anchor_line or 0),
            ),
        )

    def _context_for_signature_text(
        self,
        candidates: List[SourceArtifactContext],
        text: str,
    ) -> Optional[SourceArtifactContext]:
        stripped = str(text or "").strip()
        if not stripped:
            return None

        match = ProjectArtifactExtractor.FUNCTION_PATTERN.match(stripped)
        if not match:
            match = ProjectArtifactExtractor.MULTILINE_FUNCTION_START_PATTERN.match(stripped)
        if not match:
            return None

        function_name = str(match.group(1) or "").strip()
        if not function_name:
            return None

        matches = [
            item
            for item in candidates
            if str(item.function_name or "").strip() == function_name
        ]
        if not matches:
            return None
        return min(
            matches,
            key=lambda item: (
                int(item.function_start_line or 0) or int(item.anchor_line or 0),
                int(item.anchor_line or 0),
            ),
        )

    def _context_for_line(
        self,
        candidates: List[SourceArtifactContext],
        line: int,
    ) -> Optional[SourceArtifactContext]:
        if line <= 0:
            return None

        containing = [
            item
            for item in candidates
            if int(item.function_start_line or 0) > 0
            and int(item.function_end_line or 0) >= line
            and int(item.function_start_line or 0) <= line
        ]
        if containing:
            return min(
                containing,
                key=lambda item: (
                    max(int(item.function_end_line or line) - int(item.function_start_line or line), 0),
                    abs(int(item.anchor_line or 0) - line),
                    int(item.anchor_line or 0),
                ),
            )

        same_or_next = [
            item
            for item in candidates
            if int(item.function_start_line or 0) >= line
        ]
        if same_or_next:
            return min(
                same_or_next,
                key=lambda item: (
                    abs(int(item.function_start_line or 0) - line),
                    abs(int(item.anchor_line or 0) - line),
                ),
            )

        return min(
            candidates,
            key=lambda item: abs(int(item.anchor_line or 0) - line),
        )

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

    def _extract_state_resets(self, lines: List[str]) -> List[str]:
        resets: List[str] = []
        for line in lines:
            stripped = str(line or "").strip()
            if not stripped or stripped.startswith("#"):
                continue
            match = re.match(r"^(?P<lhs>[^=]+?)\s*=\s*(?P<rhs>[^;]+);$", stripped)
            if not match:
                continue
            lhs = re.sub(r"\s+", "", str(match.group("lhs") or ""))
            rhs = str(match.group("rhs") or "").strip()
            if not self._looks_like_state_slot(lhs):
                continue
            if not self._looks_like_reset_value(rhs):
                continue
            resets.append(f"{lhs} = {rhs}")
        return self._dedupe(resets)[:6]

    def _looks_like_state_slot(self, lhs: str) -> bool:
        normalized = str(lhs or "").strip()
        if not normalized:
            return False
        if "->" in normalized or "." in normalized:
            return True
        lowered = normalized.lower()
        return lowered.endswith((
            "id",
            "idx",
            "state",
            "status",
            "handle",
            "ptr",
            "ref",
            "flag",
            "valid",
        ))

    def _looks_like_reset_value(self, rhs: str) -> bool:
        normalized = str(rhs or "").strip()
        lowered = normalized.lower()
        if lowered in {"null", "nullptr", "0", "-1", "false"}:
            return True
        return lowered.startswith("invalid")

    def _extract_type_widenings(
        self,
        removed_lines: List[str],
        added_lines: List[str],
    ) -> List[Dict[str, Any]]:
        pattern = re.compile(
            r"^\s*(?P<type>(?:const\s+|volatile\s+|signed\s+|unsigned\s+)*[A-Za-z_]\w*(?:\s+[A-Za-z_]\w*)*)\s+(?P<vars>[^;=]+);\s*$"
        )
        removed_decls = [item for item in (self._parse_decl(pattern, line) for line in removed_lines) if item]
        added_decls = [item for item in (self._parse_decl(pattern, line) for line in added_lines) if item]
        widened: List[Dict[str, Any]] = []
        seen = set()
        for old_type, old_vars in removed_decls:
            for new_type, new_vars in added_decls:
                shared = [var for var in old_vars if var in new_vars]
                if not shared or self._type_rank(new_type) <= self._type_rank(old_type):
                    continue
                key = (old_type, new_type, tuple(shared))
                if key in seen:
                    continue
                seen.add(key)
                widened.append({
                    "old_type": old_type,
                    "new_type": new_type,
                    "variables": shared[:8],
                })
        return widened[:4]

    def _parse_decl(
        self,
        pattern: re.Pattern[str],
        line: str,
    ) -> Optional[tuple[str, List[str]]]:
        stripped = str(line or "").strip()
        if not stripped or "(" in stripped or ")" in stripped or "=" in stripped:
            return None
        match = pattern.match(stripped)
        if not match:
            return None
        vars_found: List[str] = []
        for chunk in str(match.group("vars") or "").split(","):
            symbol_match = re.search(r"([A-Za-z_]\w*)$", chunk.strip())
            if symbol_match:
                vars_found.append(symbol_match.group(1))
        if not vars_found:
            return None
        return self._normalize_type(str(match.group("type") or "")), vars_found[:12]

    def _normalize_type(self, raw_type: str) -> str:
        lowered = " ".join(str(raw_type or "").strip().lower().split())
        aliases = {
            "sqlite3_int64": "i64",
            "sqlite_int64": "i64",
            "int64_t": "i64",
            "long long int": "long long",
        }
        return aliases.get(lowered, lowered)

    def _type_rank(self, raw_type: str) -> int:
        normalized = self._normalize_type(raw_type)
        if normalized in {"char", "short", "unsigned char", "unsigned short"}:
            return 1
        if normalized in {"int", "unsigned int", "long", "unsigned long"}:
            return 2
        if normalized in {"size_t", "ssize_t", "long long", "unsigned long long", "i64", "u64"}:
            return 3
        return 0

    def _numeric_domain_change(self, widenings: List[Dict[str, Any]]) -> str:
        if not widenings:
            return ""
        first = widenings[0]
        return f"counter_domain({first.get('old_type', '')} -> {first.get('new_type', '')})"

    def _arithmetic_operations(
        self,
        source_excerpt: str,
        variables: List[str],
    ) -> List[str]:
        if not variables:
            return []
        operations: List[str] = []
        for raw_line in (source_excerpt or "").splitlines():
            line = raw_line.strip()
            if not line:
                continue
            if not any(re.search(rf"\b{re.escape(var)}\b", line) for var in variables):
                continue
            if any(token in line for token in ("+=", "-=", "++", "--")) or ("=" in line and any(op in line for op in ("+", "-", "*", "/"))):
                operations.append(line)
        return self._dedupe(operations)[:6]

    def _sink_calls(
        self,
        source_excerpt: str,
        variables: List[str],
    ) -> List[str]:
        if not variables:
            return []
        sinks: List[str] = []
        for raw_line in (source_excerpt or "").splitlines():
            line = raw_line.strip()
            if not line or not any(re.search(rf"\b{re.escape(var)}\b", line) for var in variables):
                continue
            for match in re.findall(r"\b([A-Za-z_]\w*)\s*\(([^)]*)\)", line):
                callee, args = match
                if callee in self._CONTROL_TOKENS:
                    continue
                if any(re.search(rf"\b{re.escape(var)}\b", args) for var in variables):
                    sinks.append(callee)
        return self._dedupe(sinks)[:4]

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
        *,
        hunk_index: Optional[int] = None,
        preferred_calls: Optional[List[str]] = None,
        preferred_guards: Optional[List[str]] = None,
    ) -> Optional[SourceArtifactContext]:
        candidates = [
            item
            for item in source_contexts
            if item.relative_file == patch_file or item.patch_file == patch_file
        ]
        if not candidates:
            return None
        if hunk_index is not None:
            same_hunk = [
                item
                for item in candidates
                if int(item.hunk_index or 0) == int(hunk_index or 0)
            ]
            if same_hunk:
                candidates = same_hunk
        containing = [
            item
            for item in candidates
            if int(item.function_start_line or 0) > 0
            and int(item.function_end_line or 0) >= int(line or 0)
            and int(item.function_start_line or 0) <= int(line or 0)
        ]
        if containing:
            candidates = containing

        preferred_call_set = {
            str(token).strip()
            for token in (preferred_calls or [])
            if str(token).strip()
        }
        preferred_guard_tokens = {
            token
            for token in self._interesting_tokens("\n".join(preferred_guards or []))
            if token
        }
        return max(
            candidates,
            key=lambda item: (
                len(preferred_call_set.intersection(set(item.call_targets))),
                sum(
                    1
                    for guard in item.guard_exprs
                    if any(token in guard for token in preferred_guard_tokens)
                ),
                1 if item.function_name else 0,
                -abs(int(item.anchor_line or 0) - int(line or 0)),
                int(item.anchor_line or 0),
            ),
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
        sink_calls: Optional[List[str]] = None,
        state_resets: Optional[List[str]] = None,
    ) -> str:
        scope = function_name or source_file or "scope"
        state_resets = list(state_resets or [])
        sink_calls = list(sink_calls or [])
        if contract_type == "bounded_write_barrier":
            return (
                f"{scope} replaces {', '.join(removed_calls[:2]) or 'risky writes'} with "
                f"{', '.join(added_calls[:2]) or 'bounded writes'} and introduces guard "
                f"`{guards[0] if guards else 'unknown'}` that must stay bound to the same call."
            )
        if contract_type == "checked_format_barrier":
            return (
                f"{scope} switches to checked formatting via {', '.join((sink_calls or added_calls)[:1]) or 'bounded formatting'}; "
                f"return-value guard `{guards[0] if guards else 'unknown'}` is the patched silence condition."
            )
        if contract_type == "counter_widening_barrier":
            widened = ", ".join(added_calls[:2] or removed_calls[:2]) or "the downstream size sink"
            return (
                f"{scope} widens arithmetic carriers before {widened}; the detector should model narrow-counter accumulation "
                f"that reaches the same sizing or allocation sink without the widened numeric domain."
            )
        if contract_type == "state_reset_barrier":
            return (
                f"{scope} clears stale state via {', '.join(state_resets[:2]) or 'sentinel reset'} "
                "after the lifetime transition so later consumers cannot reuse the invalid handle."
            )
        return (
            f"{scope} adds patch barrier `{guards[0] if guards else 'unknown'}` around "
            f"{', '.join((sink_calls or added_calls or removed_calls)[:2]) or 'the affected sink'}."
        )

    def _state_records(
        self,
        source_contexts: List[SourceArtifactContext],
        runtime_artifacts: Dict[str, object],
        patch_contracts: List[Dict[str, Any]],
        reason: str,
    ) -> List[dict]:
        records: List[dict] = []
        seen = set()
        for item in patch_contracts:
            if item.get("contract_type") != "counter_widening_barrier":
                continue
            summary = str(item.get("summary", "") or "").strip()
            state_after = [
                str(item.get("numeric_domain_change", "") or "").strip(),
                *[f"transition({op})" for op in (item.get("arithmetic_operations", []) or [])[:2]],
                *[f"sink({call})" for call in (item.get("sink_calls", []) or [])[:2]],
            ]
            state_after = [entry for entry in state_after if entry]
            records.append({
                "line": int(item.get("line", 0) or 0),
                "artifact": "patch-diff:arithmetic-state",
                "confidence": 0.9,
                "payload": {
                    "reason": reason,
                    "summary": summary,
                    "state_before": [
                        (
                            f"counter_domain({item.get('old_numeric_type', '')})"
                            if str(item.get("old_numeric_type", "") or "").strip()
                            else "counter_domain(narrow)"
                        ),
                        *[f"input({symbol})" for symbol in (item.get("widened_variables", []) or [])[:2]],
                    ],
                    "state_after": state_after[:6],
                    "functions": [str(item.get("function", "") or "")] if str(item.get("function", "") or "").strip() else [],
                    "globals": [],
                    "tracked_symbols": list(item.get("widened_variables", []) or [])[:6],
                    "buffer_fields": list(item.get("buffer_fields", []) or [])[:4],
                    "call_targets": list(item.get("sink_calls", []) or [])[:4],
                    "call_edges": list(item.get("call_edges", []) or [])[:4],
                    "cfg_branch_kinds": [],
                    "branch_conditions": [],
                    "state_statements": list(item.get("arithmetic_operations", []) or [])[:6],
                    "return_statements": [],
                    "source_file": str(item.get("source_file", "") or ""),
                    "source_excerpt": str(item.get("source_excerpt", "") or ""),
                    "coverage_status": str(item.get("coverage_status", "") or "partial"),
                },
                "evidence_slice": EvidenceSlice(
                    kind="state_witness",
                    anchor=EvidenceAnchor(
                        patch_file=str(item.get("patch_file", "") or ""),
                        hunk_index=int(item.get("hunk_index", 0) or 0),
                        source_line=int(item.get("line", 0) or 0),
                    ),
                    summary=summary,
                    statements=list(item.get("arithmetic_operations", []) or [])[:6],
                    guards=[],
                    call_boundary=list(item.get("sink_calls", []) or [])[:4],
                    call_edges=list(item.get("call_edges", []) or [])[:4],
                    state_transitions=state_after[:6],
                    api_terms=list(item.get("sink_calls", []) or [])[:4],
                    related_symbols=list(item.get("widened_variables", []) or [])[:6],
                    verifier="patch-diff",
                    extraction_method="patch_hunk_contracts",
                    coverage_status=str(item.get("coverage_status", "") or "partial"),
                ),
            })

        for item in patch_contracts:
            if item.get("contract_type") != "state_reset_barrier":
                continue
            resets = [str(entry).strip() for entry in (item.get("state_resets", []) or []) if str(entry).strip()]
            if not resets:
                continue
            summary = str(item.get("summary", "") or "").strip()
            state_after = (
                [f"transition({entry})" for entry in resets[:3]]
                + [f"sink({call})" for call in (item.get("added_calls", []) or [])[:2]]
                + [f"call({edge})" for edge in (item.get("call_edges", []) or [])[:2]]
            )
            records.append({
                "line": int(item.get("line", 0) or 0),
                "artifact": "patch-diff:state-reset",
                "confidence": 0.9,
                "payload": {
                    "reason": reason,
                    "summary": summary,
                    "state_before": [
                        f"reachable({token})"
                        for token in list(item.get("buffer_fields", []) or [])[:2]
                    ] or ["reachable(stale_handle)"],
                    "state_after": state_after[:6],
                    "functions": [str(item.get("function", "") or "")] if str(item.get("function", "") or "").strip() else [],
                    "globals": [],
                    "tracked_symbols": list(item.get("symbols", []) or [])[:6],
                    "buffer_fields": list(item.get("buffer_fields", []) or [])[:4],
                    "call_targets": list(item.get("added_calls", []) or [])[:4],
                    "call_edges": list(item.get("call_edges", []) or [])[:4],
                    "cfg_branch_kinds": [],
                    "branch_conditions": list(item.get("guards", []) or [])[:4],
                    "state_statements": resets[:6],
                    "return_statements": [],
                    "source_file": str(item.get("source_file", "") or ""),
                    "source_excerpt": str(item.get("source_excerpt", "") or ""),
                    "coverage_status": str(item.get("coverage_status", "") or "partial"),
                },
                "evidence_slice": EvidenceSlice(
                    kind="state_witness",
                    anchor=EvidenceAnchor(
                        patch_file=str(item.get("patch_file", "") or ""),
                        hunk_index=int(item.get("hunk_index", 0) or 0),
                        source_line=int(item.get("line", 0) or 0),
                    ),
                    summary=summary,
                    statements=resets[:6],
                    guards=list(item.get("guards", []) or [])[:4],
                    call_boundary=list(item.get("added_calls", []) or [])[:4],
                    call_edges=list(item.get("call_edges", []) or [])[:4],
                    state_transitions=state_after[:6],
                    api_terms=list(item.get("added_calls", []) or [])[:4],
                    related_symbols=list(item.get("symbols", []) or [])[:6],
                    verifier="patch-diff",
                    extraction_method="patch_hunk_contracts",
                    coverage_status=str(item.get("coverage_status", "") or "partial"),
                ),
            })

        for item in patch_contracts:
            if str(item.get("contract_type", "") or "") not in {
                "bounded_write_barrier",
                "checked_format_barrier",
                "patch_barrier",
            }:
                continue
            guards = [str(guard).strip() for guard in (item.get("guards", []) or []) if str(guard).strip()]
            if not guards:
                continue
            summary = str(item.get("summary", "") or "").strip()
            tracked_symbols = [str(symbol).strip() for symbol in (item.get("symbols", []) or []) if str(symbol).strip()]
            buffer_fields = [str(field).strip() for field in (item.get("buffer_fields", []) or []) if str(field).strip()]
            removed_calls = [str(call).strip() for call in (item.get("removed_calls", []) or []) if str(call).strip()]
            added_calls = [str(call).strip() for call in (item.get("added_calls", []) or []) if str(call).strip()]
            sink_calls = [str(call).strip() for call in (item.get("sink_calls", []) or []) if str(call).strip()]
            guard = guards[0]
            state_after = self._dedupe(
                [f"guard({guard})"]
                + [f"sink({call})" for call in (sink_calls[:2] or added_calls[:2])]
                + [f"replaces({call})" for call in removed_calls[:2]]
            )[:6]
            records.append({
                "line": int(item.get("line", 0) or 0),
                "artifact": "patch-diff:guarded-state",
                "confidence": 0.9,
                "payload": {
                    "reason": reason,
                    "summary": summary,
                    "state_before": self._dedupe(
                        [f"input({symbol})" for symbol in tracked_symbols[:2]]
                        + [f"buffer({field})" for field in buffer_fields[:2]]
                        + [f"risky({call})" for call in removed_calls[:2]]
                    )[:6],
                    "state_after": state_after,
                    "functions": [str(item.get("function", "") or "")] if str(item.get("function", "") or "").strip() else [],
                    "globals": [],
                    "tracked_symbols": tracked_symbols[:6],
                    "buffer_fields": buffer_fields[:4],
                    "call_targets": (sink_calls[:4] or added_calls[:4] or removed_calls[:4]),
                    "call_edges": list(item.get("call_edges", []) or [])[:4],
                    "cfg_branch_kinds": ["if"],
                    "branch_conditions": [guard],
                    "state_statements": list(item.get("statements", []) or [])[:6],
                    "return_statements": [],
                    "source_file": str(item.get("source_file", "") or ""),
                    "source_excerpt": str(item.get("source_excerpt", "") or ""),
                    "coverage_status": str(item.get("coverage_status", "") or "partial"),
                },
                "evidence_slice": EvidenceSlice(
                    kind="state_witness",
                    anchor=EvidenceAnchor(
                        patch_file=str(item.get("patch_file", "") or ""),
                        hunk_index=int(item.get("hunk_index", 0) or 0),
                        source_line=int(item.get("line", 0) or 0),
                    ),
                    summary=summary,
                    statements=list(item.get("statements", []) or [])[:6],
                    guards=[guard],
                    call_boundary=(sink_calls[:4] or added_calls[:4] or removed_calls[:4]),
                    call_edges=list(item.get("call_edges", []) or [])[:4],
                    state_transitions=state_after,
                    api_terms=(sink_calls[:3] or added_calls[:3] or removed_calls[:2]),
                    related_symbols=tracked_symbols[:6],
                    verifier="patch-diff",
                    extraction_method="patch_hunk_contracts",
                    coverage_status=str(item.get("coverage_status", "") or "partial"),
                ),
            })

        if records:
            return records

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
        patch_contracts: List[Dict[str, Any]],
        reason: str,
    ) -> Optional[dict]:
        if any(str(item.get("contract_type", "") or "") == "counter_widening_barrier" for item in patch_contracts):
            return None

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
            if not release_ops and not acquisition_ops:
                continue
            if len(operations) < 2 and not release_ops:
                continue
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
        if normalized in self.RESOURCE_LIFECYCLE_APIS:
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
            "spawn",
        ))

    def _match_runtime_snapshot(
        self,
        item: SourceArtifactContext,
        runtime_artifacts: Dict[str, object],
    ) -> Optional[Dict[str, object]]:
        snapshots = list(runtime_artifacts.get("cfg_snapshots", []) or [])
        matching = [
            snapshot
            for snapshot in snapshots
            if isinstance(snapshot, dict)
            and snapshot.get("source_file") == item.relative_file
            and snapshot.get("function_name") == item.function_name
        ]
        if matching:
            return min(
                matching,
                key=lambda snapshot: abs(int(snapshot.get("anchor_line", 0) or 0) - int(item.anchor_line or 0)),
            )
        if item.function_name:
            return None
        file_only = [
            snapshot
            for snapshot in snapshots
            if isinstance(snapshot, dict)
            and snapshot.get("source_file") == item.relative_file
        ]
        if not file_only:
            return None
        return min(
            file_only,
            key=lambda snapshot: abs(int(snapshot.get("anchor_line", 0) or 0) - int(item.anchor_line or 0)),
        )

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
