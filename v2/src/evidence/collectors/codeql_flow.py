"""
CodeQL-oriented evidence collection.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from ...core.analyzer_base import AnalyzerContext
from ...core.evidence_planner import PatchFactsExtractor
from ...core.evidence_schema import EvidenceAnchor, EvidenceBundle, EvidenceSlice
from .artifact_extractor import ProjectArtifactExtractor, SourceArtifactContext
from .base import EvidenceCollector
from .csa_path import CSAPathEvidenceCollector


class CodeQLFlowEvidenceCollector(EvidenceCollector):
    """Collect flow-oriented evidence hints for CodeQL synthesis."""

    analyzer_id = "codeql"
    supported_types = ["semantic_slice", "dataflow_candidate", "call_chain"]
    _CONTROL_TARGETS = frozenset({"if", "for", "while", "switch", "return", "sizeof"})
    _PSEUDO_CALLS = frozenset({"assert", "va_arg"})

    def collect(self, context: AnalyzerContext) -> EvidenceBundle:
        records = []
        missing_evidence: List[str] = []
        requirements = self._evidence_requirements(context)
        extractor = ProjectArtifactExtractor()
        source_contexts, artifact_meta = extractor.collect_source_contexts(context)
        project_info = artifact_meta.get("project_info", {}) or {}
        dependency_map = project_info.get("dependencies", {}) or {}
        runtime_artifacts = extractor.collect_codeql_runtime_artifacts(
            context=context,
            source_contexts=source_contexts,
            project_info=project_info,
        )

        for requirement in requirements:
            evidence_type = str(requirement.get("evidence_type", ""))
            if evidence_type == "dataflow_candidate":
                flow_candidate = self._dataflow_candidate(
                    context=context,
                    source_contexts=source_contexts,
                    runtime_artifacts=runtime_artifacts,
                )
                flow_focus_function = str(flow_candidate.get("focus_function", "") or self._focus_function(source_contexts, runtime_artifacts))
                satisfied = bool(flow_candidate.get("path"))
                records.append(self._record(
                    "codeql_flow_0",
                    "dataflow_candidate",
                    context,
                    {
                        "reason": requirement.get("reason", ""),
                        **flow_candidate,
                        "live_query_status": self._live_status(runtime_artifacts),
                        "database_status": "ready" if runtime_artifacts.get("database_exists") else "missing",
                        "database_create_message": runtime_artifacts.get("database_create_message", ""),
                        "coverage_status": "full" if satisfied else ("partial" if flow_candidate.get("summary") else "missing"),
                    },
                    artifact="codeql-db:live-inventory" if self._has_live_inventory(runtime_artifacts) else "source-window:data-flow-seed",
                    confidence=0.9 if self._has_live_inventory(runtime_artifacts) and satisfied else (0.84 if satisfied else 0.7),
                    file=self._focus_file(source_contexts, runtime_artifacts),
                    function=flow_focus_function,
                    evidence_slice=self._build_slice(
                        source_contexts=source_contexts,
                        runtime_artifacts=runtime_artifacts,
                        kind="flow_witness",
                        summary=str(flow_candidate.get("summary", "") or "No concrete flow candidate recovered."),
                        coverage_status="full" if satisfied else ("partial" if flow_candidate.get("summary") else "missing"),
                        call_boundary=[str(flow_candidate.get("sink", "") or "")] if str(flow_candidate.get("sink", "") or "").strip() else None,
                        call_edges=[str(item) for item in (flow_candidate.get("path", []) or []) if str(item).strip()],
                        api_terms=list(flow_candidate.get("call_targets", []) or [])[:6],
                        related_symbols=list(flow_candidate.get("entry_points", []) or [])[:6],
                        state_transitions=list(flow_candidate.get("state_transitions", []) or [])[:4],
                    ),
                ))
                if not satisfied:
                    missing_evidence.append("dataflow_candidate")

            elif evidence_type == "call_chain":
                chain_summary = self._call_chain_summary(context, source_contexts, dependency_map, runtime_artifacts)
                chain_edges = (
                    self._relevant_live_call_edges(context, source_contexts, runtime_artifacts)
                    or self._direct_call_edges(context, source_contexts)
                    or self._live_call_edges(runtime_artifacts)
                )
                chain_focus = self._focus_context(context, source_contexts)
                satisfied = bool(chain_edges)
                records.append(self._record(
                    "codeql_chain_0",
                    "call_chain",
                    context,
                    {
                        "reason": requirement.get("reason", ""),
                        "summary": chain_summary,
                        "call_edges": chain_edges[:8],
                        "live_query_status": self._live_status(runtime_artifacts),
                        "database_status": "ready" if runtime_artifacts.get("database_exists") else "missing",
                        "database_create_message": runtime_artifacts.get("database_create_message", ""),
                        "coverage_status": "full" if satisfied else ("partial" if chain_summary else "missing"),
                    },
                    artifact="codeql-db:call-edges" if self._has_live_inventory(runtime_artifacts) else "source-window:interprocedural-summary",
                    confidence=0.88 if self._has_live_inventory(runtime_artifacts) and chain_summary else (0.78 if chain_summary else 0.6),
                    file=self._focus_file(source_contexts, runtime_artifacts),
                    function=str(chain_focus.function_name if chain_focus else self._focus_function(source_contexts, runtime_artifacts)),
                    evidence_slice=self._build_slice(
                        source_contexts=source_contexts,
                        runtime_artifacts=runtime_artifacts,
                        kind="interprocedural_slice",
                        summary=", ".join(chain_summary[:4]) if chain_summary else "No interprocedural chain recovered.",
                        coverage_status="full" if satisfied else ("partial" if chain_summary else "missing"),
                        call_boundary=self._call_targets(context, source_contexts, runtime_artifacts),
                        call_edges=chain_edges,
                    ),
                ))
                if not satisfied:
                    missing_evidence.append("call_chain")

            elif evidence_type == "semantic_slice":
                semantic_summary = self._semantic_slice_summary(
                    context=context,
                    source_contexts=source_contexts,
                    dependency_map=dependency_map,
                    runtime_artifacts=runtime_artifacts,
                )
                semantic_focus_function = str(semantic_summary.get("focus_function", "") or self._focus_function(source_contexts, runtime_artifacts))
                has_semantic_slice = bool(semantic_summary.get("summary")) and (
                    bool(source_contexts) or bool(self._live_call_edges(runtime_artifacts))
                )
                records.append(self._record(
                    "codeql_semantic_slice_0",
                    "semantic_slice",
                    context,
                    semantic_summary,
                    artifact="codeql-db:semantic-slice" if self._has_live_inventory(runtime_artifacts) else "source-window:semantic-slice",
                    confidence=0.9 if self._has_live_inventory(runtime_artifacts) and has_semantic_slice else (0.8 if has_semantic_slice else 0.62),
                    file=self._focus_file(source_contexts, runtime_artifacts),
                    function=semantic_focus_function,
                    evidence_slice=self._build_slice(
                        source_contexts=source_contexts,
                        runtime_artifacts=runtime_artifacts,
                        kind="semantic_slice",
                        summary=str(semantic_summary.get("summary", "") or "No semantic slice recovered."),
                        coverage_status=str(semantic_summary.get("coverage_status", "") or "missing"),
                        guards=[] if semantic_summary.get("sink_calls") else None,
                        call_boundary=list(semantic_summary.get("sink_calls", []) or semantic_summary.get("call_targets", []) or [])[:6],
                        call_edges=list(semantic_summary.get("call_edges", []) or [])[:8],
                        api_terms=list(semantic_summary.get("apis", []) or [])[:6],
                        related_symbols=list(semantic_summary.get("tracked_symbols", []) or semantic_summary.get("entry_points", []) or [])[:6],
                        state_transitions=list(semantic_summary.get("state_transitions", []) or [])[:4],
                        statements=list(semantic_summary.get("statements", []) or [])[:6],
                    ),
                ))
                if not has_semantic_slice:
                    missing_evidence.append("semantic_slice")

        return EvidenceBundle(
            records=records,
            missing_evidence=sorted(set(missing_evidence)),
            collected_analyzers=[self.analyzer_id] if records else [],
        )

    def _api_terms(
        self,
        source_contexts: List[SourceArtifactContext],
        runtime_artifacts: Dict[str, object],
    ) -> List[str]:
        terms: List[str] = []
        for item in source_contexts:
            terms.extend(item.call_targets)
            terms.extend(item.memory_ops)
            terms.extend(item.lock_calls)
        terms.extend(self._live_callees(runtime_artifacts))
        for finding in list(runtime_artifacts.get("existing_findings", []) or [])[:10]:
            if not isinstance(finding, dict):
                continue
            terms.extend(re.findall(r"[A-Za-z_]\w+", str(finding.get("message", "") or "")))
        return self._dedupe(terms)[:12]

    def _entry_points(
        self,
        source_contexts: List[SourceArtifactContext],
        runtime_artifacts: Dict[str, object],
    ) -> List[str]:
        terms: List[str] = []
        for item in source_contexts:
            terms.extend(self._context_related_symbols(item))
        if not terms:
            for function in self._live_functions(runtime_artifacts):
                terms.append(function)
        return self._dedupe(terms)[:8]

    def _call_targets(
        self,
        context: AnalyzerContext,
        source_contexts: List[SourceArtifactContext],
        runtime_artifacts: Dict[str, object],
    ) -> List[str]:
        focused = self._focused_call_targets(context, source_contexts)
        if focused:
            return focused[:8]
        targets: List[str] = []
        for item in source_contexts:
            targets.extend(self._filter_call_targets(item.call_targets))
        targets.extend(self._filter_call_targets(self._live_callees(runtime_artifacts)))
        return self._dedupe(targets)[:8]

    def _source_functions(
        self,
        source_contexts: List[SourceArtifactContext],
    ) -> List[str]:
        return self._dedupe([
            str(item.function_name).strip()
            for item in source_contexts
            if str(item.function_name).strip()
        ])[:8]

    def _focus_context(
        self,
        context: AnalyzerContext,
        source_contexts: List[SourceArtifactContext],
    ) -> Optional[SourceArtifactContext]:
        if not source_contexts:
            return None
        widened_variables = self._widened_variables(context)
        return max(
            source_contexts,
            key=lambda item: (
                len(self._sink_calls_from_excerpt(item.source_excerpt, widened_variables)),
                len(self._arithmetic_lines(item.source_excerpt, widened_variables)),
                len(self._context_call_targets(context, item)),
                len(item.guard_exprs),
                len(self._context_related_symbols(item)),
                int(item.anchor_line or 0),
            ),
        )

    def _context_call_targets(
        self,
        context: AnalyzerContext,
        item: Optional[SourceArtifactContext],
    ) -> List[str]:
        if item is None:
            return []
        widened_variables = self._widened_variables(context)
        sink_calls = self._sink_calls_from_excerpt(item.source_excerpt, widened_variables)
        if sink_calls:
            return sink_calls[:6]
        excerpt_calls = self._excerpt_call_targets(item)
        if excerpt_calls:
            return excerpt_calls[:6]
        return self._filter_call_targets(item.call_targets)[:6]

    def _context_related_symbols(
        self,
        item: Optional[SourceArtifactContext],
    ) -> List[str]:
        if item is None:
            return []
        symbols: List[str] = []
        symbols.extend(item.parameters)
        symbols.extend(item.globals)
        for field in re.findall(r"[A-Za-z_]\w*->\w+", item.source_excerpt or ""):
            symbols.append(field)
            symbols.append(field.split("->", 1)[1])
        return self._dedupe(symbols)[:8]

    def _direct_call_edges(
        self,
        context: AnalyzerContext,
        source_contexts: List[SourceArtifactContext],
    ) -> List[str]:
        edges: List[str] = []
        for item in source_contexts[:4]:
            if not item.function_name:
                continue
            callees = self._context_call_targets(context, item)
            for callee in callees[:6]:
                edges.append(f"{item.function_name} -> {callee}")
        return self._dedupe(edges)[:12]

    def _widening_facts(self, context: AnalyzerContext) -> List[Dict[str, object]]:
        patchweaver = (context.shared_analysis or {}).get("patchweaver", {}) or {}
        facts: List[Dict[str, object]] = []
        for raw in patchweaver.get("patch_facts", []) or []:
            if not isinstance(raw, dict):
                continue
            if str(raw.get("fact_type", "") or "") != "type_widening":
                continue
            payload = raw.get("attributes", {}) or {}
            if isinstance(payload, dict):
                facts.append(payload)
        return facts[:4]

    def _widened_variables(self, context: AnalyzerContext) -> List[str]:
        variables: List[str] = []
        for item in self._widening_facts(context):
            for raw in (item.get("variables", []) or []):
                token = str(raw).strip()
                if token and token not in variables:
                    variables.append(token)
        return variables[:8]

    def _numeric_domain_change(self, context: AnalyzerContext) -> str:
        facts = self._widening_facts(context)
        if not facts:
            return ""
        first = facts[0]
        old_type = str(first.get("old_type", "") or "").strip()
        new_type = str(first.get("new_type", "") or "").strip()
        if old_type and new_type:
            return f"counter_domain({old_type} -> {new_type})"
        return ""

    def _patch_facts(self, context: AnalyzerContext) -> List[object]:
        cache = getattr(self, "_patch_fact_cache", {})
        cache_key = str(context.patch_path or "")
        if cache_key in cache:
            return list(cache[cache_key])

        extractor = ProjectArtifactExtractor()
        file_entries = extractor.parse_patch(context.patch_path)
        patch_analysis = {
            "files_changed": [
                str(item.get("new_path") or item.get("old_path") or "").strip()
                for item in file_entries
                if str(item.get("new_path") or item.get("old_path") or "").strip()
            ],
            "file_details": [
                {
                    "path": str(item.get("new_path") or item.get("old_path") or "").strip(),
                    "additions": sum(len(list(hunk.get("added_lines", []) or [])) for hunk in (item.get("hunks", []) or [])),
                    "deletions": sum(len(list(hunk.get("removed_lines", []) or [])) for hunk in (item.get("hunks", []) or [])),
                    "hunks": len(list(item.get("hunks", []) or [])),
                }
                for item in file_entries
                if str(item.get("new_path") or item.get("old_path") or "").strip()
            ],
            "vulnerability_patterns": [],
            "cross_file_dependencies": [],
            "detection_strategy": {},
        }
        facts = PatchFactsExtractor().extract(context.patch_path, patch_analysis)
        cache[cache_key] = list(facts)
        self._patch_fact_cache = cache
        return list(facts)

    def _patch_fact_attributes(
        self,
        context: AnalyzerContext,
        fact_type: str,
        key: str,
    ) -> List[str]:
        values: List[str] = []
        for fact in self._patch_facts(context):
            if str(getattr(fact, "fact_type", "") or "") != fact_type:
                continue
            for raw in (getattr(fact, "attributes", {}) or {}).get(key, []) or []:
                token = str(raw).strip()
                if token and token not in values:
                    values.append(token)
        return values

    def _patch_guard_terms(self, context: AnalyzerContext) -> List[str]:
        guards: List[str] = []
        for raw in self._patch_fact_attributes(context, "added_guards", "guards"):
            match = re.search(r"\bif\s*\((.+)\)", raw)
            guards.append(match.group(1).strip() if match else raw)
        return self._dedupe(guards)[:6]

    def _patch_fix_patterns(self, context: AnalyzerContext) -> List[str]:
        return self._patch_fact_attributes(context, "fix_patterns", "patterns")[:6]

    def _patch_added_apis(self, context: AnalyzerContext) -> List[str]:
        return self._patch_fact_attributes(context, "added_api_calls", "apis")[:8]

    def _patch_removed_calls(self, context: AnalyzerContext) -> List[str]:
        calls: List[str] = []
        for raw in self._patch_fact_attributes(context, "removed_risky_operations", "operations"):
            for match in re.findall(r"\b([A-Za-z_]\w*)\s*\(", raw):
                token = str(match).strip()
                if token and token not in calls:
                    calls.append(token)
        return calls[:8]

    def _patch_contracts(
        self,
        context: AnalyzerContext,
        source_contexts: List[SourceArtifactContext],
    ) -> List[Dict[str, Any]]:
        cache = getattr(self, "_patch_contract_cache", {})
        cache_key = (
            str(context.patch_path or ""),
            str(context.evidence_dir or context.validate_path or ""),
        )
        if cache_key in cache:
            return list(cache[cache_key])

        contracts = CSAPathEvidenceCollector()._patch_contracts(context, source_contexts)
        cache[cache_key] = list(contracts)
        self._patch_contract_cache = cache
        return list(contracts)

    def _patch_contract_priority(self, contract: Dict[str, Any]) -> int:
        contract_type = str(contract.get("contract_type", "") or "")
        priorities = {
            "counter_widening_barrier": 5,
            "checked_format_barrier": 4,
            "state_reset_barrier": 3,
            "bounded_write_barrier": 3,
            "patch_barrier": 2,
        }
        return priorities.get(contract_type, 1)

    def _contract_calls(self, contract: Dict[str, Any]) -> List[str]:
        return self._dedupe(
            [str(item).strip() for item in (contract.get("sink_calls", []) or []) if str(item).strip()]
            + [str(item).strip() for item in (contract.get("added_calls", []) or []) if str(item).strip()]
            + [str(item).strip() for item in (contract.get("removed_calls", []) or []) if str(item).strip()]
        )[:6]

    def _contract_focus_calls(self, contract: Dict[str, Any]) -> List[str]:
        contract_type = str(contract.get("contract_type", "") or "")
        if contract_type == "checked_format_barrier":
            preferred = list(contract.get("added_calls", []) or []) or list(contract.get("sink_calls", []) or [])
            return self._dedupe([str(item).strip() for item in preferred if str(item).strip()])[:4]
        if contract_type == "bounded_write_barrier":
            preferred = list(contract.get("added_calls", []) or []) + list(contract.get("sink_calls", []) or [])
            return self._dedupe([str(item).strip() for item in preferred if str(item).strip()])[:4]
        if contract_type == "patch_barrier":
            preferred = list(contract.get("sink_calls", []) or []) + list(contract.get("added_calls", []) or [])
            return self._dedupe([str(item).strip() for item in preferred if str(item).strip()])[:4]
        return self._contract_calls(contract)

    def _best_patch_contract(
        self,
        context: AnalyzerContext,
        source_contexts: List[SourceArtifactContext],
        preferred_function: str = "",
    ) -> Optional[Dict[str, Any]]:
        contracts = self._patch_contracts(context, source_contexts)
        if not contracts:
            return None

        preferred_function = str(preferred_function or "").strip()
        preferred = [
            item
            for item in contracts
            if preferred_function and str(item.get("function", "") or "").strip() == preferred_function
        ]
        candidates = preferred or contracts
        return max(
            candidates,
            key=lambda item: (
                self._patch_contract_priority(item),
                len(self._contract_calls(item)),
                len(list(item.get("guards", []) or [])),
                len(list(item.get("symbols", []) or [])),
            ),
        )

    def _contract_summary_token(self, contract: Dict[str, Any]) -> str:
        function_name = str(contract.get("function", "") or contract.get("source_file", "") or "scope")
        contract_type = str(contract.get("contract_type", "") or "patch_barrier")
        focus_calls = self._contract_focus_calls(contract)
        calls = ", ".join(focus_calls[:2])
        guard = str((contract.get("guards", []) or [""])[0] or "").strip()
        if contract_type == "counter_widening_barrier":
            change = str(contract.get("numeric_domain_change", "") or "widened")
            return f"{function_name}: {change} before {calls or 'the size sink'}"
        if contract_type == "checked_format_barrier":
            return f"{function_name}: checked formatting via {calls or 'snprintf'} guarded by `{guard}`"
        if contract_type == "state_reset_barrier":
            resets = ", ".join((contract.get("state_resets", []) or [])[:2])
            return f"{function_name}: resets stale state with {resets or 'sentinel writes'}"
        if contract_type == "bounded_write_barrier":
            return f"{function_name}: bounds guard `{guard}` before {calls or 'bounded write'}"
        return f"{function_name}: barrier `{guard}` around {calls or 'affected sink'}"

    def _filter_edges_for_contract(
        self,
        edges: List[str],
        contract: Dict[str, Any],
    ) -> List[str]:
        if not edges:
            return []

        contract_type = str(contract.get("contract_type", "") or "")
        if contract_type == "counter_widening_barrier":
            return self._dedupe(edges)[:6]

        focus_calls = set(self._contract_focus_calls(contract))
        all_calls = set(self._contract_calls(contract))
        accepted = focus_calls or all_calls
        if not accepted:
            return self._dedupe(edges)[:6]

        filtered = [
            edge
            for edge in edges
            if "->" in edge and edge.split("->", 1)[1].strip() in accepted
        ]
        return self._dedupe(filtered)[:6]

    def _preferred_call_targets(
        self,
        contract: Optional[Dict[str, Any]],
        discovered_targets: List[str],
    ) -> List[str]:
        if not contract:
            return self._dedupe(discovered_targets)[:8]

        contract_type = str(contract.get("contract_type", "") or "")
        focus_calls = self._contract_focus_calls(contract)
        all_calls = self._contract_calls(contract)
        if contract_type == "counter_widening_barrier":
            return self._dedupe(focus_calls[:4] + discovered_targets[:6])[:8]

        if focus_calls or all_calls:
            accepted = set(focus_calls or all_calls)
            filtered_targets = [
                token
                for token in discovered_targets
                if token in accepted
            ]
            return self._dedupe(focus_calls[:4] + filtered_targets[:4])[:8]

        return self._dedupe(discovered_targets)[:8]

    def _contract_state_terms(self, contract: Dict[str, Any]) -> List[str]:
        terms: List[str] = []
        numeric_domain = str(contract.get("numeric_domain_change", "") or "").strip()
        if numeric_domain:
            terms.append(numeric_domain)
        for guard in (contract.get("guards", []) or [])[:2]:
            token = str(guard).strip()
            if token:
                terms.append(f"guard({token})")
        for reset in (contract.get("state_resets", []) or [])[:2]:
            token = str(reset).strip()
            if token:
                terms.append(f"transition({token})")
        return self._dedupe(terms)[:6]

    def _arithmetic_lines(
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

    def _sink_calls_from_excerpt(
        self,
        source_excerpt: str,
        variables: List[str],
    ) -> List[str]:
        if not variables:
            return []
        sinks: List[str] = []
        for raw_line in (source_excerpt or "").splitlines():
            line = raw_line.strip()
            if not line:
                continue
            for callee, args in re.findall(r"\b([A-Za-z_]\w*)\s*\(([^)]*)\)", line):
                if callee in {"if", "for", "while", "switch", "return", "sizeof"} or self._is_noise_call_target(callee):
                    continue
                if any(re.search(rf"\b{re.escape(var)}\b", args) for var in variables):
                    sinks.append(callee)
        return self._dedupe(sinks)[:4]

    def _dataflow_candidate(
        self,
        context: AnalyzerContext,
        source_contexts: List[SourceArtifactContext],
        runtime_artifacts: Dict[str, object],
    ) -> Dict[str, object]:
        widened_variables = self._widened_variables(context)
        focus = self._focus_context(context, source_contexts)
        source_excerpt = str(focus.source_excerpt if focus else "")
        arithmetic_ops = self._arithmetic_lines(source_excerpt, widened_variables)
        sink_calls = self._sink_calls_from_excerpt(source_excerpt, widened_variables)
        local_targets = self._context_call_targets(context, focus) if focus is not None else []
        local_edges = (
            self._relevant_live_call_edges(context, [focus], runtime_artifacts)
            if focus is not None
            else []
        ) or (
            self._direct_call_edges(context, [focus])
            if focus is not None
            else []
        )
        patch_contract = self._best_patch_contract(
            context,
            source_contexts,
            preferred_function=str(focus.function_name if focus else ""),
        )
        patch_guards = self._patch_guard_terms(context)
        patch_added_apis = self._patch_added_apis(context)
        entry_points = self._dedupe(
            widened_variables
            + (self._context_related_symbols(focus) if focus is not None else [])
            + ([] if focus is not None else self._live_functions(runtime_artifacts))
        )[:8]
        path: List[str] = []
        if focus is not None and focus.function_name:
            path.append(f"function:{focus.function_name}")
        if patch_contract is not None and str(patch_contract.get("function", "") or "").strip():
            path = [f"function:{str(patch_contract.get('function', '') or '').strip()}"]
            for guard in (patch_contract.get("guards", []) or [])[:1]:
                token = str(guard).strip()
                if token:
                    path.append(f"guard:{token}")
            for call in self._contract_focus_calls(patch_contract)[:2]:
                path.append(f"api:{call}")
        path.extend(arithmetic_ops[:2])
        path.extend(f"{focus.function_name} -> {call}" for call in sink_calls[:2] if focus is not None and focus.function_name)
        if patch_contract is not None:
            path.extend(self._filter_edges_for_contract(local_edges, patch_contract)[:2])
        else:
            path.extend(local_edges[:2])
        summary = ""
        if widened_variables and sink_calls:
            summary = (
                f"Widened counters {', '.join(widened_variables[:4])} feed {', '.join(sink_calls[:2])} "
                "through local accumulation before the sink."
            )
        elif widened_variables and arithmetic_ops:
            summary = (
                f"Widened counters {', '.join(widened_variables[:4])} participate in local arithmetic that should stay in the wider domain."
            )
        elif patch_contract is not None:
            summary = self._contract_summary_token(patch_contract)
        elif patch_guards and (patch_added_apis or local_targets):
            summary = (
                f"Patch adds guard `{patch_guards[0]}` before "
                f"{', '.join((patch_added_apis[:2] or local_targets[:2]))}."
            )
        elif focus is not None and (local_targets or local_edges):
            scope = focus.function_name or focus.relative_file or "patch-local flow"
            summary = f"{scope} reaches {', '.join(local_targets[:3] or ['relevant calls'])}"
            if focus.guard_exprs:
                summary += f" after guard {focus.guard_exprs[0]}"
        elif entry_points:
            summary = f"Observed entry candidates: {', '.join(entry_points[:5])}"
        focus_calls = self._contract_focus_calls(patch_contract or {})
        sink = ", ".join(
            focus_calls[:2]
            if patch_contract is not None
            else sink_calls[:2]
        )
        call_targets = self._preferred_call_targets(
            patch_contract,
            list(self._call_targets(context, source_contexts, runtime_artifacts)),
        )
        if patch_contract is not None:
            entry_points = self._dedupe(
                [str(item).strip() for item in (patch_contract.get("symbols", []) or []) if str(item).strip()]
                + entry_points
            )[:8]
        return {
            "source": ", ".join(entry_points[:4]),
            "sink": sink,
            "path": self._dedupe(path)[:6],
            "summary": summary,
            "focus_function": str(
                (patch_contract or {}).get("function", "")
                or (focus.function_name if focus else "")
            ),
            "entry_points": entry_points[:6],
            "call_targets": call_targets,
            "state_transitions": (
                [self._numeric_domain_change(context)] if self._numeric_domain_change(context) else self._contract_state_terms(patch_contract or {})
            ),
            "source_excerpt": source_excerpt,
        }

    def _call_chain_summary(
        self,
        context: AnalyzerContext,
        source_contexts: List[SourceArtifactContext],
        dependency_map: dict,
        runtime_artifacts: Dict[str, object],
    ) -> List[str]:
        summary: List[str] = []
        live_edges = self._live_call_edges(runtime_artifacts)
        direct_edges = self._direct_call_edges(context, source_contexts)
        focused_edges = self._relevant_live_call_edges(context, source_contexts, runtime_artifacts)
        if focused_edges:
            summary.extend(focused_edges[:6])
        elif direct_edges:
            summary.extend(direct_edges[:6])
        elif live_edges:
            summary.extend(live_edges[:6])

        if not summary:
            for item in source_contexts[:4]:
                focused_targets = self._context_call_targets(context, item)
                if item.function_name and focused_targets:
                    summary.append(f"{item.function_name} -> {', '.join(focused_targets[:3])}")
                includes = dependency_map.get(item.relative_file, []) or []
                if includes and not summary:
                    summary.append(f"{item.relative_file} includes {', '.join(map(str, includes[:2]))}")

        return self._dedupe(summary)[:8]

    def _has_live_inventory(self, runtime_artifacts: Dict[str, object]) -> bool:
        return self._live_status(runtime_artifacts) == "success"

    def _live_status(self, runtime_artifacts: Dict[str, object]) -> str:
        live = runtime_artifacts.get("live_inventory", {}) or {}
        return str(live.get("status", "skipped") or "skipped")

    def _live_functions(self, runtime_artifacts: Dict[str, object]) -> List[str]:
        live = runtime_artifacts.get("live_inventory", {}) or {}
        functions = []
        for item in live.get("functions", []) or []:
            if isinstance(item, dict) and item.get("function"):
                functions.append(str(item["function"]))
        return self._dedupe(functions)[:12]

    def _live_call_edges(self, runtime_artifacts: Dict[str, object]) -> List[str]:
        live = runtime_artifacts.get("live_inventory", {}) or {}
        edges = [str(item).strip() for item in (live.get("call_edges", []) or []) if str(item).strip()]
        return self._dedupe([
            self._normalize_call_edge(edge)
            for edge in edges
            if self._is_call_edge(edge)
        ])[:30]

    def _live_callees(self, runtime_artifacts: Dict[str, object]) -> List[str]:
        callees: List[str] = []
        for edge in self._live_call_edges(runtime_artifacts):
            if "->" not in edge:
                continue
            callees.append(edge.split("->", 1)[1].strip())
        return self._dedupe(callees)[:12]

    def _dedupe(self, items: List[str]) -> List[str]:
        seen = set()
        deduped: List[str] = []
        for item in items:
            token = str(item).strip()
            if token and token not in seen:
                seen.add(token)
                deduped.append(token)
        return deduped

    def _focus_file(
        self,
        source_contexts: List[SourceArtifactContext],
        runtime_artifacts: Dict[str, object],
    ) -> str:
        for item in source_contexts:
            if item.relative_file:
                return item.relative_file
        live = runtime_artifacts.get("live_inventory", {}) or {}
        target_files = [str(item).strip() for item in (live.get("target_files", []) or []) if str(item).strip()]
        if target_files:
            return target_files[0]
        return ""

    def _focus_function(
        self,
        source_contexts: List[SourceArtifactContext],
        runtime_artifacts: Dict[str, object],
    ) -> str:
        for item in source_contexts:
            if item.function_name:
                return item.function_name
        for item in (runtime_artifacts.get("live_inventory", {}) or {}).get("functions", []) or []:
            if isinstance(item, dict) and item.get("function"):
                return str(item.get("function"))
        return ""

    def _semantic_slice_summary(
        self,
        context: AnalyzerContext,
        source_contexts: List[SourceArtifactContext],
        dependency_map: dict,
        runtime_artifacts: Dict[str, object],
    ) -> Dict[str, object]:
        call_edges = (
            self._relevant_live_call_edges(context, source_contexts, runtime_artifacts)
            or self._direct_call_edges(context, source_contexts)
        )[:8]
        call_targets = self._call_targets(context, source_contexts, runtime_artifacts)
        widened_variables = self._widened_variables(context)
        entry_points = self._dedupe(widened_variables + self._entry_points(source_contexts, runtime_artifacts))[:8]
        focus = self._focus_context(context, source_contexts)
        source_excerpt = str(focus.source_excerpt if focus else "")
        arithmetic_ops = self._arithmetic_lines(source_excerpt, widened_variables)
        sink_calls = self._sink_calls_from_excerpt(source_excerpt, widened_variables)
        patch_contracts = self._patch_contracts(context, source_contexts)
        focus_contract = self._best_patch_contract(
            context,
            source_contexts,
            preferred_function=str(focus.function_name if focus else ""),
        )
        patch_guards = self._patch_guard_terms(context)
        patch_fix_patterns = self._patch_fix_patterns(context)
        patch_added_apis = self._patch_added_apis(context)
        patch_removed_calls = self._patch_removed_calls(context)
        guard_terms = list(focus.guard_exprs[:2]) if focus is not None else []
        related_symbols = self._context_related_symbols(focus) if focus is not None else []
        contract_calls = self._contract_calls(focus_contract or {})
        contract_focus_calls = self._contract_focus_calls(focus_contract or {})
        contract_symbols = [
            str(item).strip()
            for item in ((focus_contract or {}).get("symbols", []) or [])
            if str(item).strip()
        ]
        apis = (
            self._dedupe(sink_calls[:4] + call_targets[:4])[:6]
            if sink_calls
            else self._dedupe(
                contract_focus_calls[:4]
                + patch_added_apis[:4]
                + patch_removed_calls[:3]
                + list(call_targets[:4])
                + self._filter_call_targets(self._api_terms(source_contexts, runtime_artifacts))
            )[:6]
        )
        state_transitions = (
            [self._numeric_domain_change(context)] if self._numeric_domain_change(context) else self._contract_state_terms(focus_contract or {})
        )
        modules: List[str] = []
        for item in source_contexts[:4]:
            includes = dependency_map.get(item.relative_file, []) or []
            for include in includes[:3]:
                token = str(include).strip()
                if token and token not in modules:
                    modules.append(token)

        summary_parts: List[str] = []
        if focus is not None and focus.function_name:
            summary_parts.append(f"focus={focus.function_name}")
        if widened_variables:
            summary_parts.append(f"widened={', '.join(widened_variables[:4])}")
        if state_transitions:
            label = "domain" if str(state_transitions[0]).startswith("counter_domain(") else "state"
            summary_parts.append(f"{label}={state_transitions[0]}")
        if sink_calls:
            summary_parts.append(f"sinks={', '.join(sink_calls[:3])}")
        if arithmetic_ops:
            summary_parts.append(f"arith={'; '.join(arithmetic_ops[:2])}")
        if call_edges and not sink_calls:
            summary_parts.append(f"call_edges={'; '.join(call_edges[:3])}")
        if call_targets and not sink_calls:
            summary_parts.append(f"targets={', '.join(call_targets[:4])}")
        if patch_contracts and not widened_variables:
            summary_parts.append(
                "patch_contracts="
                + "; ".join(self._contract_summary_token(item) for item in patch_contracts[:3])
            )
        elif patch_guards and not widened_variables:
            summary_parts.append(f"patch_guards={'; '.join(patch_guards[:2])}")
        if patch_fix_patterns:
            summary_parts.append(f"patch_fix={', '.join(patch_fix_patterns[:2])}")
        if patch_added_apis and not sink_calls:
            summary_parts.append(f"patched_apis={', '.join(patch_added_apis[:3])}")
        if patch_removed_calls and not sink_calls:
            summary_parts.append(f"removed_ops={', '.join(patch_removed_calls[:3])}")
        if guard_terms and not (widened_variables or sink_calls or arithmetic_ops):
            summary_parts.append(f"guards={'; '.join(guard_terms[:2])}")
        if related_symbols and not widened_variables:
            summary_parts.append(f"symbols={', '.join(related_symbols[:4])}")
        if modules and not (widened_variables or sink_calls or arithmetic_ops):
            summary_parts.append(f"deps={', '.join(modules[:3])}")
        if apis and not sink_calls:
            summary_parts.append(f"apis={', '.join(apis[:4])}")
        summary = " | ".join(summary_parts)
        coverage_status = "full" if self._has_live_inventory(runtime_artifacts) and summary else ("partial" if summary else "missing")
        preferred_targets = self._preferred_call_targets(
            focus_contract,
            list(call_targets[:6]),
        )
        return {
            "summary": summary,
            "focus_function": str(
                (focus_contract or {}).get("function", "")
                or (focus.function_name if focus else "")
            ),
            "call_edges": call_edges,
            "call_targets": preferred_targets[:6],
            "entry_points": entry_points[:6],
            "tracked_symbols": widened_variables[:6] or contract_symbols[:6] or related_symbols[:6] or entry_points[:6],
            "sink_calls": sink_calls[:4],
            "state_transitions": state_transitions[:4],
            "statements": arithmetic_ops[:6] or list((focus_contract or {}).get("statements", []) or [])[:6],
            "apis": apis[:6],
            "dependencies": modules[:6],
            "source_excerpt": source_excerpt,
            "coverage_status": coverage_status,
        }

    def _focused_call_targets(
        self,
        context: AnalyzerContext,
        source_contexts: List[SourceArtifactContext],
    ) -> List[str]:
        focused: List[str] = []
        for item in source_contexts[:4]:
            focused.extend(self._context_call_targets(context, item))
        return self._dedupe(self._filter_call_targets(focused))[:8]

    def _excerpt_call_targets(self, item: SourceArtifactContext) -> List[str]:
        calls: List[str] = []
        for raw_line in (item.source_excerpt or "").splitlines():
            line_no, statement = self._split_excerpt_line(raw_line)
            if line_no and line_no < int(item.anchor_line or 0):
                continue
            stripped = statement.strip()
            if (
                not stripped
                or stripped.startswith("//")
                or stripped.startswith("/*")
                or stripped.startswith("*")
                or stripped.startswith("**")
            ):
                continue
            candidate_text = re.sub(r"/\*.*?\*/", "", statement)
            candidate_text = candidate_text.split("//", 1)[0]
            if ProjectArtifactExtractor.FUNCTION_PATTERN.match(stripped):
                continue
            for name in re.findall(r"\b([A-Za-z_]\w*)\s*\(", candidate_text):
                if self._is_noise_call_target(name):
                    continue
                calls.append(name)
        return self._dedupe(calls)[:8]

    def _split_excerpt_line(self, raw_line: str) -> tuple[int, str]:
        match = re.match(r"^\s*(\d+):\s?(.*)$", str(raw_line or ""))
        if not match:
            return 0, str(raw_line or "")
        return int(match.group(1) or 0), match.group(2)

    def _filter_call_targets(self, targets: List[str]) -> List[str]:
        return [
            token
            for token in [str(item).strip() for item in targets]
            if token and not self._is_noise_call_target(token)
        ]

    def _is_noise_call_target(self, token: str) -> bool:
        normalized = str(token or "").strip()
        if not normalized:
            return True
        if normalized in self._CONTROL_TARGETS:
            return True
        if normalized in self._PSEUDO_CALLS:
            return True
        if any(ch.isalpha() for ch in normalized) and normalized.upper() == normalized:
            return True
        return False

    def _is_call_edge(self, edge: str) -> bool:
        if "->" not in edge:
            return False
        caller, callee = [part.strip() for part in edge.split("->", 1)]
        if not caller or not callee:
            return False
        if not re.match(r"^[A-Za-z_][\w:]*$", caller):
            return False
        if not re.match(r"^[A-Za-z_][\w:]*$", callee):
            return False
        return not self._is_noise_call_target(callee)

    def _normalize_call_edge(self, edge: str) -> str:
        token = str(edge or "").strip()
        if "->" not in token:
            return token
        caller, callee = [part.strip() for part in token.split("->", 1)]
        if not caller or not callee:
            return token
        return f"{caller} -> {callee}"

    def _relevant_live_call_edges(
        self,
        context: AnalyzerContext,
        source_contexts: List[SourceArtifactContext],
        runtime_artifacts: Dict[str, object],
    ) -> List[str]:
        focused_targets = set(self._focused_call_targets(context, source_contexts))
        source_functions = set(self._source_functions(source_contexts))
        if not focused_targets and not source_functions:
            return []
        relevant: List[str] = []
        for edge in self._live_call_edges(runtime_artifacts):
            if "->" not in edge:
                continue
            caller, callee = [part.strip() for part in edge.split("->", 1)]
            if source_functions and caller not in source_functions:
                continue
            if focused_targets and callee not in focused_targets:
                continue
            relevant.append(edge)
        return relevant[:8]

    def _build_slice(
        self,
        source_contexts: List[SourceArtifactContext],
        runtime_artifacts: Dict[str, object],
        kind: str,
        summary: str,
        *,
        coverage_status: str = "unknown",
        guards: Optional[List[str]] = None,
        call_boundary: Optional[List[str]] = None,
        call_edges: Optional[List[str]] = None,
        api_terms: Optional[List[str]] = None,
        related_symbols: Optional[List[str]] = None,
        state_transitions: Optional[List[str]] = None,
        statements: Optional[List[str]] = None,
    ) -> EvidenceSlice:
        first = source_contexts[0] if source_contexts else None
        guards: List[str] = []
        default_statements: List[str] = []
        anchor = EvidenceAnchor()
        if first is not None:
            guards = list(first.guard_exprs[:4]) if guards is None else list(guards[:4])
            default_statements = [
                line.strip()
                for line in (first.source_excerpt or "").splitlines()
                if line.strip()
            ][:6]
            anchor = EvidenceAnchor(
                patch_file=first.patch_file,
                hunk_index=first.hunk_index,
                source_line=first.anchor_line,
            )

        default_boundary = self._dedupe(
            [
                *self._filter_call_targets([
                    target
                    for item in source_contexts
                    for target in item.call_targets
                ]),
                *self._filter_call_targets(self._live_callees(runtime_artifacts)),
            ]
        )[:6]
        default_edges = self._live_call_edges(runtime_artifacts)
        default_apis = self._filter_call_targets(self._api_terms(source_contexts, runtime_artifacts))
        default_symbols = self._entry_points(source_contexts, runtime_artifacts)

        return EvidenceSlice(
            kind=kind,
            anchor=anchor,
            summary=summary,
            statements=[str(item) for item in (statements or default_statements)[:6]],
            guards=list(guards or [])[:4],
            call_boundary=[str(item) for item in (call_boundary or default_boundary)[:6]],
            call_edges=[str(item) for item in (call_edges or default_edges)[:8]],
            state_transitions=[str(item) for item in (state_transitions or [])[:6]],
            api_terms=[str(item) for item in (api_terms or default_apis)[:6]],
            related_symbols=[str(item) for item in (related_symbols or default_symbols)[:6]],
            verifier="codeql-live-inventory" if self._has_live_inventory(runtime_artifacts) else "source-window",
            extraction_method="live_inventory+source_window" if self._has_live_inventory(runtime_artifacts) else "source_window",
            coverage_status=coverage_status,
        )
