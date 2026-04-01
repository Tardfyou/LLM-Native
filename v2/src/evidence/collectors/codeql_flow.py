"""
CodeQL-oriented evidence collection.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List, Optional

from ...core.analyzer_base import AnalyzerContext
from ...core.evidence_schema import EvidenceAnchor, EvidenceBundle, EvidenceSlice
from .artifact_extractor import ProjectArtifactExtractor, SourceArtifactContext
from .base import EvidenceCollector


class CodeQLFlowEvidenceCollector(EvidenceCollector):
    """Collect flow-oriented evidence hints for CodeQL synthesis."""

    analyzer_id = "codeql"

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
                entry_points = self._entry_points(source_contexts, runtime_artifacts)
                satisfied = bool(entry_points) and self._has_live_inventory(runtime_artifacts)
                records.append(self._record(
                    "codeql_flow_0",
                    "dataflow_candidate",
                    context,
                    {
                        "reason": requirement.get("reason", ""),
                        "entry_points": entry_points,
                        "summary": (
                            f"Observed CodeQL-backed entry candidates: {', '.join(entry_points[:5])}"
                            if entry_points else "No concrete CodeQL-backed entry candidates resolved."
                        ),
                        "call_targets": self._call_targets(source_contexts, runtime_artifacts),
                        "live_query_status": self._live_status(runtime_artifacts),
                        "database_status": "ready" if runtime_artifacts.get("database_exists") else "missing",
                        "database_create_message": runtime_artifacts.get("database_create_message", ""),
                        "coverage_status": "full" if satisfied else ("partial" if entry_points else "missing"),
                    },
                    artifact="codeql-db:live-inventory" if self._has_live_inventory(runtime_artifacts) else "source-window:data-flow-seed",
                    confidence=0.9 if self._has_live_inventory(runtime_artifacts) and entry_points else (0.84 if entry_points else 0.66),
                    file=self._focus_file(source_contexts, runtime_artifacts),
                    function=self._focus_function(source_contexts, runtime_artifacts),
                    evidence_slice=self._build_slice(
                        source_contexts=source_contexts,
                        runtime_artifacts=runtime_artifacts,
                        kind="flow_witness",
                        summary=(
                            f"Observed CodeQL-backed entry candidates: {', '.join(entry_points[:5])}"
                            if entry_points else "No concrete CodeQL-backed entry candidates resolved."
                        ),
                        coverage_status="full" if satisfied else ("partial" if entry_points else "missing"),
                        api_terms=self._call_targets(source_contexts, runtime_artifacts),
                        related_symbols=entry_points,
                    ),
                ))
                if not satisfied:
                    missing_evidence.append("dataflow_candidate")

            elif evidence_type == "call_chain":
                chain_summary = self._call_chain_summary(source_contexts, dependency_map, runtime_artifacts)
                satisfied = bool(self._live_call_edges(runtime_artifacts))
                records.append(self._record(
                    "codeql_chain_0",
                    "call_chain",
                    context,
                    {
                        "reason": requirement.get("reason", ""),
                        "summary": chain_summary,
                        "call_edges": self._live_call_edges(runtime_artifacts)[:8],
                        "live_query_status": self._live_status(runtime_artifacts),
                        "database_status": "ready" if runtime_artifacts.get("database_exists") else "missing",
                        "database_create_message": runtime_artifacts.get("database_create_message", ""),
                        "coverage_status": "full" if satisfied else ("partial" if chain_summary else "missing"),
                    },
                    artifact="codeql-db:call-edges" if self._has_live_inventory(runtime_artifacts) else "source-window:interprocedural-summary",
                    confidence=0.88 if self._has_live_inventory(runtime_artifacts) and chain_summary else (0.78 if chain_summary else 0.6),
                    file=self._focus_file(source_contexts, runtime_artifacts),
                    function=self._focus_function(source_contexts, runtime_artifacts),
                    evidence_slice=self._build_slice(
                        source_contexts=source_contexts,
                        runtime_artifacts=runtime_artifacts,
                        kind="interprocedural_slice",
                        summary=", ".join(chain_summary[:4]) if chain_summary else "No interprocedural chain recovered.",
                        coverage_status="full" if satisfied else ("partial" if chain_summary else "missing"),
                        call_boundary=self._call_targets(source_contexts, runtime_artifacts),
                        call_edges=self._live_call_edges(runtime_artifacts),
                    ),
                ))
                if not satisfied:
                    missing_evidence.append("call_chain")

            elif evidence_type == "api_contract":
                api_terms = self._api_terms(source_contexts, runtime_artifacts)
                satisfied = bool(api_terms) and (
                    self._has_live_inventory(runtime_artifacts) or runtime_artifacts.get("database_exists")
                )
                records.append(self._record(
                    "codeql_api_0",
                    "api_contract",
                    context,
                    {
                        "reason": requirement.get("reason", ""),
                        "apis": api_terms[:6],
                        "summary": (
                            f"Observed CodeQL-backed API surface: {', '.join(api_terms[:5])}"
                            if api_terms else "No concrete API surface resolved from CodeQL/project artifacts."
                        ),
                        "live_query_status": self._live_status(runtime_artifacts),
                        "database_status": "ready" if runtime_artifacts.get("database_exists") else "missing",
                        "database_create_message": runtime_artifacts.get("database_create_message", ""),
                        "coverage_status": "full" if satisfied else ("partial" if api_terms else "missing"),
                    },
                    artifact="codeql-db:api-surface" if self._has_live_inventory(runtime_artifacts) else "source-window:api-contract-hints",
                    confidence=0.87 if self._has_live_inventory(runtime_artifacts) and api_terms else (0.79 if api_terms else 0.6),
                    file=self._focus_file(source_contexts, runtime_artifacts),
                    function=self._focus_function(source_contexts, runtime_artifacts),
                    evidence_slice=self._build_slice(
                        source_contexts=source_contexts,
                        runtime_artifacts=runtime_artifacts,
                        kind="api_contract_slice",
                        summary=(
                            f"Observed CodeQL-backed API surface: {', '.join(api_terms[:5])}"
                            if api_terms else "No concrete API surface resolved from CodeQL/project artifacts."
                        ),
                        coverage_status="full" if satisfied else ("partial" if api_terms else "missing"),
                        api_terms=api_terms,
                    ),
                ))
                if not satisfied:
                    missing_evidence.append("api_contract")

            elif evidence_type in {"context_summary", "slice_summary"}:
                database_metadata = runtime_artifacts.get("database_metadata", {}) or {}
                satisfied = bool(project_info or runtime_artifacts.get("database_exists"))
                payload = {
                    "reason": requirement.get("reason", ""),
                    "summary": (
                        f"build={project_info.get('build_system') or 'unknown'}, "
                        f"source_count={project_info.get('source_count', 0)}, "
                        f"compile_commands={bool(project_info.get('has_compile_commands'))}, "
                        f"codeql_db={'ready' if runtime_artifacts.get('database_exists') else 'missing'}, "
                        f"live_inventory={self._live_status(runtime_artifacts)}"
                    ),
                    "build_system": project_info.get("build_system"),
                    "compile_commands_path": project_info.get("compile_commands_path"),
                    "database_status": "ready" if runtime_artifacts.get("database_exists") else "missing",
                    "database_path": runtime_artifacts.get("database_path", ""),
                    "database_languages": list(database_metadata.get("languages", []) or []),
                    "source_archive_zip": database_metadata.get("sourceArchiveZip", ""),
                    "baseline_files_count": len(runtime_artifacts.get("baseline_files", []) or []),
                    "baseline_loc": int(runtime_artifacts.get("baseline_loc", 0) or 0),
                    "build_script": runtime_artifacts.get("build_script", ""),
                    "database_create_message": runtime_artifacts.get("database_create_message", ""),
                    "modules": [
                        item.get("name", "")
                        for item in (project_info.get("modules", []) or [])
                        if isinstance(item, dict) and item.get("name")
                    ][:6],
                    "live_query_status": self._live_status(runtime_artifacts),
                    "target_files": list((runtime_artifacts.get("live_inventory", {}) or {}).get("target_files", []) or [])[:6],
                    "existing_findings_count": int(runtime_artifacts.get("existing_findings_count", 0) or 0),
                    "coverage_status": "full" if runtime_artifacts.get("database_exists") else ("partial" if satisfied else "missing"),
                }
                records.append(self._record(
                    "codeql_context_0",
                    "context_summary",
                    context,
                    payload,
                    artifact="codeql-db:metadata",
                    confidence=0.86 if runtime_artifacts.get("database_exists") else 0.7,
                    file=self._focus_file(source_contexts, runtime_artifacts),
                    function=self._focus_function(source_contexts, runtime_artifacts),
                    evidence_slice=EvidenceSlice(
                        kind="context_summary",
                        anchor=EvidenceAnchor(
                            patch_file="",
                            hunk_index=0,
                            source_line=0,
                        ),
                        summary=str(payload.get("summary", "") or ""),
                        call_boundary=list(payload.get("target_files", []) or [])[:4],
                        call_edges=self._live_call_edges(runtime_artifacts)[:6],
                        api_terms=self._api_terms(source_contexts, runtime_artifacts)[:4],
                        verifier="codeql-db" if runtime_artifacts.get("database_exists") else "project-analyzer",
                        extraction_method="database_metadata+project_info",
                        coverage_status=str(payload.get("coverage_status", "") or "unknown"),
                    ),
                ))
                if not satisfied:
                    missing_evidence.append("context_summary")

            elif evidence_type == "semantic_slice":
                semantic_summary = self._semantic_slice_summary(source_contexts, dependency_map, runtime_artifacts)
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
                    function=self._focus_function(source_contexts, runtime_artifacts),
                    evidence_slice=self._build_slice(
                        source_contexts=source_contexts,
                        runtime_artifacts=runtime_artifacts,
                        kind="semantic_slice",
                        summary=str(semantic_summary.get("summary", "") or "No semantic slice recovered."),
                        coverage_status=str(semantic_summary.get("coverage_status", "") or "missing"),
                        call_boundary=list(semantic_summary.get("call_targets", []) or [])[:6],
                        call_edges=list(semantic_summary.get("call_edges", []) or [])[:8],
                        api_terms=list(semantic_summary.get("apis", []) or [])[:6],
                        related_symbols=list(semantic_summary.get("entry_points", []) or [])[:6],
                    ),
                ))
                if not has_semantic_slice:
                    missing_evidence.append("semantic_slice")

            elif evidence_type == "diagnostic":
                records.append(self._record(
                    "codeql_diag_0",
                    "diagnostic",
                    context,
                    {
                        "reason": requirement.get("reason", ""),
                        "summary": (
                            f"CodeQL artifacts: database={'ready' if runtime_artifacts.get('database_exists') else 'missing'}, "
                            f"live_inventory={self._live_status(runtime_artifacts)}, "
                            f"build_script={'present' if runtime_artifacts.get('build_script_exists') else 'absent'}, "
                            f"existing_findings={runtime_artifacts.get('existing_findings_count', 0)}."
                        ),
                        "database_status": "ready" if runtime_artifacts.get("database_exists") else "missing",
                        "database_path": runtime_artifacts.get("database_path", ""),
                        "build_script": runtime_artifacts.get("build_script", ""),
                        "database_create_message": runtime_artifacts.get("database_create_message", ""),
                        "live_query_status": self._live_status(runtime_artifacts),
                        "existing_findings_count": int(runtime_artifacts.get("existing_findings_count", 0) or 0),
                    },
                    artifact="codeql-runtime-artifacts",
                    confidence=0.8 if runtime_artifacts.get("database_exists") else 0.68,
                    file=self._focus_file(source_contexts, runtime_artifacts),
                    function=self._focus_function(source_contexts, runtime_artifacts),
                    evidence_slice=EvidenceSlice(
                        kind="context_summary",
                        anchor=EvidenceAnchor(),
                        summary=(
                            f"CodeQL artifacts: database={'ready' if runtime_artifacts.get('database_exists') else 'missing'}, "
                            f"live_inventory={self._live_status(runtime_artifacts)}"
                        ),
                        verifier="codeql-db" if runtime_artifacts.get("database_exists") else "project-analyzer",
                        extraction_method="runtime_artifacts",
                        coverage_status="full" if runtime_artifacts.get("database_exists") else "partial",
                    ),
                ))

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
            terms.extend(item.parameters)
            terms.extend(item.globals)
        for function in self._live_functions(runtime_artifacts):
            terms.append(function)
        return self._dedupe(terms)[:8]

    def _call_targets(
        self,
        source_contexts: List[SourceArtifactContext],
        runtime_artifacts: Dict[str, object],
    ) -> List[str]:
        targets: List[str] = []
        for item in source_contexts:
            targets.extend(item.call_targets)
        targets.extend(self._live_callees(runtime_artifacts))
        return self._dedupe(targets)[:8]

    def _call_chain_summary(
        self,
        source_contexts: List[SourceArtifactContext],
        dependency_map: dict,
        runtime_artifacts: Dict[str, object],
    ) -> List[str]:
        summary: List[str] = []
        live_edges = self._live_call_edges(runtime_artifacts)
        if live_edges:
            summary.extend(live_edges[:6])

        for item in source_contexts[:4]:
            if item.function_name and item.call_targets:
                summary.append(f"{item.function_name} -> {', '.join(item.call_targets[:3])}")
            includes = dependency_map.get(item.relative_file, []) or []
            if includes:
                summary.append(f"{item.relative_file} includes {', '.join(map(str, includes[:2]))}")

        for finding in list(runtime_artifacts.get("existing_findings", []) or [])[:4]:
            if not isinstance(finding, dict):
                continue
            file_label = Path(str(finding.get("file_path", "") or "")).name
            line = int(finding.get("line", 0) or 0)
            message = str(finding.get("message", "") or "").strip()
            if file_label and line and message:
                summary.append(f"{file_label}:{line} -> {message}")

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
        return self._dedupe(edges)[:12]

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
        source_contexts: List[SourceArtifactContext],
        dependency_map: dict,
        runtime_artifacts: Dict[str, object],
    ) -> Dict[str, object]:
        call_edges = self._live_call_edges(runtime_artifacts)[:8]
        call_targets = self._call_targets(source_contexts, runtime_artifacts)
        entry_points = self._entry_points(source_contexts, runtime_artifacts)
        apis = self._api_terms(source_contexts, runtime_artifacts)
        modules: List[str] = []
        for item in source_contexts[:4]:
            includes = dependency_map.get(item.relative_file, []) or []
            for include in includes[:3]:
                token = str(include).strip()
                if token and token not in modules:
                    modules.append(token)

        summary_parts: List[str] = []
        if call_edges:
            summary_parts.append(f"call_edges={'; '.join(call_edges[:3])}")
        if call_targets:
            summary_parts.append(f"targets={', '.join(call_targets[:4])}")
        if modules:
            summary_parts.append(f"deps={', '.join(modules[:3])}")
        if apis:
            summary_parts.append(f"apis={', '.join(apis[:4])}")
        summary = " | ".join(summary_parts)
        coverage_status = "full" if self._has_live_inventory(runtime_artifacts) and summary else ("partial" if summary else "missing")
        return {
            "summary": summary,
            "call_edges": call_edges,
            "call_targets": call_targets[:6],
            "entry_points": entry_points[:6],
            "apis": apis[:6],
            "dependencies": modules[:6],
            "coverage_status": coverage_status,
        }

    def _build_slice(
        self,
        source_contexts: List[SourceArtifactContext],
        runtime_artifacts: Dict[str, object],
        kind: str,
        summary: str,
        *,
        coverage_status: str = "unknown",
        call_boundary: Optional[List[str]] = None,
        call_edges: Optional[List[str]] = None,
        api_terms: Optional[List[str]] = None,
        related_symbols: Optional[List[str]] = None,
    ) -> EvidenceSlice:
        first = source_contexts[0] if source_contexts else None
        guards: List[str] = []
        statements: List[str] = []
        anchor = EvidenceAnchor()
        if first is not None:
            guards = list(first.guard_exprs[:4])
            statements = [
                line.strip()
                for line in (first.source_excerpt or "").splitlines()
                if line.strip()
            ][:6]
            anchor = EvidenceAnchor(
                patch_file=first.patch_file,
                hunk_index=first.hunk_index,
                source_line=first.anchor_line,
            )

        default_boundary = self._call_targets(source_contexts, runtime_artifacts)
        default_edges = self._live_call_edges(runtime_artifacts)
        default_apis = self._api_terms(source_contexts, runtime_artifacts)
        default_symbols = self._entry_points(source_contexts, runtime_artifacts)

        return EvidenceSlice(
            kind=kind,
            anchor=anchor,
            summary=summary,
            statements=statements,
            guards=guards,
            call_boundary=[str(item) for item in (call_boundary or default_boundary)[:6]],
            call_edges=[str(item) for item in (call_edges or default_edges)[:8]],
            state_transitions=[],
            api_terms=[str(item) for item in (api_terms or default_apis)[:6]],
            related_symbols=[str(item) for item in (related_symbols or default_symbols)[:6]],
            verifier="codeql-live-inventory" if self._has_live_inventory(runtime_artifacts) else "source-window",
            extraction_method="live_inventory+source_window" if self._has_live_inventory(runtime_artifacts) else "source_window",
            coverage_status=coverage_status,
        )
