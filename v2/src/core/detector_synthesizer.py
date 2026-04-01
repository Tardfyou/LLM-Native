"""
Structured synthesis input for analyzer-native detector backends.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ..evidence.normalizer import EvidenceNormalizer
from ..utils.vulnerability_taxonomy import (
    mechanism_family_for_vulnerability,
    normalize_vulnerability_type,
)
from .analyzer_base import AnalyzerContext, AnalyzerDescriptor
from .evidence_schema import EvidenceBundle, EvidenceRecord


@dataclass(frozen=True)
class SynthesisConstraint:
    """Hard or soft constraints passed to detector synthesis."""

    title: str
    description: str
    priority: str = "high"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "description": self.description,
            "priority": self.priority,
        }


@dataclass(frozen=True)
class MechanismContract:
    """Pattern-agnostic mechanism contract used to guide synthesis."""

    mechanism_family: str
    semantic_dimensions: List[str] = field(default_factory=list)
    trigger_invariants: List[str] = field(default_factory=list)
    silence_invariants: List[str] = field(default_factory=list)
    transfer_axes: List[str] = field(default_factory=list)
    forbidden_shortcuts: List[str] = field(default_factory=list)
    evidence_backed_axes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "mechanism_family": self.mechanism_family,
            "semantic_dimensions": list(self.semantic_dimensions),
            "trigger_invariants": list(self.trigger_invariants),
            "silence_invariants": list(self.silence_invariants),
            "transfer_axes": list(self.transfer_axes),
            "forbidden_shortcuts": list(self.forbidden_shortcuts),
            "evidence_backed_axes": list(self.evidence_backed_axes),
        }


@dataclass(frozen=True)
class DetectorSynthesisInput:
    """Structured input consumed by detector backends."""

    analyzer_id: str
    detector_artifact: str
    primary_pattern: str
    objective: str
    mechanism_contract: Optional[MechanismContract] = None
    detector_name_hint: str = ""
    focus_files: List[str] = field(default_factory=list)
    focus_functions: List[str] = field(default_factory=list)
    hypotheses: List[str] = field(default_factory=list)
    required_evidence_types: List[str] = field(default_factory=list)
    missing_evidence_types: List[str] = field(default_factory=list)
    evidence_degraded: bool = False
    patch_mechanism_signals: List[str] = field(default_factory=list)
    silencing_conditions: List[str] = field(default_factory=list)
    retry_guidance: List[str] = field(default_factory=list)
    selected_evidence_ids: List[str] = field(default_factory=list)
    selected_evidence: List[Dict[str, Any]] = field(default_factory=list)
    semantic_slice_count: int = 0
    context_summary_count: int = 0
    semantic_slice_coverage: str = ""
    selected_semantic_slice_ids: List[str] = field(default_factory=list)
    selected_context_summary_ids: List[str] = field(default_factory=list)
    selected_semantic_slices: List[Dict[str, Any]] = field(default_factory=list)
    selected_context_summaries: List[Dict[str, Any]] = field(default_factory=list)
    semantic_clause_plan: List[Dict[str, Any]] = field(default_factory=list)
    repair_directives: List[Dict[str, Any]] = field(default_factory=list)
    constraints: List[SynthesisConstraint] = field(default_factory=list)
    implementation_hints: List[str] = field(default_factory=list)
    validation_expectations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "analyzer_id": self.analyzer_id,
            "detector_artifact": self.detector_artifact,
            "primary_pattern": self.primary_pattern,
            "objective": self.objective,
            "mechanism_contract": self.mechanism_contract.to_dict() if self.mechanism_contract else {},
            "detector_name_hint": self.detector_name_hint,
            "focus_files": list(self.focus_files),
            "focus_functions": list(self.focus_functions),
            "hypotheses": list(self.hypotheses),
            "required_evidence_types": list(self.required_evidence_types),
            "missing_evidence_types": list(self.missing_evidence_types),
            "evidence_degraded": self.evidence_degraded,
            "patch_mechanism_signals": list(self.patch_mechanism_signals),
            "silencing_conditions": list(self.silencing_conditions),
            "retry_guidance": list(self.retry_guidance),
            "selected_evidence_ids": list(self.selected_evidence_ids),
            "selected_evidence": list(self.selected_evidence),
            "semantic_slice_count": self.semantic_slice_count,
            "context_summary_count": self.context_summary_count,
            "semantic_slice_coverage": self.semantic_slice_coverage,
            "selected_semantic_slice_ids": list(self.selected_semantic_slice_ids),
            "selected_context_summary_ids": list(self.selected_context_summary_ids),
            "selected_semantic_slices": list(self.selected_semantic_slices),
            "selected_context_summaries": list(self.selected_context_summaries),
            "semantic_clause_plan": list(self.semantic_clause_plan),
            "repair_directives": list(self.repair_directives),
            "constraints": [item.to_dict() for item in self.constraints],
            "implementation_hints": list(self.implementation_hints),
            "validation_expectations": list(self.validation_expectations),
        }

    def to_prompt_block(self) -> str:
        """Render a compact but structured prompt block."""
        lines = [
            "## PATCHWEAVER Synthesis Contract",
            f"- target_analyzer: {self.analyzer_id}",
            f"- detector_artifact: {self.detector_artifact}",
            f"- primary_pattern: {self.primary_pattern}",
            f"- objective: {self.objective}",
        ]
        if self.mechanism_contract:
            lines.append(f"- mechanism_family: {self.mechanism_contract.mechanism_family}")
            if self.mechanism_contract.semantic_dimensions:
                lines.append(f"- mechanism_dimensions: {'; '.join(self.mechanism_contract.semantic_dimensions[:4])}")
            if self.mechanism_contract.evidence_backed_axes:
                lines.append(f"- evidence_backed_axes: {'; '.join(self.mechanism_contract.evidence_backed_axes[:4])}")
            if self.mechanism_contract.transfer_axes:
                lines.append(f"- transfer_axes: {'; '.join(self.mechanism_contract.transfer_axes[:4])}")
            if self.mechanism_contract.forbidden_shortcuts:
                lines.append(f"- forbidden_shortcuts: {'; '.join(self.mechanism_contract.forbidden_shortcuts[:4])}")
        if self.detector_name_hint:
            lines.append(f"- detector_name_hint: {self.detector_name_hint}")
        if self.focus_files:
            lines.append(f"- focus_files: {', '.join(self.focus_files[:4])}")
        if self.focus_functions:
            lines.append(f"- focus_functions: {', '.join(self.focus_functions[:6])}")
        if self.required_evidence_types:
            lines.append(f"- required_evidence_types: {', '.join(self.required_evidence_types)}")
        if self.missing_evidence_types:
            lines.append(f"- missing_evidence_types: {', '.join(self.missing_evidence_types)}")
        if self.evidence_degraded:
            lines.append("- evidence_degraded: true")
        if self.patch_mechanism_signals:
            lines.append(f"- patch_mechanism_signals: {'; '.join(self.patch_mechanism_signals[:4])}")
        if self.silencing_conditions:
            lines.append(f"- silencing_conditions: {'; '.join(self.silencing_conditions[:3])}")
        if self.retry_guidance:
            lines.append(f"- retry_guidance: {'; '.join(self.retry_guidance[:3])}")
        if self.selected_evidence_ids:
            lines.append(f"- selected_evidence_ids: {', '.join(self.selected_evidence_ids[:8])}")
        if self.semantic_slice_count:
            lines.append(f"- semantic_slice_count: {self.semantic_slice_count}")
        if self.context_summary_count:
            lines.append(f"- context_summary_count: {self.context_summary_count}")
        if self.semantic_slice_coverage:
            lines.append(f"- semantic_slice_coverage: {self.semantic_slice_coverage}")
        if self.selected_semantic_slice_ids:
            lines.append(f"- selected_semantic_slice_ids: {', '.join(self.selected_semantic_slice_ids[:6])}")
        if self.selected_context_summary_ids:
            lines.append(f"- selected_context_summary_ids: {', '.join(self.selected_context_summary_ids[:4])}")
        if self.semantic_clause_plan:
            clause_ids = [str(item.get("clause_id", "")).strip() for item in self.semantic_clause_plan if str(item.get("clause_id", "")).strip()]
            if clause_ids:
                lines.append(f"- semantic_clause_plan: {', '.join(clause_ids[:4])}")
        if self.repair_directives:
            modes = [str(item.get("failure_mode", "")).strip() for item in self.repair_directives if str(item.get("failure_mode", "")).strip()]
            if modes:
                lines.append(f"- repair_directives: {', '.join(modes[:4])}")
        if self.implementation_hints:
            lines.append("- implementation_hints:")
            for item in self.implementation_hints[:8]:
                lines.append(f"  - {item}")
        if self.validation_expectations:
            lines.append("- validation_expectations:")
            for item in self.validation_expectations[:4]:
                lines.append(f"  - {item}")

        lines.append("")
        lines.append("```json")
        lines.append(json.dumps(self.to_dict(), ensure_ascii=False, indent=2))
        lines.append("```")
        return "\n".join(lines)


class DetectorSynthesisInputBuilder:
    """Build structured synthesis contracts from PATCHWEAVER evidence."""

    def build(
        self,
        descriptor: AnalyzerDescriptor,
        context: AnalyzerContext,
        evidence_bundle: EvidenceBundle,
    ) -> DetectorSynthesisInput:
        shared = context.shared_analysis or {}
        patchweaver = shared.get("patchweaver", {}) or {}
        evidence_plan = patchweaver.get("evidence_plan", {}) or {}
        focus_files = self._focus_files(shared)
        focus_functions = self._focus_functions(shared)
        selected = self._select_relevant_evidence(
            analyzer_id=descriptor.id,
            evidence_bundle=evidence_bundle,
            focus_files=focus_files,
            focus_functions=focus_functions,
        )
        semantic_slices = [record for record in selected if EvidenceNormalizer.is_semantic_slice(record)]
        context_summaries = [record for record in selected if EvidenceNormalizer.is_context_summary(record)]
        slice_metrics = EvidenceNormalizer.slice_metrics(evidence_bundle, analyzer=descriptor.id)

        primary_pattern = self._primary_pattern(shared)
        detector_artifact = descriptor.detector_artifacts[0] if descriptor.detector_artifacts else "detector"
        objective = self._objective_for(descriptor.id, primary_pattern)
        patch_mechanism_signals = self._patch_mechanism_signals(shared, primary_pattern)
        silencing_conditions = self._silencing_conditions(
            analyzer_id=descriptor.id,
            shared=shared,
            primary_pattern=primary_pattern,
        )
        mechanism_contract = self._build_mechanism_contract(
            analyzer_id=descriptor.id,
            primary_pattern=primary_pattern,
            shared=shared,
            selected_records=selected,
            patch_mechanism_signals=patch_mechanism_signals,
            silencing_conditions=silencing_conditions,
        )
        retry_guidance = self._retry_guidance(shared, evidence_bundle)
        semantic_clause_plan = self._semantic_clause_plan(
            analyzer_id=descriptor.id,
            selected_records=selected,
            primary_pattern=primary_pattern,
            silencing_conditions=silencing_conditions,
            focus_functions=focus_functions,
        )
        repair_directives = self._repair_directives(
            evidence_bundle=evidence_bundle,
            shared=shared,
            clause_plan=semantic_clause_plan,
        )
        prefer_consumer_lifetime_mode = self._prefer_consumer_lifetime_mode(
            shared=shared,
            primary_pattern=primary_pattern,
        )

        constraints = self._constraints_for(
            analyzer_id=descriptor.id,
            primary_pattern=primary_pattern,
            detector_artifact=detector_artifact,
            focus_files=focus_files,
            focus_functions=focus_functions,
            fix_patterns=self._fix_patterns(shared),
            added_apis=self._added_apis(shared),
            added_guards=self._added_guards(shared),
            removed_operations=self._removed_risky_operations(shared),
            silencing_conditions=silencing_conditions,
            retry_guidance=retry_guidance,
            mechanism_contract=mechanism_contract,
            prefer_consumer_lifetime_mode=prefer_consumer_lifetime_mode,
        )
        implementation_hints = self._implementation_hints(
            descriptor.id,
            primary_pattern,
            selected,
            shared,
            list(evidence_bundle.missing_evidence),
            patch_mechanism_signals,
            silencing_conditions,
            retry_guidance,
            repair_directives,
            mechanism_contract,
            prefer_consumer_lifetime_mode,
        )
        validation_expectations = self._validation_expectations(
            primary_pattern=primary_pattern,
            silencing_conditions=silencing_conditions,
            retry_guidance=retry_guidance,
            mechanism_contract=mechanism_contract,
            prefer_consumer_lifetime_mode=prefer_consumer_lifetime_mode,
        )

        detector_name_hint = str(shared.get("checker_name_suggestion", "") or "")
        if descriptor.id == "codeql" and detector_name_hint.endswith("Checker"):
            detector_name_hint = detector_name_hint[:-7] or detector_name_hint

        return DetectorSynthesisInput(
            analyzer_id=descriptor.id,
            detector_artifact=detector_artifact,
            primary_pattern=primary_pattern,
            objective=objective,
            mechanism_contract=mechanism_contract,
            detector_name_hint=detector_name_hint,
            focus_files=focus_files,
            focus_functions=focus_functions,
            hypotheses=list(evidence_plan.get("hypotheses", []) or []),
            required_evidence_types=[
                item.get("evidence_type", "")
                for item in (evidence_plan.get("requirements", []) or [])
                if item.get("evidence_type")
            ],
            missing_evidence_types=list(evidence_bundle.missing_evidence),
            evidence_degraded=bool(evidence_bundle.missing_evidence),
            patch_mechanism_signals=patch_mechanism_signals,
            silencing_conditions=silencing_conditions,
            retry_guidance=retry_guidance,
            selected_evidence_ids=[record.evidence_id for record in selected],
            selected_evidence=[self._compact_record(record) for record in selected],
            semantic_slice_count=int(slice_metrics.get("semantic_slice_count", 0) or 0),
            context_summary_count=int(slice_metrics.get("context_summary_count", 0) or 0),
            semantic_slice_coverage=str(slice_metrics.get("coverage", "") or ""),
            selected_semantic_slice_ids=[record.evidence_id for record in semantic_slices],
            selected_context_summary_ids=[record.evidence_id for record in context_summaries],
            selected_semantic_slices=[self._compact_record(record) for record in semantic_slices[:6]],
            selected_context_summaries=[self._compact_record(record) for record in context_summaries[:4]],
            semantic_clause_plan=semantic_clause_plan,
            repair_directives=repair_directives,
            constraints=constraints,
            implementation_hints=implementation_hints,
            validation_expectations=validation_expectations,
        )

    def _select_relevant_evidence(
        self,
        analyzer_id: str,
        evidence_bundle: EvidenceBundle,
        focus_files: List[str],
        focus_functions: List[str],
    ) -> List[EvidenceRecord]:
        if not evidence_bundle:
            return []
        relevant = [
            record
            for record in evidence_bundle.records
            if record.analyzer in {analyzer_id, "patch"}
        ]
        analyzer_records = [record for record in relevant if record.analyzer == analyzer_id]
        patch_records = [record for record in relevant if record.analyzer == "patch"]

        analyzer_records.sort(
            key=lambda item: (
                0 if EvidenceNormalizer.is_semantic_slice(item) else (1 if EvidenceNormalizer.is_context_summary(item) else 2),
                0 if EvidenceNormalizer.is_verifier_backed_slice(item) else 1,
                -self._focus_score(item, focus_files, focus_functions),
                -(item.provenance.confidence if item.provenance else 0.0),
                item.type,
            )
        )
        patch_records.sort(
            key=lambda item: (
                self._patch_fact_priority(item),
                -self._focus_score(item, focus_files, focus_functions),
                -(item.provenance.confidence if item.provenance else 0.0),
                item.type,
            )
        )

        selected: List[EvidenceRecord] = []
        seen_novelty = set()
        path_guard_count = 0
        analyzer_limit = 4
        selected_context_summary = False
        for record in analyzer_records:
            if len(selected) >= analyzer_limit:
                break
            if record.type == "path_guard" and path_guard_count >= 2:
                continue
            novelty_key = self._record_novelty_key(record)
            if novelty_key in seen_novelty:
                continue
            seen_novelty.add(novelty_key)
            selected.append(record)
            if record.type == "path_guard":
                path_guard_count += 1
            if EvidenceNormalizer.is_context_summary(record):
                selected_context_summary = True

        if not selected_context_summary:
            context_candidate = next(
                (
                    record
                    for record in analyzer_records
                    if EvidenceNormalizer.is_context_summary(record)
                    and self._record_novelty_key(record) not in seen_novelty
                ),
                None,
            )
            if context_candidate is not None:
                if len(selected) >= analyzer_limit:
                    removed = selected.pop()
                    seen_novelty.discard(self._record_novelty_key(removed))
                    if removed.type == "path_guard":
                        path_guard_count = max(0, path_guard_count - 1)
                selected.append(context_candidate)
                seen_novelty.add(self._record_novelty_key(context_candidate))

        for record in patch_records:
            if len(selected) >= 9:
                break
            novelty_key = self._record_novelty_key(record)
            if novelty_key in seen_novelty:
                continue
            seen_novelty.add(novelty_key)
            selected.append(record)

        for record in analyzer_records:
            if len(selected) >= 9:
                break
            novelty_key = self._record_novelty_key(record)
            if novelty_key in seen_novelty:
                continue
            seen_novelty.add(novelty_key)
            selected.append(record)

        return selected[:9]

    def _patch_fact_priority(self, record: EvidenceRecord) -> int:
        if record.type != "patch_fact":
            return 100
        fact_type = str((record.semantic_payload or {}).get("fact_type", "") or "").strip()
        priority = {
            "removed_risky_operations": 0,
            "added_guards": 1,
            "fix_patterns": 2,
            "added_api_calls": 3,
            "detection_strategy": 4,
            "affected_functions": 5,
            "vulnerability_patterns": 6,
            "patch_overview": 7,
        }
        return priority.get(fact_type, 50)

    def _record_novelty_key(self, record: EvidenceRecord) -> tuple:
        payload = record.semantic_payload or {}
        return (
            record.type,
            record.scope.file,
            record.scope.function,
            str(payload.get("fact_type", "") or payload.get("guard_expr", "") or payload.get("summary", "") or ""),
        )

    def _primary_pattern(self, shared: Dict[str, Any]) -> str:
        profiles = {
            "buffer_overflow",
            "out_of_bounds_read",
            "null_dereference",
            "use_after_free",
            "double_free",
            "memory_leak",
            "uninitialized_variable",
            "integer_overflow",
            "divide_by_zero",
            "race_condition",
            "command_injection",
            "path_traversal",
            "sql_injection",
            "format_string",
        }

        strategy = shared.get("detection_strategy", {}) or {}
        if strategy.get("primary_pattern"):
            primary = normalize_vulnerability_type(str(strategy["primary_pattern"]))
            family = mechanism_family_for_vulnerability(primary)
            return primary if primary in profiles else (family or primary or "unknown")
        patchweaver = shared.get("patchweaver", {}) or {}
        evidence_plan = patchweaver.get("evidence_plan", {}) or {}
        if evidence_plan.get("primary_pattern"):
            primary = normalize_vulnerability_type(str(evidence_plan["primary_pattern"]))
            family = mechanism_family_for_vulnerability(primary)
            return primary if primary in profiles else (family or primary or "unknown")
        patterns = shared.get("vulnerability_patterns", []) or []
        for item in patterns:
            pattern = normalize_vulnerability_type(str(item.get("type", "")).strip())
            if pattern:
                family = mechanism_family_for_vulnerability(pattern)
                return pattern if pattern in profiles else (family or pattern)
        return "unknown"

    def _objective_for(self, analyzer_id: str, primary_pattern: str) -> str:
        if primary_pattern == "unknown":
            if analyzer_id == "csa":
                return (
                    "Synthesize a path-sensitive detector that encodes the patch-evidenced local state, guards, "
                    "and lifecycle mechanism, while remaining open to the true vulnerability family being uncertain."
                )
            if analyzer_id == "codeql":
                return (
                    "Synthesize a reusable query centered on the patch-evidenced semantic mechanism, interprocedural flow, "
                    "and API or state contract, without hard-coding an uncertain vulnerability label."
                )
            return "Synthesize a reusable detector from structured patch evidence without assuming a precise vulnerability label."
        if analyzer_id == "csa":
            return (
                f"Synthesize a path-sensitive {primary_pattern} detector that encodes the same local state, guards, "
                "and lifecycle mechanism evidenced by the patch, while still generalizing to semantically equivalent sites."
            )
        if analyzer_id == "codeql":
            return (
                f"Synthesize a reusable {primary_pattern} query that captures the same semantic mechanism, "
                "interprocedural flow, or API contract implied by the patch rather than a generic broad class proxy."
            )
        return f"Synthesize a reusable {primary_pattern} detector from structured evidence."

    def _build_mechanism_contract(
        self,
        analyzer_id: str,
        primary_pattern: str,
        shared: Dict[str, Any],
        selected_records: List[EvidenceRecord],
        patch_mechanism_signals: List[str],
        silencing_conditions: List[str],
    ) -> MechanismContract:
        profile = self._pattern_profile(primary_pattern)
        evidence_axes = self._evidence_backed_axes(selected_records)
        transfer_axes = list(profile.get("transfer_axes", []))

        if "path guards and barrier conditions" in evidence_axes:
            transfer_axes.append("equivalent guard or barrier predicates on sibling paths")
        if "state transitions" in evidence_axes:
            transfer_axes.append("equivalent local state transitions around the same sink or dereference")
        if "resource lifecycle" in evidence_axes:
            transfer_axes.append("equivalent ownership or release/reinit lifecycle on the same symbolic resource")
        if "interprocedural flow" in evidence_axes:
            transfer_axes.append("equivalent interprocedural propagation across adjacent helpers or wrappers")
        if "api contracts" in evidence_axes:
            transfer_axes.append("equivalent API roles rather than exact callee spellings")

        trigger_invariants = list(profile.get("trigger_invariants", []))
        for item in patch_mechanism_signals[:3]:
            trigger_invariants.append(f"Patch-backed trigger clue: {item}")

        silence_invariants = list(profile.get("silence_invariants", []))
        silence_invariants.extend(silencing_conditions[:4])

        forbidden_shortcuts = [
            "bind the detector to fixed file paths, line numbers, or exact patch strings",
            "broaden into unrelated bug families just to improve hit count",
        ]
        forbidden_shortcuts.extend(profile.get("forbidden_shortcuts", []))
        if analyzer_id == "csa":
            forbidden_shortcuts.append("placeholder helper logic or empty ProgramState modeling")
        if analyzer_id == "codeql":
            forbidden_shortcuts.append("callee-only matching or stringified guard inference instead of structured predicates")

        return MechanismContract(
            mechanism_family=str(profile.get("mechanism_family", "generic_vulnerability_mechanism")),
            semantic_dimensions=self._dedupe_strings(list(profile.get("semantic_dimensions", []))),
            trigger_invariants=self._dedupe_strings(trigger_invariants)[:6],
            silence_invariants=self._dedupe_strings(silence_invariants)[:6],
            transfer_axes=self._dedupe_strings(transfer_axes)[:6],
            forbidden_shortcuts=self._dedupe_strings(forbidden_shortcuts)[:6],
            evidence_backed_axes=self._dedupe_strings(evidence_axes)[:6],
        )

    def _pattern_profile(self, primary_pattern: str) -> Dict[str, Any]:
        pattern = str(primary_pattern or "").strip().lower()
        profiles: Dict[str, Dict[str, Any]] = {
            "buffer_overflow": {
                "mechanism_family": "memory_write_without_proven_bound",
                "semantic_dimensions": [
                    "write or copy sink",
                    "destination object or buffer identity",
                    "length/capacity relation",
                    "guard or safe-API barrier",
                ],
                "trigger_invariants": [
                    "a write-like sink is reached",
                    "destination capacity is not proven sufficient for the copied data",
                    "the current path lacks a barrier that proves the write is bounded",
                ],
                "silence_invariants": [
                    "a guard or checked bounded API proves the write fits the destination",
                    "patch-style length or return-value validation blocks the unsafe write",
                ],
                "transfer_axes": [
                    "equivalent sink/size relationships across sibling functions",
                    "equivalent guard omission around the same bounded destination model",
                ],
                "forbidden_shortcuts": [
                    "treat every risky copy API as a finding without size semantics",
                    "infer guard semantics from strings instead of AST/state relations",
                ],
            },
            "null_dereference": {
                "mechanism_family": "nullability_contract_violation",
                "semantic_dimensions": [
                    "pointer-like value",
                    "dereference or call sink",
                    "nonnull proof or dominating guard",
                ],
                "trigger_invariants": [
                    "a pointer-like value reaches dereference, field access, or indirect call",
                    "the active path does not prove the value is non-null",
                ],
                "silence_invariants": [
                    "a dominating non-null check or successful initializer proves the value is safe",
                    "patch-added early return or validation guard blocks the null path",
                ],
                "transfer_axes": [
                    "equivalent nullability guards before sibling dereference sites",
                    "equivalent initialization or validation patterns for the same pointer role",
                ],
                "forbidden_shortcuts": [
                    "report every pointer dereference regardless of path proof",
                    "confuse null checks with unrelated branch conditions",
                ],
            },
            "use_after_free": {
                "mechanism_family": "resource_lifetime_violation",
                "semantic_dimensions": [
                    "resource identity or alias",
                    "release event",
                    "later use sink on the same resource",
                    "reinitialization/nulling/ownership transfer barrier",
                ],
                "trigger_invariants": [
                    "a resource is released",
                    "the same symbolic resource reaches a later use without reinitialization or ownership transfer",
                ],
                "silence_invariants": [
                    "the resource is nulled, rebound, or reinitialized before reuse",
                    "ownership transfer or guard logic blocks access after release",
                ],
                "transfer_axes": [
                    "equivalent release-then-use sequences on the same resource role",
                    "equivalent lifecycle transitions across wrappers or helper functions",
                ],
                "forbidden_shortcuts": [
                    "report every free/delete call as if it were a bug",
                    "ignore resource identity and alias continuity between release and use",
                    "identify resources only by variable or field names such as session/cache/context instead of lifecycle evidence",
                ],
            },
            "double_free": {
                "mechanism_family": "resource_lifetime_violation",
                "semantic_dimensions": [
                    "resource identity or alias",
                    "release event count",
                    "reinitialization or nulling barrier",
                ],
                "trigger_invariants": [
                    "the same symbolic resource is released more than once on a feasible path",
                    "no reallocation, rebinding, or nulling separates the release events",
                ],
                "silence_invariants": [
                    "the resource is nulled, transferred, or rebound after the first release",
                    "a guard prevents the second release on the active path",
                ],
                "transfer_axes": [
                    "equivalent repeated-release sequences for the same resource role",
                    "equivalent ownership handoff patterns across sibling helpers",
                ],
                "forbidden_shortcuts": [
                    "count free/delete calls without tracking resource identity",
                    "treat unrelated release sites as the same resource lifecycle",
                ],
            },
            "integer_overflow": {
                "mechanism_family": "arithmetic_bound_violation",
                "semantic_dimensions": [
                    "arithmetic operands",
                    "range or width constraint",
                    "downstream allocation/index/write sink",
                ],
                "trigger_invariants": [
                    "size/count arithmetic feeds a sensitive sink such as allocation, indexing, or copy length",
                    "the path lacks a proof that the arithmetic stays within the intended range",
                ],
                "silence_invariants": [
                    "overflow checks, clamps, widened types, or guard predicates prove safe range",
                    "patch-added validation blocks out-of-range arithmetic before the sink",
                ],
                "transfer_axes": [
                    "equivalent arithmetic-to-sink relationships on sibling code paths",
                    "equivalent range guards for the same size/count role",
                ],
                "forbidden_shortcuts": [
                    "flag every large integer expression without sink semantics",
                    "ignore the relation between arithmetic result and the downstream sink",
                ],
            },
            "divide_by_zero": {
                "mechanism_family": "arithmetic_guard_violation",
                "semantic_dimensions": [
                    "divisor expression",
                    "division or modulo sink",
                    "zero-check barrier",
                ],
                "trigger_invariants": [
                    "a divisor reaches division or modulo",
                    "the active path does not prove the divisor is non-zero",
                ],
                "silence_invariants": [
                    "a dominating non-zero guard or early return blocks the zero path",
                    "patch-added validation proves the divisor is constrained before the sink",
                ],
                "transfer_axes": [
                    "equivalent divisor validation around sibling arithmetic sinks",
                    "equivalent guard omission on the same parameter or field role",
                ],
                "forbidden_shortcuts": [
                    "flag every arithmetic expression regardless of operator and divisor role",
                    "treat unrelated range checks as proof that the divisor is non-zero",
                ],
            },
            "out_of_bounds_read": {
                "mechanism_family": "memory_read_without_proven_bound",
                "semantic_dimensions": [
                    "read or dereference sink",
                    "buffer or region identity",
                    "index/offset/end-pointer relation",
                    "guard or sentinel barrier",
                ],
                "trigger_invariants": [
                    "a read-like sink is reached",
                    "the path does not prove the read stays inside the intended region",
                ],
                "silence_invariants": [
                    "index, size, or end-pointer checks prove the read stays in bounds",
                    "patch-added sentinel or length validation blocks the unsafe read",
                ],
                "transfer_axes": [
                    "equivalent index-to-buffer relations across sibling readers",
                    "equivalent end-pointer or length guards for the same data role",
                ],
                "forbidden_shortcuts": [
                    "flag every array access without modeling index and region semantics",
                    "infer safe bounds from unrelated null or type checks",
                ],
            },
            "memory_leak": {
                "mechanism_family": "resource_lifetime_leak",
                "semantic_dimensions": [
                    "allocation source",
                    "ownership scope",
                    "release obligations on exit paths",
                ],
                "trigger_invariants": [
                    "a resource is allocated or acquired",
                    "a feasible exit path leaves the scope without releasing or transferring ownership",
                ],
                "silence_invariants": [
                    "all relevant exit paths release, transfer, or intentionally retain ownership",
                    "patch-added cleanup paths or defer-style release blocks the leak",
                ],
                "transfer_axes": [
                    "equivalent allocation and cleanup contracts across sibling helpers",
                    "equivalent early-return cleanup omissions on adjacent paths",
                ],
                "forbidden_shortcuts": [
                    "report every allocation without checking ownership handoff",
                    "treat any free in the function as proof that all paths are safe",
                ],
            },
            "uninitialized_variable": {
                "mechanism_family": "initialization_contract_violation",
                "semantic_dimensions": [
                    "variable or field identity",
                    "definition/init path",
                    "read or branch sink",
                ],
                "trigger_invariants": [
                    "a variable or field reaches a read-like sink",
                    "the active path lacks a dominating initializer for that storage",
                ],
                "silence_invariants": [
                    "a dominating assignment, zero-init, or constructor path proves initialization",
                    "patch-added initialization or guard blocks the uninitialized path",
                ],
                "transfer_axes": [
                    "equivalent init-before-use contracts across sibling variables",
                    "equivalent constructor or reset responsibilities for the same field role",
                ],
                "forbidden_shortcuts": [
                    "treat declaration without inline initializer as a finding by itself",
                    "ignore path-sensitive writes that dominate the later use",
                ],
            },
            "race_condition": {
                "mechanism_family": "shared_state_atomicity_violation",
                "semantic_dimensions": [
                    "shared state object",
                    "critical section boundary",
                    "check/use/update window",
                    "lock or atomic barrier",
                ],
                "trigger_invariants": [
                    "shared state is observed and mutated across a race-prone window",
                    "the path lacks synchronization that makes the compound action atomic",
                ],
                "silence_invariants": [
                    "lock, atomic, or serialized region proves exclusive access for the critical sequence",
                    "patch-added synchronization or retry logic closes the race window",
                ],
                "transfer_axes": [
                    "equivalent shared-state access windows across sibling handlers",
                    "equivalent synchronization contracts around the same state role",
                ],
                "forbidden_shortcuts": [
                    "report every shared-state access without modeling synchronization",
                    "equate any mutex call with proof of correct atomicity",
                ],
            },
            "command_injection": {
                "mechanism_family": "untrusted_input_to_sensitive_sink",
                "semantic_dimensions": [
                    "untrusted source",
                    "sensitive execution sink",
                    "sanitizer, allowlist, or prepared-interface barrier",
                ],
                "trigger_invariants": [
                    "untrusted or externally influenced data reaches a sensitive execution sink",
                    "the path lacks a sanitizer, allowlist, or constrained execution barrier",
                ],
                "silence_invariants": [
                    "validated command construction or allowlist logic proves the sink input is constrained",
                    "patch-added escaping or safe API usage blocks arbitrary execution",
                ],
                "transfer_axes": [
                    "equivalent source-to-sink propagation chains across helpers",
                    "equivalent sanitizer or allowlist contracts for the same sink role",
                ],
                "forbidden_shortcuts": [
                    "report every shell or exec API call without source/sanitizer semantics",
                    "treat string presence as proof of taint or sanitization",
                ],
            },
            "path_traversal": {
                "mechanism_family": "untrusted_input_to_sensitive_sink",
                "semantic_dimensions": [
                    "path-like input source",
                    "filesystem sink",
                    "canonicalization or root-boundary barrier",
                ],
                "trigger_invariants": [
                    "externally influenced path data reaches a filesystem sink",
                    "the path lacks canonicalization, allowlist, or root-boundary validation",
                ],
                "silence_invariants": [
                    "canonicalization or root-prefix validation proves the path stays inside the allowed boundary",
                    "patch-added rejection of traversal tokens blocks unsafe paths",
                ],
                "transfer_axes": [
                    "equivalent path-source to filesystem-sink flows",
                    "equivalent canonicalization or base-directory checks across sibling handlers",
                ],
                "forbidden_shortcuts": [
                    "flag every file API call without user-controlled path semantics",
                    "look only for '../' strings without normalization semantics",
                ],
            },
            "sql_injection": {
                "mechanism_family": "untrusted_input_to_sensitive_sink",
                "semantic_dimensions": [
                    "query-building source",
                    "database execution sink",
                    "prepared statement or parameterization barrier",
                ],
                "trigger_invariants": [
                    "externally influenced data flows into a query execution sink",
                    "the path lacks parameterization or sanitizer semantics",
                ],
                "silence_invariants": [
                    "prepared statements, bound parameters, or allowlist validation prove safe construction",
                    "patch-added query builder or escaping logic blocks raw injection",
                ],
                "transfer_axes": [
                    "equivalent source-to-query-sink propagation chains",
                    "equivalent parameterization contracts across sibling database helpers",
                ],
                "forbidden_shortcuts": [
                    "report every SQL execution API call without taint semantics",
                    "infer injection only from string concatenation syntax without sink role",
                ],
            },
        }
        fallback = {
            "mechanism_family": "generic_vulnerability_mechanism",
            "semantic_dimensions": [
                "vulnerability trigger",
                "patch-introduced barrier",
                "local state or flow relation",
            ],
            "trigger_invariants": [
                "the vulnerable mechanism is reachable on a feasible path",
                "the path lacks the barrier introduced by the patch",
            ],
            "silence_invariants": [
                "patch-introduced guards, barriers, or safe APIs must suppress findings",
            ],
            "transfer_axes": [
                "only generalize along evidence-backed state, guard, flow, or API-role equivalence",
            ],
            "forbidden_shortcuts": [
                "use the patch text itself as the matching rule",
                "widen to unrelated bug families without evidence",
            ],
        }
        return profiles.get(pattern, fallback)

    def _evidence_backed_axes(self, records: List[EvidenceRecord]) -> List[str]:
        axes: List[str] = []
        for record in records:
            slice_kind = str((record.evidence_slice.kind if record.evidence_slice else "") or "").strip()
            if record.type == "semantic_slice" or slice_kind == "semantic_slice":
                axes.append("semantic trigger slice")
            if record.type == "path_guard" or slice_kind == "path_witness":
                axes.append("path guards and barrier conditions")
            if record.type == "state_transition" or slice_kind == "state_witness":
                axes.append("state transitions")
            if record.type == "allocation_lifecycle":
                axes.append("resource lifecycle")
            if record.type == "dataflow_candidate" or slice_kind == "flow_witness":
                axes.append("source-to-sink flow")
            if record.type == "call_chain" or slice_kind == "interprocedural_slice":
                axes.append("interprocedural flow")
            if record.type == "api_contract" or slice_kind == "api_contract_slice":
                axes.append("api contracts")
            if record.type == "metadata_hint" or slice_kind == "intent_slice":
                axes.append("patch intent and barrier semantics")
            if record.type == "context_summary" or slice_kind == "context_summary":
                axes.append("project and build context")
        return self._dedupe_strings(axes)

    def _constraints_for(
        self,
        analyzer_id: str,
        primary_pattern: str,
        detector_artifact: str,
        focus_files: List[str],
        focus_functions: List[str],
        fix_patterns: List[str],
        added_apis: List[str],
        added_guards: List[str],
        removed_operations: List[str],
        silencing_conditions: List[str],
        retry_guidance: List[str],
        mechanism_contract: MechanismContract,
        prefer_consumer_lifetime_mode: bool,
    ) -> List[SynthesisConstraint]:
        constraints = [
            SynthesisConstraint(
                title="Generalize beyond patch site",
                description="Do not bind the detector to fixed file paths, line numbers, or exact patch strings.",
            ),
            SynthesisConstraint(
                title="Preserve vulnerability semantics",
                description="Keep the detector focused on the vulnerability family implied by the patch and evidence.",
            ),
            SynthesisConstraint(
                title="Respect analyzer-native form",
                description=f"Output must be a valid {detector_artifact} for {analyzer_id}.",
            ),
            SynthesisConstraint(
                title="Stay within proven mechanism scope",
                description=(
                    "Generalize only along evidence-supported semantic dimensions. "
                    "Do not broaden the detector into unrelated globals, APIs, or bug families."
                ),
            ),
            SynthesisConstraint(
                title="Honor mechanism contract",
                description=(
                    "Preserve the mechanism family `"
                    + mechanism_contract.mechanism_family
                    + "` by keeping trigger invariants "
                    + "; ".join(mechanism_contract.trigger_invariants[:3])
                    + "."
                ),
            ),
            SynthesisConstraint(
                title="Generalize only on contract axes",
                description="Reuse semantics only along these transfer axes: " + "; ".join(mechanism_contract.transfer_axes[:3]) + ".",
            ),
        ]

        if focus_files or focus_functions:
            constraints.append(
                SynthesisConstraint(
                    title="Anchor on patch-touched scope",
                    description=(
                        "Use patch-touched files/functions as the semantic anchor for synthesis. "
                        "Only extend beyond them when the same mechanism is explicitly supported by evidence."
                    ),
                )
            )

        if fix_patterns or added_apis or added_guards:
            parts: List[str] = []
            if fix_patterns:
                parts.append(f"model the absence of barriers like {', '.join(fix_patterns[:4])}")
            if added_guards:
                parts.append(f"treat guards such as {', '.join(added_guards[:3])} as semantic barriers")
            if added_apis:
                parts.append(f"use APIs such as {', '.join(added_apis[:6])} as semantic clues, not string matches")
            constraints.append(
                SynthesisConstraint(
                    title="Encode the patch-added barrier",
                    description="; ".join(parts) + ".",
                )
            )

        if silencing_conditions:
            constraints.append(
                SynthesisConstraint(
                    title="Respect patched silence",
                    description="Use these no-report conditions when they are semantically proven: " + "; ".join(silencing_conditions[:3]) + ".",
                )
            )

        if retry_guidance:
            constraints.append(
                SynthesisConstraint(
                    title="Counterexample-guided repair",
                    description="Fix prior validation failures first: " + "; ".join(retry_guidance[:3]) + ".",
                )
            )

        if primary_pattern == "buffer_overflow" and removed_operations:
            constraints.append(
                SynthesisConstraint(
                    title="Model unchecked bounded writes",
                    description=(
                        "Target writes equivalent to removed risky operations such as "
                        + "; ".join(removed_operations[:3])
                        + ", but only when no guard proves the destination bound is respected."
                    ),
                )
            )
            constraints.append(
                SynthesisConstraint(
                    title="Do not drop symbolic unbounded sinks",
                    description=(
                        "For patch-removed unbounded string writes such as strcpy/strcat/sprintf/gets, "
                        "do not silently suppress the finding just because exact source length is symbolic; "
                        "only a patch-style bound proof or safe-API barrier may silence the detector."
                    ),
                )
            )
        elif mechanism_contract.mechanism_family == "resource_lifetime_violation":
            constraints.append(
                SynthesisConstraint(
                    title="Track resource identity across lifetime edges",
                    description="Model release, reuse, reinitialization, and ownership transfer on the same symbolic resource; do not count frees or uses in isolation.",
                )
            )
            constraints.append(
                SynthesisConstraint(
                    title="Do not key on local identifier names",
                    description="Do not define the vulnerable resource role solely by field/variable names such as session/cache/context; infer it from release-use-nulling-relookup semantics and alias continuity.",
                )
            )
            if prefer_consumer_lifetime_mode:
                constraints.append(
                    SynthesisConstraint(
                        title="Prefer authoritative-relookup contract over hidden producer paths",
                        description=(
                            "When the patch replaces direct cached-pointer use with stable-handle validation plus authoritative relookup, "
                            "the detector should prefer consumer-side stale-cache / missing-relookup semantics over requiring a full cross-function release->use path."
                        ),
                    )
                )
                constraints.append(
                    SynthesisConstraint(
                        title="Do not treat nullness as freshness",
                        description=(
                            "Null/non-null checks on cached resources are not proof that the object is still fresh; "
                            "use explicit invalidation, authoritative relookup, rebinding, or ownership transfer as silence conditions."
                        ),
                    )
                )
        elif mechanism_contract.mechanism_family == "nullability_contract_violation":
            constraints.append(
                SynthesisConstraint(
                    title="Require missing non-null proof",
                    description="Only report dereference-like sinks when the active path lacks a non-null proof; patched null checks and early returns must stay silent.",
                )
            )
        elif mechanism_contract.mechanism_family == "arithmetic_bound_violation":
            constraints.append(
                SynthesisConstraint(
                    title="Tie arithmetic to the sensitive sink",
                    description="Do not flag standalone arithmetic; require a range-unsafe expression to feed allocation, indexing, copy length, or an equivalent sensitive sink.",
                )
            )
        elif mechanism_contract.mechanism_family == "arithmetic_guard_violation":
            constraints.append(
                SynthesisConstraint(
                    title="Require missing divisor guard",
                    description="Model the divisor, division/modulo sink, and non-zero guard together; do not flag arithmetic that is already protected by a dominating zero check.",
                )
            )
        elif mechanism_contract.mechanism_family == "memory_read_without_proven_bound":
            constraints.append(
                SynthesisConstraint(
                    title="Model read bounds, not generic indexing",
                    description="Require a read-like sink plus missing proof that index, offset, or end pointer stays inside the intended region.",
                )
            )
        elif mechanism_contract.mechanism_family == "resource_lifetime_leak":
            constraints.append(
                SynthesisConstraint(
                    title="Require an escaping unreleased path",
                    description="Model allocation/acquisition, ownership scope, and an exit path that misses cleanup or transfer; do not treat every allocation as a leak.",
                )
            )
        elif mechanism_contract.mechanism_family == "initialization_contract_violation":
            constraints.append(
                SynthesisConstraint(
                    title="Require missing dominating initialization",
                    description="Only report read-like uses when the active path lacks a dominating initializer or reset that covers the same variable or field.",
                )
            )
        elif mechanism_contract.mechanism_family == "untrusted_input_to_sensitive_sink":
            constraints.append(
                SynthesisConstraint(
                    title="Require source-sink semantics",
                    description="Model untrusted source, sensitive sink, and sanitizer or prepared-interface barriers together; do not reduce the detector to sink-name matching.",
                )
            )
        elif mechanism_contract.mechanism_family == "shared_state_atomicity_violation":
            constraints.append(
                SynthesisConstraint(
                    title="Model synchronization around shared-state windows",
                    description="Require a race-prone check/use/update window on shared state and absence of a synchronizing barrier; mutex or atomic APIs alone are not sufficient evidence.",
                )
            )

        if analyzer_id == "csa":
            constraints.append(
                SynthesisConstraint(
                    title="Use path-sensitive evidence",
                    description="Prefer guards, state transitions, and lifecycle facts over broad textual matching.",
                )
            )
            constraints.append(
                SynthesisConstraint(
                    title="No placeholder helper logic",
                    description="Helper predicates must inspect AST/program state and must not be unconditional return-true/return-false stubs.",
                )
            )
            if primary_pattern == "buffer_overflow":
                constraints.append(
                    SynthesisConstraint(
                        title="Do not return early on unknown string length",
                        description="For inherently unbounded sinks like strcpy/strcat/sprintf/gets, missing concrete source length is not by itself a no-report condition; require a real barrier proof to stay silent.",
                    )
                )
                constraints.append(
                    SynthesisConstraint(
                        title="Do not confuse nullness with bounds",
                        description="Null/non-null checks on source, destination, or size symbols are not buffer-bound proofs and must not be used as silence conditions for overflow detection.",
                    )
                )
        if analyzer_id == "codeql":
            constraints.append(
                SynthesisConstraint(
                    title="Prefer semantic predicates",
                    description="Prefer reusable predicates, flow steps, and API modeling over patch-location matching.",
                )
            )
            constraints.append(
                SynthesisConstraint(
                    title="No callee-only matching",
                    description="Do not report every call to risky APIs by name alone; require an unchecked write/copy condition and absence of a patch-style barrier.",
                )
            )
            if primary_pattern == "buffer_overflow":
                constraints.append(
                    SynthesisConstraint(
                        title="Bind barriers to the same call",
                        description="A barrier predicate must relate the same destination, size, source, or compared variables as the candidate write; the mere presence of any comparison or if-statement in the same function is not a proof.",
                    )
                )
                constraints.append(
                    SynthesisConstraint(
                        title="Ignore non-bounds preconditions",
                        description="Null checks or argument-validity checks like `!dst || !src` are not patch-style bounds barriers and must not silence the query.",
                    )
                )
        return constraints

    def _implementation_hints(
        self,
        analyzer_id: str,
        primary_pattern: str,
        records: List[EvidenceRecord],
        shared: Dict[str, Any],
        missing_evidence: List[str],
        patch_mechanism_signals: List[str],
        silencing_conditions: List[str],
        retry_guidance: List[str],
        repair_directives: List[Dict[str, Any]],
        mechanism_contract: MechanismContract,
        prefer_consumer_lifetime_mode: bool,
    ) -> List[str]:
        def top_items(value: Any, limit: int) -> List[Any]:
            if value is None:
                return []
            if isinstance(value, (list, tuple)):
                return list(value[:limit])
            if isinstance(value, set):
                return list(value)[:limit]
            if isinstance(value, str):
                token = value.strip()
                return [token] if token else []
            return [value]

        hints: List[str] = []
        hints.append(f"Mechanism family: {mechanism_contract.mechanism_family}")
        if mechanism_contract.semantic_dimensions:
            hints.append(f"Mechanism dimensions: {', '.join(map(str, mechanism_contract.semantic_dimensions[:4]))}")
        if mechanism_contract.trigger_invariants:
            hints.append(f"Trigger invariants: {', '.join(map(str, mechanism_contract.trigger_invariants[:3]))}")
        if mechanism_contract.silence_invariants:
            hints.append(f"Silence invariants: {', '.join(map(str, mechanism_contract.silence_invariants[:3]))}")
        if mechanism_contract.transfer_axes:
            hints.append(f"Transfer axes: {', '.join(map(str, mechanism_contract.transfer_axes[:3]))}")
        focus_files = self._focus_files(shared)
        if focus_files:
            hints.append(f"Focus files: {', '.join(map(str, focus_files[:4]))}")
        affected_functions = top_items(shared.get("affected_functions", []), 5)
        if affected_functions:
            hints.append(f"Priority functions: {', '.join(map(str, affected_functions))}")
        fix_patterns = self._fix_patterns(shared)
        if fix_patterns:
            hints.append(f"Patch-added barriers: {', '.join(map(str, fix_patterns[:5]))}")
        added_apis = self._added_apis(shared)
        if added_apis:
            hints.append(f"Relevant APIs: {', '.join(map(str, added_apis[:6]))}")
        if missing_evidence:
            hints.append(f"Missing planned evidence: {', '.join(map(str, missing_evidence[:4]))}")
        for item in silencing_conditions[:3]:
            hints.append(f"Silence condition: {item}")
        for item in patch_mechanism_signals[:4]:
            hints.append(f"Patch mechanism: {item}")
        for item in retry_guidance[:3]:
            hints.append(f"Counterexample repair: {item}")
        for item in repair_directives[:3]:
            failure_mode = str(item.get("failure_mode", "") or "").strip()
            action = str(item.get("action", "") or "").strip()
            target_clause = str(item.get("target_clause", "") or "").strip()
            if failure_mode and action:
                if target_clause:
                    hints.append(f"Repair {failure_mode} via {target_clause}: {action}")
                else:
                    hints.append(f"Repair {failure_mode}: {action}")

        if primary_pattern == "buffer_overflow" and analyzer_id == "codeql":
            hints.append("Prefer predicates over callee names: model unchecked writes into bounded destinations, not every memcpy/strcpy/snprintf call.")
            hints.append("Patched examples with explicit length guards or checked snprintf return values must stay silent.")
            hints.append("Barrier predicates must be tied to the same call arguments or related variable accesses; do not suppress a call just because the function contains some unrelated comparison.")
        if primary_pattern == "buffer_overflow" and analyzer_id == "csa":
            hints.append("Implement real AST/path-sensitive guard reasoning; helper checks must not be unconditional placeholders.")
            hints.append("Suppress reports on paths where length guards or snprintf return-value checks prove the write is bounded.")
            hints.append("Do not drop patch-removed strcpy/strcat/sprintf/gets style sinks merely because the source length is symbolic; missing barrier proof should still keep the path suspicious.")
            hints.append("Do not use `State->isNull` / `State->isNonNull` on source or size symbols as a substitute for bounds reasoning.")
            hints.append("Recover fixed destination extents from FieldRegion/ElementRegion super-regions instead of relying only on the decayed argument type.")
            hints.append("For memcpy-like sinks, model `strlen(x)+1`, `len+1`, and guard-bound size variables even when the final byte count is not a concrete constant.")
        if primary_pattern == "buffer_overflow" and analyzer_id == "codeql":
            hints.append("Null checks and generic argument validation are not bounds barriers; keep barrier predicates tied to compared size/capacity variables.")
            hints.append("Prefer fixed-buffer destinations plus tracked size expressions (`strlen(...) + 1`, `len + 1`, size arguments) over generic function-level `if` heuristics.")
        if mechanism_contract.mechanism_family == "resource_lifetime_violation":
            hints.append("Track the same symbolic resource across release, nulling/reinit, and later use/free; do not reduce lifecycle reasoning to raw API names.")
            hints.append("Do not classify the resource only by field or variable names; use release/use/nulling/relookup relations plus alias continuity.")
            if prefer_consumer_lifetime_mode:
                hints.append("The patch shape suggests stable-handle validation plus authoritative relookup. Prefer consumer-side stale cached-pointer misuse over a generic freed-symbol template if the latter needs unobservable producer/consumer continuity.")
                hints.append("If validation is translation-unit local or consumer-local, a direct cached-pointer dereference that bypasses handle/id relookup is a better primary trigger than a hidden release event.")
                hints.append("Treat explicit invalidation/reset and authoritative relookup as the real patched silence conditions; plain null/non-null checks are not freshness proofs.")
                hints.append("Write the positive trigger first, then add silence predicates only when they are tied to the same cached receiver, stable handle, relookup result, or alias resource.")
                hints.append("Do not suppress a candidate just because the same function contains some unrelated `if (!x)`, assignment, or helper call.")
                hints.append("For CSA, do not force ProgramStateTrait just because the bug family is use-after-free; if a local AST contract such as nested MemberExpr on a cached managed field is sufficient, prefer that simpler observable trigger.")
                hints.append("Treat generic `FreedSymbols` / `checkLocation` / `Loc.getAsSymbol()` scaffolding as a rejected alternative when the patch evidence says the primary observable mode is consumer-side stale-cache misuse.")
        if mechanism_contract.mechanism_family == "resource_lifetime_leak":
            hints.append("Track ownership across all exits and transfers; a single cleanup site does not prove the absence of a leak.")
        if mechanism_contract.mechanism_family == "nullability_contract_violation":
            hints.append("Report only when dereference-like sinks are reachable without a non-null proof on the active path.")
        if mechanism_contract.mechanism_family == "arithmetic_bound_violation":
            hints.append("Connect arithmetic range reasoning to the downstream sink instead of flagging arithmetic in isolation.")
        if mechanism_contract.mechanism_family == "arithmetic_guard_violation":
            hints.append("Model divisor non-zero proofs directly; unrelated range guards are not enough.")
        if mechanism_contract.mechanism_family == "memory_read_without_proven_bound":
            hints.append("Model index/offset/end-pointer relations for the same region; do not flag all reads or dereferences indiscriminately.")
        if mechanism_contract.mechanism_family == "initialization_contract_violation":
            hints.append("Track dominating writes or zero-inits on the same variable/field before reporting a later read.")
        if mechanism_contract.mechanism_family == "untrusted_input_to_sensitive_sink":
            hints.append("Model source, sink, and sanitizer/prepared-interface barrier together; keep the query/checker scoped to the same trust boundary.")
        if mechanism_contract.mechanism_family == "shared_state_atomicity_violation":
            hints.append("Model the shared-state window and synchronization barrier together; a lone lock call is not proof of safety.")

        for record in records:
            payload = record.semantic_payload or {}
            evidence_slice = record.evidence_slice
            if evidence_slice is not None:
                if evidence_slice.summary:
                    hints.append(f"Semantic slice ({evidence_slice.kind}): {evidence_slice.summary}")
                if evidence_slice.guards:
                    hints.append(f"Slice guards: {', '.join(map(str, evidence_slice.guards[:3]))}")
                if evidence_slice.state_transitions:
                    hints.append(f"Slice transitions: {', '.join(map(str, evidence_slice.state_transitions[:3]))}")
                if evidence_slice.call_edges:
                    hints.append(f"Slice call edges: {', '.join(map(str, evidence_slice.call_edges[:3]))}")
                if evidence_slice.api_terms:
                    hints.append(f"Slice API terms: {', '.join(map(str, evidence_slice.api_terms[:4]))}")
                if evidence_slice.related_symbols:
                    hints.append(f"Slice symbols: {', '.join(map(str, evidence_slice.related_symbols[:4]))}")
                if evidence_slice.coverage_status and evidence_slice.coverage_status != "full":
                    hints.append(f"Slice coverage: {evidence_slice.coverage_status}")
            if record.type == "path_guard" and payload.get("guard_expr"):
                hints.append(f"Model guard: {payload.get('guard_expr')}")
            elif payload.get("state_after"):
                hints.append(f"State after: {', '.join(map(str, top_items(payload.get('state_after'), 3)))}")
            elif payload.get("state_before"):
                hints.append(f"State before: {', '.join(map(str, top_items(payload.get('state_before'), 3)))}")
            elif record.type == "state_transition" and payload.get("summary"):
                hints.append(f"State transition: {payload.get('summary')}")
            elif payload.get("tracked_symbols"):
                hints.append(f"Tracked symbols: {', '.join(map(str, top_items(payload.get('tracked_symbols'), 4)))}")
            elif payload.get("buffer_fields"):
                hints.append(f"Buffer fields: {', '.join(map(str, top_items(payload.get('buffer_fields'), 3)))}")
            elif payload.get("cfg_branch_kinds"):
                hints.append(f"CFG branches: {', '.join(map(str, top_items(payload.get('cfg_branch_kinds'), 4)))}")
            elif payload.get("branch_conditions"):
                hints.append(f"Branch conditions: {', '.join(map(str, top_items(payload.get('branch_conditions'), 3)))}")
            elif payload.get("state_statements"):
                hints.append(f"State statements: {', '.join(map(str, top_items(payload.get('state_statements'), 3)))}")
            elif payload.get("call_edges"):
                hints.append(f"Analyzer edges: {', '.join(map(str, top_items(payload.get('call_edges'), 3)))}")
            elif record.type == "allocation_lifecycle" and payload.get("operations"):
                hints.append(f"Lifecycle ops: {', '.join(map(str, top_items(payload.get('operations'), 3)))}")
            elif record.type == "dataflow_candidate" and payload.get("entry_points"):
                hints.append(f"Flow entry points: {', '.join(map(str, top_items(payload.get('entry_points'), 4)))}")
            elif record.type == "call_chain" and payload.get("summary"):
                summary = payload.get("summary")
                if isinstance(summary, list):
                    hints.append(f"Call-chain context: {', '.join(map(str, summary[:3]))}")
                else:
                    hints.append(f"Call-chain context: {summary}")
            elif record.type == "api_contract" and payload.get("apis"):
                hints.append(f"API semantics: {', '.join(map(str, top_items(payload.get('apis'), 4)))}")
            elif record.type == "metadata_hint" and payload.get("summary"):
                hints.append(f"Patch intent: {payload.get('summary')}")
            elif record.type == "metadata_hint" and payload.get("external_references"):
                refs = payload.get("external_references", {}) or {}
                ref_tokens = top_items(refs.get("cves"), 2) + top_items(refs.get("cwes"), 2)
                if ref_tokens:
                    hints.append(f"External refs: {', '.join(map(str, ref_tokens[:4]))}")
            elif payload.get("call_targets"):
                hints.append(f"Observed calls: {', '.join(map(str, top_items(payload.get('call_targets'), 4)))}")
            elif payload.get("globals"):
                hints.append(f"Shared state: {', '.join(map(str, top_items(payload.get('globals'), 4)))}")
            elif payload.get("database_status"):
                hints.append(f"CodeQL database status: {payload.get('database_status')}")
            elif payload.get("database_create_message"):
                hints.append(f"CodeQL DB note: {payload.get('database_create_message')}")
            elif payload.get("live_query_status"):
                hints.append(f"CodeQL inventory: {payload.get('live_query_status')}")
            elif record.type == "validation_outcome" and payload.get("failure_mode"):
                hints.append(f"Validation failure: {payload.get('failure_mode')}")
            elif payload.get("compile_command_preview"):
                hints.append(f"Compile context: {payload.get('compile_command_preview')}")
            elif record.type == "validation_outcome" and payload.get("feedback_hint"):
                hints.append(f"Validation feedback: {payload.get('feedback_hint')}")
            elif record.type == "patch_fact" and payload.get("label"):
                hints.append(f"Patch fact: {payload.get('label')}")

        deduped: List[str] = []
        seen = set()
        for item in hints:
            if item not in seen:
                seen.add(item)
                deduped.append(item)
        return deduped[:8]

    def _focus_files(self, shared: Dict[str, Any]) -> List[str]:
        files: List[str] = []
        for item in (shared.get("file_details", []) or []):
            if not isinstance(item, dict):
                continue
            path = str(item.get("path", "")).strip()
            if path and path not in files:
                files.append(path)
        return files[:6]

    def _focus_functions(self, shared: Dict[str, Any]) -> List[str]:
        functions: List[str] = []
        for item in (shared.get("affected_functions", []) or []):
            token = str(item).strip()
            if token and token not in functions:
                functions.append(token)
        return functions[:8]

    def _fix_patterns(self, shared: Dict[str, Any]) -> List[str]:
        patterns: List[str] = []
        for fact in (((shared.get("patchweaver", {}) or {}).get("patch_facts", [])) or []):
            if str(fact.get("fact_type", "")) != "fix_patterns":
                continue
            for item in ((fact.get("attributes", {}) or {}).get("patterns", []) or []):
                token = str(item).strip()
                if token and token not in patterns:
                    patterns.append(token)
        return patterns[:8]

    def _added_guards(self, shared: Dict[str, Any]) -> List[str]:
        guards: List[str] = []
        for fact in (((shared.get("patchweaver", {}) or {}).get("patch_facts", [])) or []):
            if str(fact.get("fact_type", "")) != "added_guards":
                continue
            for item in ((fact.get("attributes", {}) or {}).get("guards", []) or []):
                token = str(item).strip()
                if token and token not in guards:
                    guards.append(token)
        return guards[:10]

    def _removed_risky_operations(self, shared: Dict[str, Any]) -> List[str]:
        operations: List[str] = []
        for fact in (((shared.get("patchweaver", {}) or {}).get("patch_facts", [])) or []):
            if str(fact.get("fact_type", "")) != "removed_risky_operations":
                continue
            for item in ((fact.get("attributes", {}) or {}).get("operations", []) or []):
                token = str(item).strip()
                if token and token not in operations:
                    operations.append(token)
        return operations[:10]

    def _added_apis(self, shared: Dict[str, Any]) -> List[str]:
        apis: List[str] = []
        for fact in (((shared.get("patchweaver", {}) or {}).get("patch_facts", [])) or []):
            if str(fact.get("fact_type", "")) != "added_api_calls":
                continue
            for item in ((fact.get("attributes", {}) or {}).get("apis", []) or []):
                token = str(item).strip()
                if token and token not in apis:
                    apis.append(token)
        return apis[:10]

    def _patch_mechanism_signals(self, shared: Dict[str, Any], primary_pattern: str) -> List[str]:
        signals: List[str] = []
        removed_operations = self._removed_risky_operations(shared)
        added_guards = self._added_guards(shared)
        added_apis = self._added_apis(shared)
        strategy = shared.get("detection_strategy", {}) or {}

        for item in removed_operations[:4]:
            signals.append(f"removed risky operation: {item}")
        for item in added_guards[:3]:
            signals.append(f"added guard: {item}")
        if added_apis:
            signals.append(f"added or highlighted APIs: {', '.join(added_apis[:4])}")
        suggestions = [str(item).strip() for item in (strategy.get("suggestions", []) or []) if str(item).strip()]
        if suggestions:
            signals.append(f"detection hints: {', '.join(suggestions[:3])}")
        if primary_pattern == "buffer_overflow" and not signals:
            signals.append("look for writes into bounded buffers where no guard proves the source length fits the destination.")
        if primary_pattern == "out_of_bounds_read" and not signals:
            signals.append("look for reads where index, offset, or pointer arithmetic can escape the intended region without a dominating bound check.")
        return signals[:8]

    def _prefer_consumer_lifetime_mode(self, shared: Dict[str, Any], primary_pattern: str) -> bool:
        if primary_pattern != "use_after_free":
            return False

        patch_semantics = shared.get("patch_semantics", {}) or {}
        lifecycle_changes = [str(item).strip().lower() for item in (patch_semantics.get("lifecycle_changes", []) or [])]
        state_resets = [str(item).strip().lower() for item in (patch_semantics.get("state_resets", []) or [])]
        added_guards = [str(item).strip().lower() for item in (patch_semantics.get("added_guards", []) or [])]
        added_apis = [str(item).strip().lower() for item in (patch_semantics.get("added_api_calls", []) or [])]

        has_stable_handle = any("_id" in item for item in lifecycle_changes + added_guards + state_resets)
        has_authoritative_lookup = any(
            token.startswith(("find_", "lookup_", "fetch_", "acquire_")) or "lookup" in token
            for token in added_apis
        )
        has_explicit_invalidation = bool(state_resets)

        return has_stable_handle and has_authoritative_lookup and has_explicit_invalidation

    def _silencing_conditions(
        self,
        analyzer_id: str,
        shared: Dict[str, Any],
        primary_pattern: str,
    ) -> List[str]:
        conditions: List[str] = []
        fix_patterns = self._fix_patterns(shared)
        added_guards = self._added_guards(shared)
        added_apis = self._added_apis(shared)

        for item in added_guards[:3]:
            conditions.append(f"length/capacity guard present: {item}")
        for item in fix_patterns[:3]:
            conditions.append(f"patch-introduced barrier pattern: {item}")

        if primary_pattern == "buffer_overflow":
            if "snprintf" in added_apis:
                conditions.append("snprintf is used with a checked return value that enforces output buffer bounds")
            if "memcpy" in added_apis:
                conditions.append("memcpy size is guarded by a patch-style bound check before the write")
            if analyzer_id == "codeql":
                conditions.append("a dominating guard proves source length is below destination capacity before the write")
            if analyzer_id == "csa":
                conditions.append("current path condition proves the copied byte count fits the destination buffer")
        if primary_pattern == "out_of_bounds_read":
            conditions.append("a dominating length/index/end-pointer guard proves the read stays inside the intended region")
        if primary_pattern == "divide_by_zero":
            conditions.append("a dominating non-zero guard or early return blocks zero divisors before the arithmetic sink")
        if primary_pattern == "memory_leak":
            conditions.append("patch-introduced cleanup or ownership-transfer logic covers all relevant exit paths")
        if primary_pattern == "uninitialized_variable":
            conditions.append("patch-introduced initialization dominates the later read or branch sink")

        deduped: List[str] = []
        seen = set()
        for item in conditions:
            if item not in seen:
                seen.add(item)
                deduped.append(item)
        return deduped[:6]

    def _retry_guidance(self, shared: Dict[str, Any], evidence_bundle: EvidenceBundle) -> List[str]:
        patchweaver = shared.get("patchweaver", {}) or {}
        feedback_bundle = patchweaver.get("validation_feedback", {}) or {}
        guidance: List[str] = []
        seen = set()
        for record in (getattr(evidence_bundle, "records", []) or []):
            if getattr(record, "type", "") != "validation_outcome":
                continue
            payload = getattr(record, "semantic_payload", {}) or {}
            failure_mode = str(payload.get("failure_mode", "") or "").strip()
            if failure_mode:
                target_clause = self._repair_target_clause(failure_mode)
                message = f"{target_clause}: {self._repair_action(failure_mode)}"
                if message not in seen:
                    seen.add(message)
                    guidance.append(message)
            hint = str(payload.get("feedback_hint", "") or "").strip()
            if hint and hint not in seen:
                seen.add(hint)
                guidance.append(hint)
        for item in (feedback_bundle.get("records", []) or []):
            if not isinstance(item, dict):
                continue
            payload = item.get("semantic_payload", {}) or {}
            failure_mode = str(payload.get("failure_mode", "") or "").strip()
            if failure_mode:
                target_clause = self._repair_target_clause(failure_mode)
                message = f"{target_clause}: {self._repair_action(failure_mode)}"
                if message not in seen:
                    seen.add(message)
                    guidance.append(message)
            hint = str(payload.get("feedback_hint", "") or "").strip()
            if hint and hint not in seen:
                seen.add(hint)
                guidance.append(hint)
        return guidance[:6]

    def _semantic_clause_plan(
        self,
        analyzer_id: str,
        selected_records: List[EvidenceRecord],
        primary_pattern: str,
        silencing_conditions: List[str],
        focus_functions: List[str],
    ) -> List[Dict[str, Any]]:
        trigger_support = [
            record.evidence_id
            for record in selected_records
            if record.type in {"semantic_slice", "path_guard", "state_transition", "allocation_lifecycle", "dataflow_candidate"}
            or (record.evidence_slice and record.evidence_slice.kind in {"semantic_slice", "path_witness", "state_witness", "flow_witness", "interprocedural_slice"})
        ]
        silence_support = [
            record.evidence_id
            for record in selected_records
            if record.type in {"patch_fact", "metadata_hint", "api_contract", "context_summary"}
            or (record.evidence_slice and record.evidence_slice.kind in {"intent_slice", "context_summary", "api_contract_slice"})
        ]
        transfer_support = [
            record.evidence_id
            for record in selected_records
            if record.type in {"call_chain", "semantic_slice", "metadata_hint"}
            or (record.evidence_slice and record.evidence_slice.kind in {"interprocedural_slice", "semantic_slice", "intent_slice"})
        ]
        interface_support = [
            record.evidence_id
            for record in selected_records
            if record.type in {"diagnostic", "context_summary", "metadata_hint"}
        ]

        clauses = [
            {
                "clause_id": "vulnerable_trigger_clause",
                "intent": f"Trigger on the vulnerable {primary_pattern} mechanism using evidence-backed path/flow semantics.",
                "supporting_evidence_ids": trigger_support[:8],
                "repair_when": ["semantic_no_hits"],
                "focus_functions": focus_functions[:6],
            },
            {
                "clause_id": "patched_silence_clause",
                "intent": "Stay silent on patched code when patch-added guards, barriers, or safe APIs prove the mechanism is blocked.",
                "supporting_evidence_ids": silence_support[:8],
                "repair_when": [],
                "silencing_conditions": silencing_conditions[:4],
            },
            {
                "clause_id": "semantic_transfer_clause",
                "intent": "Generalize along semantic slices and call-chain evidence rather than patch-local syntax.",
                "supporting_evidence_ids": transfer_support[:8],
                "repair_when": [],
                "analyzer_id": analyzer_id,
            },
            {
                "clause_id": "analyzer_interface_clause",
                "intent": "Preserve valid analyzer-facing syntax and interfaces while keeping semantics unchanged.",
                "supporting_evidence_ids": interface_support[:6],
                "repair_when": ["semantic_execution_error"],
                "analyzer_id": analyzer_id,
            },
        ]
        return clauses

    def _repair_directives(
        self,
        evidence_bundle: EvidenceBundle,
        shared: Dict[str, Any],
        clause_plan: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        directives: List[Dict[str, Any]] = []
        seen = set()
        clause_map = {
            str(item.get("clause_id", "")): item
            for item in clause_plan
            if str(item.get("clause_id", "")).strip()
        }
        for payload in self._validation_feedback_payloads(shared, evidence_bundle):
            failure_mode = str(payload.get("failure_mode", "") or "").strip()
            if not failure_mode:
                continue
            target_clause = self._repair_target_clause(failure_mode)
            key = (failure_mode, target_clause)
            if key in seen:
                continue
            seen.add(key)
            clause = clause_map.get(target_clause, {})
            directives.append(
                {
                    "failure_mode": failure_mode,
                    "target_clause": target_clause,
                    "priority": self._repair_priority(failure_mode),
                    "action": self._repair_action(failure_mode),
                    "supporting_evidence_ids": list(clause.get("supporting_evidence_ids", []) or [])[:8],
                    "counterexample_scope": str(payload.get("case_id", "") or payload.get("kind", "") or ""),
                    "counterexample_location": payload.get("counterexample_location", {}) or {},
                    "feedback_hint": str(payload.get("feedback_hint", "") or ""),
                }
            )
        return directives[:6]

    def _validation_feedback_payloads(
        self,
        shared: Dict[str, Any],
        evidence_bundle: EvidenceBundle,
    ) -> List[Dict[str, Any]]:
        payloads: List[Dict[str, Any]] = []
        for record in (getattr(evidence_bundle, "records", []) or []):
            if getattr(record, "type", "") == "validation_outcome":
                payloads.append(getattr(record, "semantic_payload", {}) or {})
        feedback_bundle = ((shared.get("patchweaver", {}) or {}).get("validation_feedback", {}) or {})
        for item in (feedback_bundle.get("records", []) or []):
            if not isinstance(item, dict):
                continue
            payloads.append(item.get("semantic_payload", {}) or {})
        return payloads

    def _repair_target_clause(self, failure_mode: str) -> str:
        if failure_mode == "semantic_no_hits":
            return "vulnerable_trigger_clause"
        if failure_mode == "semantic_execution_error":
            return "analyzer_interface_clause"
        return "vulnerable_trigger_clause"

    def _repair_priority(self, failure_mode: str) -> str:
        if failure_mode in {"semantic_no_hits", "semantic_execution_error"}:
            return "high"
        return "medium"

    def _repair_action(self, failure_mode: str) -> str:
        actions = {
            "semantic_no_hits": "Restore the vulnerable trigger clause using verifier-backed slices instead of broad textual heuristics.",
            "semantic_execution_error": "Fix analyzer-facing interfaces, imports, helper signatures, or query/checker structure before changing semantics.",
        }
        if failure_mode in actions:
            return actions[failure_mode]
        return "Repair the failing clause using the most directly supporting evidence."

    def _focus_score(
        self,
        record: EvidenceRecord,
        focus_files: List[str],
        focus_functions: List[str],
    ) -> float:
        score = 0.0
        payload = record.semantic_payload or {}
        scope = record.scope.to_dict()
        record_file = str(scope.get("file", "") or payload.get("source_file", "")).strip()
        record_function = str(scope.get("function", "")).strip()
        payload_functions = [str(item).strip() for item in (payload.get("functions", []) or []) if str(item).strip()]

        for focus_file in focus_files:
            if record_file == focus_file or record_file.endswith(focus_file):
                score += 3.0
                break

        for focus_function in focus_functions:
            if record_function == focus_function:
                score += 3.0
                break
            if focus_function in payload_functions:
                score += 2.0
                break
        return score

    def _validation_expectations(
        self,
        primary_pattern: str,
        silencing_conditions: List[str],
        retry_guidance: List[str],
        mechanism_contract: MechanismContract,
        prefer_consumer_lifetime_mode: bool,
    ) -> List[str]:
        expectations = [
            f"Vulnerable version should trigger a {primary_pattern} finding.",
            "Patched version should stay silent for the same mechanism.",
            "Semantic validation that executes but returns zero hits is not acceptable; recover coverage with evidence-backed semantics.",
            "Repair phase may fix syntax/interfaces only; it must not simplify away the core detection logic.",
            "Generalization must stay inside the mechanism contract transfer axes instead of widening to adjacent bug families.",
        ]
        if mechanism_contract.mechanism_family == "resource_lifetime_violation":
            expectations.append("Sibling variants that preserve the same release-then-use lifecycle should also trigger; patch-local identifier matching is not sufficient.")
            if prefer_consumer_lifetime_mode:
                expectations.append("Consumer-local stale-cache variants that bypass stable-handle validation or authoritative relookup should also trigger, even when the release site is not visible on the same observed path.")
        for item in mechanism_contract.trigger_invariants[:2]:
            expectations.append(f"Trigger invariant: {item}.")
        for item in silencing_conditions[:2]:
            expectations.append(f"Patched silence depends on: {item}.")
        for item in retry_guidance[:2]:
            expectations.append(f"Fix counterexample: {item}.")
        return expectations

    def _compact_record(self, record: EvidenceRecord) -> Dict[str, Any]:
        payload = record.semantic_payload or {}
        compact_payload = {}
        for key in (
            "label",
            "reason",
            "entry_points",
            "guard_expr",
            "summary",
            "summary_line",
            "state_before",
            "state_after",
            "tracked_symbols",
            "buffer_fields",
            "feedback_hint",
            "coverage_status",
            "guards",
            "operations",
            "operations",
            "apis",
            "patterns",
            "descriptions",
            "suggestions",
            "guidance",
            "functions",
            "call_targets",
            "globals",
            "external_references",
            "planner_uncertainty_budget",
            "planner_escalation_triggers",
            "counterexample_location",
            "repair_target_clause",
            "repair_action",
            "repair_priority",
            "compile_command_preview",
            "cfg_branch_kinds",
            "branch_conditions",
            "call_edges",
            "state_statements",
            "return_statements",
            "database_status",
            "database_create_message",
            "database_languages",
            "live_query_status",
            "existing_findings_count",
            "build_system",
            "source_file",
            "case_id",
            "role",
            "failure_mode",
            "error_message",
        ):
            value = payload.get(key)
            if value:
                compact_payload[key] = value
        return {
            "evidence_id": record.evidence_id,
            "type": record.type,
            "analyzer": record.analyzer,
            "scope": record.scope.to_dict(),
            "semantic_payload": compact_payload or payload,
            "evidence_slice": record.evidence_slice.to_dict() if record.evidence_slice else {},
            "confidence": record.provenance.confidence if record.provenance else 0.0,
        }

    def _dedupe_strings(self, items: List[str]) -> List[str]:
        seen = set()
        deduped: List[str] = []
        for item in items:
            token = str(item).strip()
            if not token or token in seen:
                continue
            seen.add(token)
            deduped.append(token)
        return deduped
