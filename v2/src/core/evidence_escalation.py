"""
PATCHWEAVER evidence escalation heuristics.
"""

from __future__ import annotations

from typing import Any, Dict, List

from ..evidence.normalizer import EvidenceNormalizer


class EvidenceEscalationAdvisor:
    """Decide whether to request richer evidence under uncertainty."""

    def evaluate(
        self,
        analyzer_id: str,
        shared_analysis: Dict[str, Any],
        evidence_bundle,
    ) -> Dict[str, Any]:
        patchweaver = (shared_analysis or {}).get("patchweaver", {}) or {}
        evidence_plan = patchweaver.get("evidence_plan", {}) or {}
        missing = [str(item).strip() for item in (getattr(evidence_bundle, "missing_evidence", []) or []) if str(item).strip()]
        slice_metrics = EvidenceNormalizer.slice_metrics(evidence_bundle, analyzer=analyzer_id)
        failure_modes = self._failure_modes(patchweaver)
        triggers: List[str] = []

        if "semantic_slice" in missing:
            triggers.append("missing_semantic_slice")
        if "allocation_lifecycle" in missing:
            triggers.append("missing_allocation_lifecycle")
        if "context_summary" in missing:
            triggers.append("missing_context_summary")
        if "call_chain" in missing:
            triggers.append("missing_call_chain")
        if "state_transition" in missing:
            triggers.append("missing_state_transition")
        if "metadata_hint" in missing:
            triggers.append("missing_metadata_hint")
        if slice_metrics.get("context_summary_count", 0) <= 0:
            triggers.append("missing_context_summary_record")
        if slice_metrics.get("coverage") in {"missing", "partial"}:
            triggers.append("partial_slice_coverage")
        if str(evidence_plan.get("uncertainty_budget", "") or "") == "high":
            triggers.append("high_uncertainty_budget")
        if evidence_plan.get("coverage_gaps"):
            triggers.append("planner_coverage_gap")
        for mode in failure_modes:
            if mode in {"semantic_no_hits", "semantic_execution_error"}:
                trigger = f"retry_{mode}"
                if trigger not in triggers:
                    triggers.append(trigger)

        collectors: List[str] = []
        fallback_collectors = [str(item).strip() for item in (evidence_plan.get("fallback_collectors", []) or []) if str(item).strip()]
        if triggers:
            available_collectors = fallback_collectors or ["metadata_intent"]
            if "metadata_intent" in available_collectors:
                collectors.append("metadata_intent")

        return {
            "requested": bool(collectors),
            "analyzer_id": analyzer_id,
            "uncertainty_budget": str(evidence_plan.get("uncertainty_budget", "") or "normal"),
            "triggers": triggers,
            "collectors": collectors,
            "failure_modes": failure_modes,
            "missing_evidence": missing,
            "slice_metrics": slice_metrics,
            "reason": self._reason(triggers, collectors),
        }

    def _failure_modes(self, patchweaver: Dict[str, Any]) -> List[str]:
        bundle = patchweaver.get("validation_feedback", {}) or {}
        modes: List[str] = []
        for item in (bundle.get("records", []) or []):
            if not isinstance(item, dict):
                continue
            payload = item.get("semantic_payload", {}) or {}
            mode = str(payload.get("failure_mode", "") or "").strip()
            if mode and mode not in modes:
                modes.append(mode)
        return modes

    def _reason(self, triggers: List[str], collectors: List[str]) -> str:
        if not collectors:
            return "Current evidence is sufficient; no escalation requested."
        if not triggers:
            return f"Escalate with {', '.join(collectors)}."
        return (
            "Escalate evidence because "
            + ", ".join(triggers[:4])
            + f"; apply {', '.join(collectors)}."
        )
