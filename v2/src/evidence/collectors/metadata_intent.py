"""
Patch intent / metadata evidence collection.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List

from ...core.analyzer_base import AnalyzerContext
from ...core.evidence_schema import EvidenceAnchor, EvidenceBundle, EvidenceSlice
from .artifact_extractor import ProjectArtifactExtractor
from .base import EvidenceCollector


class MetadataIntentEvidenceCollector(EvidenceCollector):
    """Collect patch-intent and external-reference hints for uncertain cases."""

    def __init__(self, analyzer_id: str):
        self.analyzer_id = analyzer_id

    def collect(self, context: AnalyzerContext) -> EvidenceBundle:
        patchweaver = self._shared_patchweaver(context)
        patch_facts = patchweaver.get("patch_facts", []) or []
        evidence_plan = patchweaver.get("evidence_plan", {}) or {}
        escalation = patchweaver.get("evidence_escalation", {}) or {}
        project_info = self._project_info(context)

        metadata_payload = self._metadata_payload(
            context=context,
            patch_facts=patch_facts,
            evidence_plan=evidence_plan,
            escalation=escalation,
            project_info=project_info,
        )
        if not metadata_payload:
            return EvidenceBundle()

        record = self._record(
            "metadata_intent_0",
            "metadata_hint",
            context,
            metadata_payload,
            artifact="patch-metadata:intent",
            confidence=0.74 if metadata_payload.get("external_references") else 0.66,
            evidence_slice=EvidenceSlice(
                kind="intent_slice",
                anchor=EvidenceAnchor(
                    patch_file=str(metadata_payload.get("patch_path", "") or ""),
                    hunk_index=0,
                    source_line=0,
                ),
                summary=str(metadata_payload.get("summary", "") or ""),
                statements=list(metadata_payload.get("intent_lines", []) or [])[:4],
                guards=[],
                call_boundary=list(metadata_payload.get("module_boundaries", []) or [])[:4],
                call_edges=[],
                state_transitions=[],
                api_terms=list(metadata_payload.get("api_terms", []) or [])[:6],
                related_symbols=list(metadata_payload.get("focus_functions", []) or [])[:6],
                verifier="patch-metadata",
                extraction_method="patch_header+shared_analysis+project_info",
                coverage_status="full" if metadata_payload.get("summary") else "partial",
            ),
        )
        return EvidenceBundle(
            records=[record],
            missing_evidence=[],
            collected_analyzers=[self.analyzer_id],
        )

    def _project_info(self, context: AnalyzerContext) -> Dict[str, Any]:
        try:
            extractor = ProjectArtifactExtractor()
            return extractor.project_info(extractor.project_root(context))
        except Exception:
            return {}

    def _metadata_payload(
        self,
        context: AnalyzerContext,
        patch_facts: List[Dict[str, Any]],
        evidence_plan: Dict[str, Any],
        escalation: Dict[str, Any],
        project_info: Dict[str, Any],
    ) -> Dict[str, Any]:
        patch_text = self._read_patch_text(context.patch_path)
        intent = self._fact_attributes(patch_facts, "patch_intent")
        refs = self._fact_attributes(patch_facts, "external_references")
        strategy = context.shared_analysis.get("detection_strategy", {}) or {}
        summary_parts: List[str] = []
        subject = str(intent.get("subject", "") or "").strip()
        summary = str(intent.get("summary", "") or "").strip()
        if subject:
            summary_parts.append(subject)
        elif summary:
            summary_parts.append(summary)
        primary_pattern = str(strategy.get("primary_pattern", "") or "").strip()
        if not primary_pattern:
            primary_pattern = str(evidence_plan.get("primary_pattern", "") or "").strip()
        if primary_pattern:
            summary_parts.append(f"pattern={primary_pattern}")
        triggers = [str(item).strip() for item in (escalation.get("triggers", []) or []) if str(item).strip()]
        if triggers:
            summary_parts.append(f"escalation={', '.join(triggers[:3])}")
        intent_lines = self._intent_lines(patch_text)
        focus_functions = [
            str(item).strip()
            for item in (context.shared_analysis.get("affected_functions", []) or [])
            if str(item).strip()
        ][:8]
        api_terms = self._patch_api_terms(context)
        module_boundaries = [
            str(item.get("name", "")).strip()
            for item in (project_info.get("modules", []) or [])
            if isinstance(item, dict) and str(item.get("name", "")).strip()
        ][:6]
        external_references = {
            "cves": [str(item).strip() for item in (refs.get("cves", []) or []) if str(item).strip()],
            "cwes": [str(item).strip() for item in (refs.get("cwes", []) or []) if str(item).strip()],
            "issues": [str(item).strip() for item in (refs.get("issues", []) or []) if str(item).strip()],
        }

        if not summary_parts and not any(external_references.values()) and not intent_lines:
            return {}

        return {
            "summary": " | ".join(summary_parts[:3]),
            "subject": subject,
            "intent_lines": intent_lines[:4],
            "focus_functions": focus_functions,
            "api_terms": api_terms,
            "module_boundaries": module_boundaries,
            "external_references": external_references,
            "planner_uncertainty_budget": str(evidence_plan.get("uncertainty_budget", "") or ""),
            "planner_escalation_triggers": list(evidence_plan.get("escalation_triggers", []) or []),
            "escalation_reasons": triggers,
            "primary_pattern": primary_pattern,
            "patch_path": str(Path(context.patch_path).name),
            "metadata_keywords": list(intent.get("keywords", []) or [])[:8],
            "guidance": self._guidance(primary_pattern, external_references, triggers),
        }

    def _patch_api_terms(self, context: AnalyzerContext) -> List[str]:
        patchweaver = self._shared_patchweaver(context)
        apis: List[str] = []
        for fact in (patchweaver.get("patch_facts", []) or []):
            if str(fact.get("fact_type", "")) != "added_api_calls":
                continue
            for item in ((fact.get("attributes", {}) or {}).get("apis", []) or []):
                token = str(item).strip()
                if token and token not in apis:
                    apis.append(token)
        return apis[:8]

    def _guidance(
        self,
        primary_pattern: str,
        external_references: Dict[str, List[str]],
        triggers: List[str],
    ) -> List[str]:
        guidance: List[str] = []
        if primary_pattern:
            guidance.append(f"Keep generated semantics aligned with {primary_pattern}.")
        if external_references.get("cwes"):
            guidance.append(f"Preserve CWE intent: {', '.join(external_references.get('cwes', [])[:3])}.")
        if external_references.get("cves"):
            guidance.append(f"Patch references external CVEs: {', '.join(external_references.get('cves', [])[:3])}.")
        if triggers:
            guidance.append(f"Evidence escalation was triggered by: {', '.join(triggers[:3])}.")
        return guidance[:4]

    def _fact_attributes(self, patch_facts: List[Dict[str, Any]], fact_type: str) -> Dict[str, Any]:
        for fact in patch_facts:
            if str(fact.get("fact_type", "")) == fact_type:
                return fact.get("attributes", {}) or {}
        return {}

    def _read_patch_text(self, patch_path: str) -> str:
        try:
            return Path(patch_path).read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return ""

    def _intent_lines(self, patch_text: str) -> List[str]:
        lines: List[str] = []
        for raw_line in (patch_text or "").splitlines():
            stripped = raw_line.strip()
            if not stripped:
                if lines:
                    break
                continue
            if stripped.startswith("diff --git "):
                break
            if stripped.startswith(("From ", "Date:")):
                continue
            if re.match(r"^(index|@@|---|\+\+\+)\b", stripped):
                continue
            if stripped.startswith(("+", "-")):
                continue
            if stripped not in lines:
                lines.append(stripped)
            if len(lines) >= 4:
                break
        return lines
