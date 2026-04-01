"""
Adapter for PATCHWEAVER bootstrap evidence.
"""

from __future__ import annotations

from ...core.analyzer_base import AnalyzerContext
from ...core.evidence_schema import EvidenceBundle
from ..normalizer import EvidenceNormalizer
from .base import EvidenceCollector


class PatchSemanticsCollector(EvidenceCollector):
    """Expose preflight patch evidence as a bundle."""

    analyzer_id = "patch"

    def collect(self, context: AnalyzerContext) -> EvidenceBundle:
        patchweaver = self._shared_patchweaver(context)
        raw_bundle = patchweaver.get("evidence_bundle", {}) or {}
        return EvidenceNormalizer.from_raw_bundle(raw_bundle)
