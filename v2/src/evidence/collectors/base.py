"""
Base collector interfaces.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, List, Optional

from ...core.analyzer_base import AnalyzerContext
from ...core.evidence_schema import (
    EvidenceBundle,
    EvidenceLocation,
    EvidenceProvenance,
    EvidenceRecord,
    EvidenceScope,
    EvidenceSlice,
)


class EvidenceCollector(ABC):
    """Base class for analyzer-native evidence collectors."""

    analyzer_id: str = "generic"
    supported_types: List[str] = []

    @abstractmethod
    def collect(self, context: AnalyzerContext) -> EvidenceBundle:
        """Collect analyzer-native evidence."""

    def _shared_patchweaver(self, context: AnalyzerContext) -> Dict[str, Any]:
        return (context.shared_analysis or {}).get("patchweaver", {}) or {}

    def _evidence_requirements(self, context: AnalyzerContext) -> List[Dict[str, Any]]:
        return [
            {
                "evidence_type": evidence_type,
                "reason": "Standalone evidence collection precomputes all refine-supported evidence for this analyzer.",
            }
            for evidence_type in list(self.supported_types or [])
        ]

    def _file_details(self, context: AnalyzerContext) -> List[Dict[str, Any]]:
        return (context.shared_analysis or {}).get("file_details", []) or []

    def _primary_file(self, context: AnalyzerContext) -> str:
        details = self._file_details(context)
        if not details:
            return ""
        return str(details[0].get("path", ""))

    def _primary_function(self, context: AnalyzerContext) -> str:
        return str(((context.shared_analysis or {}).get("affected_functions", []) or [""])[0])

    def _record(
        self,
        evidence_id: str,
        evidence_type: str,
        context: AnalyzerContext,
        semantic_payload: Dict[str, Any],
        *,
        line: int = 0,
        column: int = 0,
        artifact: str = "",
        confidence: float = 0.6,
        file: str = "",
        function: str = "",
        evidence_slice: Optional[EvidenceSlice] = None,
    ) -> EvidenceRecord:
        return EvidenceRecord(
            evidence_id=evidence_id,
            type=evidence_type,
            analyzer=self.analyzer_id,
            scope=EvidenceScope(
                repo=Path(context.patch_path).name,
                file=file or self._primary_file(context),
                function=function or self._primary_function(context),
            ),
            location=EvidenceLocation(line=line, column=column),
            semantic_payload=semantic_payload,
            provenance=EvidenceProvenance(
                tool=self.analyzer_id,
                artifact=artifact or evidence_type,
                confidence=confidence,
            ),
            evidence_slice=evidence_slice,
        )
