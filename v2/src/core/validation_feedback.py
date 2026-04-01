"""
PATCHWEAVER validation feedback normalization.

将语义验证结果转换为 `validation_outcome` 证据，
以便后续 synthesis / refine / reporting 共享使用。
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

from .evidence_schema import (
    EvidenceBundle,
    EvidenceLocation,
    EvidenceProvenance,
    EvidenceRecord,
    EvidenceScope,
)
from .evidence_types import EvidenceType


class ValidationFeedbackBuilder:
    """Build normalized validation feedback evidence."""

    def build(
        self,
        analyzer_id: str,
        patch_path: str,
        validate_path: Optional[str],
        validation_result: Any = None,
    ) -> EvidenceBundle:
        records: List[EvidenceRecord] = []
        repo_name = Path(patch_path).name if patch_path else ""
        target_name = Path(validate_path).name if validate_path else ""

        if validation_result is not None:
            records.append(
                EvidenceRecord(
                    evidence_id=f"{analyzer_id}_semantic_overall",
                    type=EvidenceType.VALIDATION_OUTCOME.value,
                    analyzer=analyzer_id,
                    scope=EvidenceScope(repo=repo_name, file=target_name, function="semantic_validation"),
                    location=EvidenceLocation(),
                    semantic_payload=self._semantic_payload(validation_result),
                    provenance=EvidenceProvenance(
                        tool="patchweaver-validation",
                        artifact="semantic-validation",
                        confidence=0.92 if getattr(validation_result, "success", False) else 0.72,
                    ),
                )
            )

        return EvidenceBundle(
            records=records,
            missing_evidence=[],
            collected_analyzers=[analyzer_id] if records else [],
        )

    def _semantic_payload(self, validation_result: Any) -> Dict[str, Any]:
        diagnostics = list(getattr(validation_result, "diagnostics", []) or [])
        success = bool(getattr(validation_result, "success", False))
        bugs_found = len(diagnostics)
        failure_mode = self._semantic_failure_mode(success, diagnostics)
        payload = {
            "kind": "semantic_overall",
            "stage": getattr(getattr(validation_result, "stage", None), "value", "semantic"),
            "success": success,
            "diagnostics_count": bugs_found,
            "warnings_count": sum(1 for item in diagnostics if getattr(item, "severity", "") == "warning"),
            "errors_count": sum(1 for item in diagnostics if getattr(item, "severity", "") == "error"),
            "error_message": getattr(validation_result, "error_message", ""),
            "summary": (
                f"semantic validation {'passed' if success else 'failed'}"
                f" with {bugs_found} diagnostics"
            ),
            "failure_mode": failure_mode,
            "repair_target_clause": self._repair_target_clause(failure_mode),
            "repair_action": self._repair_action(failure_mode),
            "repair_priority": self._repair_priority(failure_mode),
            "coverage_status": self._semantic_coverage_status(success, diagnostics),
            "feedback_hint": self._semantic_feedback_hint(success, diagnostics),
        }
        first = diagnostics[0] if diagnostics else None
        if first is not None:
            payload["first_diagnostic"] = {
                "file_path": getattr(first, "file_path", ""),
                "line": getattr(first, "line", 0),
                "message": getattr(first, "message", ""),
                "severity": getattr(first, "severity", ""),
            }
        return payload

    def _semantic_failure_mode(self, success: bool, diagnostics: List[Any]) -> str:
        if success and not diagnostics:
            return "semantic_no_hits"
        if not success:
            return "semantic_execution_error"
        return ""

    def _semantic_coverage_status(self, success: bool, diagnostics: List[Any]) -> str:
        if not success:
            return "failed"
        if diagnostics:
            return "full"
        return "empty"

    def _semantic_feedback_hint(self, success: bool, diagnostics: List[Any]) -> str:
        if success and not diagnostics:
            return "Semantic validation executed successfully but produced no concrete hits on the validation target."
        if success:
            return "Semantic validation confirms the detector can execute on the target."
        return "Fix analyzer-facing syntax, interface, or environment issues before changing detection semantics."

    def _repair_target_clause(self, failure_mode: str) -> str:
        if failure_mode == "semantic_no_hits":
            return "vulnerable_trigger_clause"
        if failure_mode == "semantic_execution_error":
            return "analyzer_interface_clause"
        return ""

    def _repair_priority(self, failure_mode: str) -> str:
        if failure_mode in {"semantic_no_hits", "semantic_execution_error"}:
            return "high"
        return "medium"

    def _repair_action(self, failure_mode: str) -> str:
        if failure_mode == "semantic_no_hits":
            return "Restore the vulnerable trigger clause using evidence-backed path, flow, or state witnesses."
        if failure_mode == "semantic_execution_error":
            return "Fix analyzer-facing structure first; do not change detection semantics until execution succeeds."
        return ""
