"""
Evidence bundle normalization helpers.
"""

from __future__ import annotations

import json
from typing import Any, Dict, Iterable, List, Optional, Set

from ..core.evidence_schema import (
    EvidenceAnchor,
    EvidenceBundle,
    EvidenceLocation,
    EvidenceProvenance,
    EvidenceRecord,
    EvidenceSlice,
    EvidenceScope,
)


class EvidenceNormalizer:
    """Convert, merge, and summarize evidence bundles."""

    @staticmethod
    def from_raw_bundle(raw_bundle: Optional[Dict[str, Any]]) -> EvidenceBundle:
        if not raw_bundle:
            return EvidenceBundle()

        records: List[EvidenceRecord] = []
        for item in raw_bundle.get("records", []) or []:
            scope_raw = item.get("scope", {}) or {}
            location_raw = item.get("location", {}) or {}
            provenance_raw = item.get("provenance", {}) or {}
            slice_raw = item.get("evidence_slice", {}) or {}
            provenance = None
            if provenance_raw:
                provenance = EvidenceProvenance(
                    tool=str(provenance_raw.get("tool", "")),
                    artifact=str(provenance_raw.get("artifact", "")),
                    confidence=float(provenance_raw.get("confidence", 0.5) or 0.5),
                )
            evidence_slice = EvidenceNormalizer._slice_from_raw(
                slice_raw=slice_raw,
                item=item,
                provenance=provenance,
            )
            records.append(
                EvidenceRecord(
                    evidence_id=str(item.get("evidence_id", "")),
                    type=EvidenceNormalizer._normalize_record_type(str(item.get("type", ""))),
                    analyzer=str(item.get("analyzer", "")),
                    scope=EvidenceScope(
                        repo=str(scope_raw.get("repo", "")),
                        file=str(scope_raw.get("file", "")),
                        function=str(scope_raw.get("function", "")),
                    ),
                    location=EvidenceLocation(
                        line=int(location_raw.get("line", 0) or 0),
                        column=int(location_raw.get("column", 0) or 0),
                    ),
                    semantic_payload=item.get("semantic_payload", {}) or {},
                    provenance=provenance,
                    evidence_slice=evidence_slice,
                )
            )

        return EvidenceBundle(
            records=records,
            missing_evidence=list(raw_bundle.get("missing_evidence", []) or []),
            collected_analyzers=list(raw_bundle.get("collected_analyzers", []) or []),
        )

    @staticmethod
    def merge_bundles(*bundles: EvidenceBundle) -> EvidenceBundle:
        merged_records: List[EvidenceRecord] = []
        merged_keys: Set[str] = set()
        missing: Set[str] = set()
        analyzers: Set[str] = set()

        for bundle in bundles:
            if not bundle:
                continue
            for record in bundle.records:
                key = EvidenceNormalizer._record_key(record)
                if key in merged_keys:
                    continue
                merged_keys.add(key)
                merged_records.append(record)
            missing.update(bundle.missing_evidence or [])
            analyzers.update(bundle.collected_analyzers or [])

        collected_types = {record.type for record in merged_records if record.type}
        remaining = sorted(item for item in missing if item not in collected_types)

        return EvidenceBundle(
            records=merged_records,
            missing_evidence=remaining,
            collected_analyzers=sorted(analyzers),
        )

    @staticmethod
    def summarize_bundle(
        bundle: EvidenceBundle,
        analyzer: Optional[str] = None,
        limit: int = 8,
    ) -> List[str]:
        if not bundle or not bundle.records:
            return []

        lines: List[str] = []
        count = 0
        for record in bundle.records:
            if analyzer and record.analyzer not in {analyzer, "patch"}:
                continue
            scope = record.scope
            target = scope.function or scope.file or scope.repo or "repo"
            payload = record.semantic_payload or {}
            detail = ""
            if isinstance(payload, dict):
                for key in (
                    "failure_mode",
                    "label",
                    "reason",
                    "summary",
                    "entry_points",
                    "guard_expr",
                    "summary_line",
                    "state_after",
                    "state_before",
                    "tracked_symbols",
                    "buffer_fields",
                    "feedback_hint",
                    "functions",
                    "apis",
                    "call_edges",
                    "call_targets",
                    "focus_functions",
                    "module_boundaries",
                ):
                    value = payload.get(key)
                    if value:
                        if isinstance(value, list):
                            detail = ", ".join(map(str, value[:3]))
                        else:
                            detail = str(value)
                        break
            line = f"- {record.type} @ {target}"
            if detail:
                line += f": {detail}"
            slice_kind = ""
            coverage_status = EvidenceNormalizer._coverage_status(record)
            if record.evidence_slice is not None:
                slice_kind = str(record.evidence_slice.kind or "").strip()
            if slice_kind:
                line += f" [slice={slice_kind}]"
            if coverage_status:
                line += f" [coverage={coverage_status}]"
            lines.append(line)
            count += 1
            if count >= limit:
                break

        if bundle.missing_evidence:
            lines.append(f"- missing: {', '.join(bundle.missing_evidence[:4])}")

        return lines

    @staticmethod
    def _record_key(record: EvidenceRecord) -> str:
        payload = json.dumps(record.semantic_payload or {}, ensure_ascii=False, sort_keys=True)
        evidence_slice = json.dumps(
            record.evidence_slice.to_dict() if record.evidence_slice else {},
            ensure_ascii=False,
            sort_keys=True,
        )
        return "|".join([
            record.type,
            record.analyzer,
            record.scope.file,
            record.scope.function,
            payload,
            evidence_slice,
        ])

    @staticmethod
    def is_context_summary(record: EvidenceRecord) -> bool:
        if record is None:
            return False
        if record.type == "context_summary":
            return True
        return bool(record.evidence_slice and record.evidence_slice.kind == "context_summary")

    @staticmethod
    def is_semantic_slice(record: EvidenceRecord) -> bool:
        if record is None or record.evidence_slice is None:
            return False
        return record.evidence_slice.kind != "context_summary"

    @staticmethod
    def is_verifier_backed_slice(record: EvidenceRecord) -> bool:
        return bool(record and record.evidence_slice and str(record.evidence_slice.verifier or "").strip())

    @staticmethod
    def semantic_slice_records(
        bundle: EvidenceBundle,
        analyzer: Optional[str] = None,
    ) -> List[EvidenceRecord]:
        records: List[EvidenceRecord] = []
        for record in getattr(bundle, "records", []) or []:
            if analyzer and record.analyzer != analyzer:
                continue
            if EvidenceNormalizer.is_semantic_slice(record):
                records.append(record)
        return records

    @staticmethod
    def context_summary_records(
        bundle: EvidenceBundle,
        analyzer: Optional[str] = None,
    ) -> List[EvidenceRecord]:
        records: List[EvidenceRecord] = []
        for record in getattr(bundle, "records", []) or []:
            if analyzer and record.analyzer != analyzer:
                continue
            if EvidenceNormalizer.is_context_summary(record):
                records.append(record)
        return records

    @staticmethod
    def slice_metrics(
        bundle: EvidenceBundle,
        analyzer: Optional[str] = None,
    ) -> Dict[str, Any]:
        semantic_count = 0
        context_count = 0
        verifier_backed = 0
        coverage_counts: Dict[str, int] = {}
        kinds: Dict[str, int] = {}

        for record in getattr(bundle, "records", []) or []:
            if analyzer and record.analyzer != analyzer:
                continue
            if EvidenceNormalizer.is_context_summary(record):
                context_count += 1
            if not EvidenceNormalizer.is_semantic_slice(record):
                continue
            semantic_count += 1
            if EvidenceNormalizer.is_verifier_backed_slice(record):
                verifier_backed += 1
            kind = str((record.evidence_slice.kind if record.evidence_slice else "") or "").strip() or "semantic_slice"
            kinds[kind] = kinds.get(kind, 0) + 1
            status = EvidenceNormalizer._coverage_status(record) or "unknown"
            coverage_counts[status] = coverage_counts.get(status, 0) + 1

        if semantic_count == 0:
            coverage = "missing"
        elif coverage_counts.get("missing", 0) > 0 or coverage_counts.get("partial", 0) > 0:
            coverage = "partial"
        elif coverage_counts.get("full", 0) > 0:
            coverage = "full"
        else:
            coverage = "unknown"

        return {
            "semantic_slice_count": semantic_count,
            "context_summary_count": context_count,
            "verifier_backed_count": verifier_backed,
            "coverage": coverage,
            "coverage_counts": coverage_counts,
            "kinds": kinds,
        }

    @staticmethod
    def _normalize_record_type(record_type: str) -> str:
        normalized = str(record_type or "").strip()
        if normalized == "slice_summary":
            return "context_summary"
        return normalized

    @staticmethod
    def _slice_from_raw(
        slice_raw: Dict[str, Any],
        item: Dict[str, Any],
        provenance: Optional[EvidenceProvenance],
    ) -> Optional[EvidenceSlice]:
        record_type = EvidenceNormalizer._normalize_record_type(str(item.get("type", "")))
        payload = item.get("semantic_payload", {}) or {}
        raw = dict(slice_raw or {})

        if not raw and record_type in {"context_summary", "semantic_slice"}:
            raw = {
                "kind": "context_summary" if record_type == "context_summary" else "semantic_slice",
                "summary": str(payload.get("summary", "") or ""),
                "coverage_status": str(payload.get("coverage_status", "") or "unknown"),
                "verifier": provenance.tool if provenance else "",
                "extraction_method": provenance.artifact if provenance else "",
            }

        if not raw:
            return None

        anchor_raw = raw.get("anchor", {}) or {}
        return EvidenceSlice(
            kind=str(raw.get("kind", "") or "semantic_slice"),
            anchor=EvidenceAnchor(
                patch_file=str(anchor_raw.get("patch_file", "") or ""),
                hunk_index=int(anchor_raw.get("hunk_index", 0) or 0),
                source_line=int(anchor_raw.get("source_line", 0) or 0),
            ),
            summary=str(raw.get("summary", "") or ""),
            statements=[str(value) for value in (raw.get("statements", []) or []) if str(value).strip()],
            guards=[str(value) for value in (raw.get("guards", []) or []) if str(value).strip()],
            call_boundary=[str(value) for value in (raw.get("call_boundary", []) or []) if str(value).strip()],
            call_edges=[str(value) for value in (raw.get("call_edges", []) or []) if str(value).strip()],
            state_transitions=[str(value) for value in (raw.get("state_transitions", []) or []) if str(value).strip()],
            api_terms=[str(value) for value in (raw.get("api_terms", []) or []) if str(value).strip()],
            related_symbols=[str(value) for value in (raw.get("related_symbols", []) or []) if str(value).strip()],
            verifier=str(raw.get("verifier", "") or ""),
            extraction_method=str(raw.get("extraction_method", "") or ""),
            coverage_status=str(raw.get("coverage_status", "") or "unknown"),
        )

    @staticmethod
    def _coverage_status(record: EvidenceRecord) -> str:
        if record.evidence_slice is not None:
            status = str(record.evidence_slice.coverage_status or "").strip()
            if status:
                return status
        payload = record.semantic_payload or {}
        return str(payload.get("coverage_status", "") or "").strip()
