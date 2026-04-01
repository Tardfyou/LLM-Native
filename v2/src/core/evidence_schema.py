"""
PATCHWEAVER evidence schema.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class EvidenceScope:
    """Repository scope for an evidence record."""

    repo: str = ""
    file: str = ""
    function: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "repo": self.repo,
            "file": self.file,
            "function": self.function,
        }


@dataclass(frozen=True)
class EvidenceLocation:
    """Optional source location."""

    line: int = 0
    column: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "line": self.line,
            "column": self.column,
        }


@dataclass(frozen=True)
class EvidenceAnchor:
    """Patch/source anchor for a semantic slice."""

    patch_file: str = ""
    hunk_index: int = 0
    source_line: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "patch_file": self.patch_file,
            "hunk_index": self.hunk_index,
            "source_line": self.source_line,
        }


@dataclass(frozen=True)
class EvidenceSlice:
    """Structured semantic slice consumed by synthesis."""

    kind: str
    anchor: EvidenceAnchor = field(default_factory=EvidenceAnchor)
    summary: str = ""
    statements: List[str] = field(default_factory=list)
    guards: List[str] = field(default_factory=list)
    call_boundary: List[str] = field(default_factory=list)
    call_edges: List[str] = field(default_factory=list)
    state_transitions: List[str] = field(default_factory=list)
    api_terms: List[str] = field(default_factory=list)
    related_symbols: List[str] = field(default_factory=list)
    verifier: str = ""
    extraction_method: str = ""
    coverage_status: str = "unknown"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kind": self.kind,
            "anchor": self.anchor.to_dict(),
            "summary": self.summary,
            "statements": list(self.statements),
            "guards": list(self.guards),
            "call_boundary": list(self.call_boundary),
            "call_edges": list(self.call_edges),
            "state_transitions": list(self.state_transitions),
            "api_terms": list(self.api_terms),
            "related_symbols": list(self.related_symbols),
            "verifier": self.verifier,
            "extraction_method": self.extraction_method,
            "coverage_status": self.coverage_status,
        }


@dataclass(frozen=True)
class EvidenceProvenance:
    """Origin metadata for evidence."""

    tool: str
    artifact: str
    confidence: float = 0.5

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool": self.tool,
            "artifact": self.artifact,
            "confidence": self.confidence,
        }


@dataclass(frozen=True)
class EvidenceRecord:
    """A normalized evidence object."""

    evidence_id: str
    type: str
    analyzer: str
    scope: EvidenceScope = field(default_factory=EvidenceScope)
    location: EvidenceLocation = field(default_factory=EvidenceLocation)
    semantic_payload: Dict[str, Any] = field(default_factory=dict)
    provenance: Optional[EvidenceProvenance] = None
    evidence_slice: Optional[EvidenceSlice] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "type": self.type,
            "analyzer": self.analyzer,
            "scope": self.scope.to_dict(),
            "location": self.location.to_dict(),
            "semantic_payload": self.semantic_payload,
            "provenance": self.provenance.to_dict() if self.provenance else {},
            "evidence_slice": self.evidence_slice.to_dict() if self.evidence_slice else {},
        }


@dataclass
class EvidenceBundle:
    """Evidence records plus outstanding requirements."""

    records: List[EvidenceRecord] = field(default_factory=list)
    missing_evidence: List[str] = field(default_factory=list)
    collected_analyzers: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "records": [item.to_dict() for item in self.records],
            "missing_evidence": list(self.missing_evidence),
            "collected_analyzers": list(self.collected_analyzers),
        }
