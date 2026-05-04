"""
PATCHWEAVER core planning types.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List


class EvidenceType(str, Enum):
    """Persisted evidence primitives consumed by refine."""

    PATCH_FACT = "patch_fact"
    SEMANTIC_SLICE = "semantic_slice"
    DATAFLOW_CANDIDATE = "dataflow_candidate"
    CALL_CHAIN = "call_chain"
    PATH_GUARD = "path_guard"
    ALLOCATION_LIFECYCLE = "allocation_lifecycle"
    STATE_TRANSITION = "state_transition"

    # `directory_tree` is query-time derived context from `evidence_dir`,
    # not a persisted bundle record type.


class MechanismNodeKind(str, Enum):
    """Node kinds in the vulnerability mechanism graph."""

    PATCH = "patch"
    FILE = "file"
    PATTERN = "pattern"
    FUNCTION = "function"
    GUARD = "guard"
    FIX = "fix"
    DEPENDENCY = "dependency"
    STRATEGY = "strategy"
    COMMIT = "commit"
    CVE = "cve"
    CWE = "cwe"
    INTENT = "intent"


@dataclass(frozen=True)
class PatchFact:
    """Structured facts extracted from a patch."""

    fact_type: str
    label: str
    attributes: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "fact_type": self.fact_type,
            "label": self.label,
            "attributes": self.attributes,
        }


@dataclass(frozen=True)
class EvidenceRequirement:
    """A unit of evidence requested by the planner."""

    evidence_type: str
    reason: str
    priority: int = 50
    preferred_analyzers: List[str] = field(default_factory=list)
    confidence: float = 0.5
    mechanism_refs: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "evidence_type": self.evidence_type,
            "reason": self.reason,
            "priority": self.priority,
            "preferred_analyzers": list(self.preferred_analyzers),
            "confidence": self.confidence,
            "mechanism_refs": list(self.mechanism_refs),
        }


@dataclass(frozen=True)
class EvidencePlan:
    """Planner output consumed by analyzers and future collectors."""

    primary_pattern: str = "unknown"
    hypotheses: List[str] = field(default_factory=list)
    requirements: List[EvidenceRequirement] = field(default_factory=list)
    recommended_analyzers: List[str] = field(default_factory=list)
    planner_notes: List[str] = field(default_factory=list)
    coverage_gaps: List[str] = field(default_factory=list)
    uncertainty_budget: str = "normal"
    escalation_triggers: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "primary_pattern": self.primary_pattern,
            "hypotheses": list(self.hypotheses),
            "requirements": [item.to_dict() for item in self.requirements],
            "recommended_analyzers": list(self.recommended_analyzers),
            "planner_notes": list(self.planner_notes),
            "coverage_gaps": list(self.coverage_gaps),
            "uncertainty_budget": self.uncertainty_budget,
            "escalation_triggers": list(self.escalation_triggers),
        }
