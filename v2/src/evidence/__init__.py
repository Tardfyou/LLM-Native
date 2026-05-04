"""
PATCHWEAVER evidence collection and normalization.
"""

__all__ = ["EvidenceNormalizer", "EvidenceQueryTools", "AVAILABLE_EVIDENCE_TYPES"]


def __getattr__(name):
    if name == "EvidenceNormalizer":
        from .normalizer import EvidenceNormalizer

        return EvidenceNormalizer
    if name == "EvidenceQueryTools":
        from .evidence_tools import EvidenceQueryTools

        return EvidenceQueryTools
    if name == "AVAILABLE_EVIDENCE_TYPES":
        from .evidence_tools import AVAILABLE_EVIDENCE_TYPES

        return AVAILABLE_EVIDENCE_TYPES
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
