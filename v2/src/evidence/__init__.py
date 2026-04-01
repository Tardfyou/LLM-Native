"""
PATCHWEAVER evidence collection and normalization.
"""

__all__ = ["EvidenceNormalizer"]


def __getattr__(name):
    if name == "EvidenceNormalizer":
        from .normalizer import EvidenceNormalizer

        return EvidenceNormalizer
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
