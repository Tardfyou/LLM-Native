"""
Analyzer-native evidence collectors.

Keep package imports lightweight. In `both` mode the CSA and CodeQL analyzers
may import their collector modules from separate threads; eagerly importing all
collector submodules here can deadlock on Python's module import locks.
"""

from .base import EvidenceCollector
from .patch_semantics import PatchSemanticsCollector

__all__ = [
    "EvidenceCollector",
    "PatchSemanticsCollector",
]
