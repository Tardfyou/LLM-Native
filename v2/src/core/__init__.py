"""
核心模块

提供:
- Orchestrator: 主编排器
- 分析器抽象基类和实现
"""

from .orchestrator import Orchestrator, GenerationResult, EvidenceCollectionResult
from .analyzer_manager import AnalyzerManager
from .analyzer_base import (
    AnalyzerType,
    AnalyzerDescriptor,
    AnalyzerContext,
    AnalyzerResult,
    BaseAnalyzer,
    AnalyzerRegistry
)
from .evidence_types import EvidencePlan, EvidenceRequirement, EvidenceType, PatchFact
from .evidence_schema import EvidenceBundle, EvidenceRecord
from .mechanism_graph import VulnerabilityMechanismGraph
from .evidence_planner import PatchWeaverPreflight
from .detector_synthesizer import DetectorSynthesisInput, DetectorSynthesisInputBuilder, SynthesisConstraint
from .portfolio_controller import PortfolioController, PortfolioDecision, PortfolioCandidate
from .validation_feedback import ValidationFeedbackBuilder
from .csa_analyzer import CSAAnalyzer
from .codeql_analyzer import CodeQLAnalyzer

__all__ = [
    # 主编排器
    "Orchestrator",
    "GenerationResult",
    "EvidenceCollectionResult",
    "AnalyzerManager",

    # 分析器基类
    "AnalyzerType",
    "AnalyzerDescriptor",
    "AnalyzerContext",
    "AnalyzerResult",
    "BaseAnalyzer",
    "AnalyzerRegistry",
    "EvidenceType",
    "PatchFact",
    "EvidenceRequirement",
    "EvidencePlan",
    "EvidenceRecord",
    "EvidenceBundle",
    "VulnerabilityMechanismGraph",
    "PatchWeaverPreflight",
    "SynthesisConstraint",
    "DetectorSynthesisInput",
    "DetectorSynthesisInputBuilder",
    "PortfolioController",
    "PortfolioDecision",
    "PortfolioCandidate",
    "ValidationFeedbackBuilder",

    # 分析器实现
    "CSAAnalyzer",
    "CodeQLAnalyzer",
]
