"""
验证层共享类型
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class AnalyzerType(Enum):
    """验证侧分析器类型。"""

    CSA = "csa"
    CODEQL = "codeql"
    BOTH = "both"


class ValidationStage(Enum):
    """验证阶段。"""

    SYNTAX = "syntax"
    LSP = "lsp"
    SEMANTIC = "semantic"

@dataclass
class Diagnostic:
    """诊断信息。"""

    file_path: str
    line: int
    column: int
    severity: str
    message: str
    source: str
    code: str = ""
    suggestion: str = ""


@dataclass
class ValidationResult:
    """单次验证结果。"""

    stage: ValidationStage
    analyzer: AnalyzerType
    success: bool
    diagnostics: List[Diagnostic] = field(default_factory=list)
    execution_time: float = 0.0
    error_message: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class UnifiedValidationResult:
    """统一验证结果。"""

    syntax_valid: bool = False
    lsp_valid: bool = False
    semantic_valid: bool = False
    overall_success: bool = False
    csa_results: Dict[str, ValidationResult] = field(default_factory=dict)
    codeql_results: Dict[str, ValidationResult] = field(default_factory=dict)
    all_diagnostics: List[Diagnostic] = field(default_factory=list)
    task_status: Dict[str, bool] = field(default_factory=dict)
    summary: str = ""
    execution_time: float = 0.0
