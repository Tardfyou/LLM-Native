"""
验证模块

提供统一的验证接口，支持多种静态分析工具。
"""

from .types import (
    AnalyzerType,
    ValidationStage,
    ValidationResult,
    UnifiedValidationResult,
    Diagnostic,
)
from .codeql_support import (
    build_codeql_search_path_args,
    ensure_codeql_pack,
    is_codeql_database_dir,
    resolve_codeql_database_path,
    resolve_codeql_search_path,
    build_codeql_database_path,
)
from .lsp_validator import LSPValidator
from .semantic_validator import SemanticValidator
from .unified_validator import (
    UnifiedValidator,
    create_validator
)
from .analyzer_support import (
    parse_analyzer_choice,
    infer_analyzer_from_artifact,
)

__all__ = [
    "UnifiedValidator",
    "AnalyzerType",
    "ValidationStage",
    "ValidationResult",
    "UnifiedValidationResult",
    "Diagnostic",
    "build_codeql_search_path_args",
    "ensure_codeql_pack",
    "is_codeql_database_dir",
    "resolve_codeql_database_path",
    "resolve_codeql_search_path",
    "build_codeql_database_path",
    "LSPValidator",
    "SemanticValidator",
    "create_validator",
    "parse_analyzer_choice",
    "infer_analyzer_from_artifact",
]
