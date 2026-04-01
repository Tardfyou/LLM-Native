"""
验证侧分析器辅助函数

避免 CLI、展示层、验证层分别维护一套分析器解析逻辑。
"""

from pathlib import Path

from .unified_validator import AnalyzerType


def parse_analyzer_choice(choice: str) -> AnalyzerType:
    """将用户输入解析为验证侧分析器类型。"""
    normalized = str(choice or "").lower().strip()

    if normalized in {"csa", "clang", "clang-static-analyzer"}:
        return AnalyzerType.CSA
    if normalized in {"codeql", "ql"}:
        return AnalyzerType.CODEQL
    return AnalyzerType.BOTH


def infer_analyzer_from_artifact(artifact_path: str, fallback_choice: str = "auto") -> AnalyzerType:
    """根据检测器文件后缀推断分析器类型。"""
    suffix = Path(artifact_path or "").suffix.lower()
    if suffix == ".so":
        return AnalyzerType.CSA
    if suffix == ".ql":
        return AnalyzerType.CODEQL
    return parse_analyzer_choice(fallback_choice)

