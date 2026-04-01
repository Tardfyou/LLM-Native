"""
LSP模块 - Clangd集成

提供:
- ClangdClient: 同步LSP客户端（旧版）
- AsyncClangdClient: 异步LSP客户端（推荐）
- DiagnosticManager: 诊断管理器
"""

from .clangd_client import ClangdClient, get_clangd_client
from .async_clangd_client import AsyncClangdClient, Diagnostic, get_async_clangd_client
from .diagnostic_manager import DiagnosticManager, DiagnosticSummary, get_diagnostic_manager

__all__ = [
    # 旧版同步客户端
    "ClangdClient",
    "get_clangd_client",
    # 新版异步客户端
    "AsyncClangdClient",
    "Diagnostic",
    "get_async_clangd_client",
    # 诊断管理
    "DiagnosticManager",
    "DiagnosticSummary",
    "get_diagnostic_manager",
]
