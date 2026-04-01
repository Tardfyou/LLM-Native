"""
工具提供层

统一负责：
- 构建 ToolRegistry
- 根据运行场景开关可选工具
- 让 agent / MCP 复用同一套工具装配逻辑
"""

from dataclasses import dataclass
from typing import Dict, Any, Optional

from loguru import logger

from ..agent.tools import ToolRegistry
from .apply_patch import ApplyPatchTool
from .artifact_review import ArtifactReviewTool
from .compile import CompileCheckerTool
from .file_ops import ReadFileTool, WriteFileTool
from .knowledge import SearchKnowledgeTool
from .lsp_validate import LSPValidateTool
from .multi_file_ops import MultiFileOpsTool
from .patch_analysis import PatchAnalysisTool
from .project_analyzer import ProjectAnalyzerTool
from .semantic_validate import SemanticValidateTool

try:
    from .codeql_generate import CodeQLGenerateTool
    from .codeql_analyze import CodeQLAnalyzeTool
    CODEQL_AVAILABLE = True
except ImportError:
    CODEQL_AVAILABLE = False

try:
    from .analyzer_selector import AnalyzerSelectorTool
    ANALYZER_SELECTOR_AVAILABLE = True
except ImportError:
    ANALYZER_SELECTOR_AVAILABLE = False


@dataclass(frozen=True)
class ToolProviderOptions:
    """工具注册选项。"""

    analyzer: str = "csa"
    include_knowledge: bool = True
    include_lsp: bool = True
    include_semantic: bool = True
    include_codeql: bool = True
    include_artifact_review: bool = True
    include_analyzer_selector: bool = True
    include_patch_analysis: bool = True
    include_project_analyzer: bool = True
    silent: bool = False


def build_tool_registry(
    config: Dict[str, Any] = None,
    options: Optional[ToolProviderOptions] = None,
    tool_registry: Optional[ToolRegistry] = None,
    llm_client=None,
) -> ToolRegistry:
    """构建并返回统一的 ToolRegistry。"""
    config = config or {}
    options = options or ToolProviderOptions()
    registry = tool_registry or ToolRegistry()

    _register_core_tools(
        registry,
        config,
        llm_client=llm_client,
        include_artifact_review=options.include_artifact_review,
        include_patch_analysis=options.include_patch_analysis,
        include_project_analyzer=options.include_project_analyzer,
    )

    if options.include_knowledge:
        _register_knowledge_tool(
            registry=registry,
            config=config,
            analyzer=options.analyzer,
            silent=options.silent,
        )

    if options.include_lsp:
        _register_lsp_tool(
            registry=registry,
            config=config,
            silent=options.silent,
        )

    if options.include_semantic:
        validation_config = config.get("validation", {})
        registry.register(SemanticValidateTool(validation_config))

    if options.include_codeql:
        _register_codeql_tools(
            registry=registry,
            config=config,
            silent=options.silent,
        )

    analyzer_selection_enabled = config.get("agent", {}).get("enable_analyzer_selection", True)
    if options.include_analyzer_selector and analyzer_selection_enabled and ANALYZER_SELECTOR_AVAILABLE:
        registry.register(AnalyzerSelectorTool())

    if not options.silent:
        logger.info(f"已注册 {len(registry)} 个工具")

    return registry


def _register_core_tools(
    registry: ToolRegistry,
    config: Dict[str, Any],
    llm_client=None,
    include_artifact_review: bool = True,
    include_patch_analysis: bool = True,
    include_project_analyzer: bool = True,
):
    registry.register(ReadFileTool())
    registry.register(WriteFileTool())
    registry.register(ApplyPatchTool())
    artifact_review_enabled = bool(
        (
            ((config or {}).get("quality_gates", {}) or {}).get("artifact_review", {}) or {}
        ).get("enabled", True)
    )
    if include_artifact_review and artifact_review_enabled:
        registry.register(ArtifactReviewTool())
    registry.register(CompileCheckerTool(config.get("compilation", {})))
    if include_patch_analysis:
        registry.register(
            PatchAnalysisTool(
                llm_client=llm_client,
                llm_config=config.get("llm", {}),
                prompt_config=config,
            )
        )
    if include_project_analyzer:
        registry.register(ProjectAnalyzerTool())
    registry.register(MultiFileOpsTool())


def _register_knowledge_tool(
    registry: ToolRegistry,
    config: Dict[str, Any],
    analyzer: str,
    silent: bool,
):
    kb_config = config.get("knowledge_base", {})
    kb = None

    if kb_config:
        try:
            from ..knowledge import get_knowledge_base

            kb = get_knowledge_base(kb_config)
            if kb.initialize():
                if not silent:
                    logger.info(f"知识库工具已注册 (分析器: {analyzer})")
            elif not silent:
                logger.warning("知识库初始化失败，知识库工具降级为不可用状态")
        except Exception as exc:
            if not silent:
                logger.warning(f"知识库工具注册失败: {exc}")

    registry.register(SearchKnowledgeTool(kb, analyzer=analyzer))


def _register_lsp_tool(
    registry: ToolRegistry,
    config: Dict[str, Any],
    silent: bool,
):
    try:
        from ..lsp.async_clangd_client import AsyncClangdClient
        from ..lsp.diagnostic_manager import DiagnosticManager

        compilation_config = config.get("compilation", {})
        llvm_dir = compilation_config.get("llvm_dir", "/usr/lib/llvm-18")
        clangd_config = {
            "clangd_path": f"{llvm_dir}/bin/clangd",
            "timeout_seconds": 30,
            "diagnostic_timeout": 10,
            "llvm_dir": llvm_dir,
        }

        clangd_client = AsyncClangdClient(clangd_config)
        diagnostic_manager = DiagnosticManager(clangd_client)
        registry.register(LSPValidateTool(diagnostic_manager))
        if not silent:
            logger.info("LSP验证工具已注册")
    except Exception as exc:
        if not silent:
            logger.warning(f"LSP验证工具注册失败: {exc}")
        registry.register(LSPValidateTool())


def _register_codeql_tools(
    registry: ToolRegistry,
    config: Dict[str, Any],
    silent: bool,
):
    if not CODEQL_AVAILABLE:
        return

    codeql_config = config.get("codeql", {})
    if not codeql_config.get("enabled", True):
        return

    registry.register(CodeQLGenerateTool(codeql_config))
    registry.register(CodeQLAnalyzeTool(codeql_config))
    if not silent:
        logger.info("CodeQL工具已注册")
