"""
工具实现模块

提供智能体可调用的工具:
- 文件操作: ApplyPatchTool, ReadFileTool, WriteFileTool
- 结构审查: ArtifactReviewTool
- 编译验证: CompileCheckerTool
- 知识检索: SearchKnowledgeTool
- LSP验证: LSPValidateTool, AsyncLSPValidateTool
- 补丁分析: PatchAnalysisTool
- 项目分析: ProjectAnalyzerTool
- 多文件操作: MultiFileOpsTool
- 语义验证: SemanticValidateTool
- CodeQL: CodeQLGenerateTool, CodeQLAnalyzeTool
- 分析器选择: AnalyzerSelectorTool
"""

from .apply_patch import ApplyPatchTool
from .file_ops import ReadFileTool, WriteFileTool
from .artifact_review import ArtifactReviewTool
from .compile import CompileCheckerTool
from .knowledge import SearchKnowledgeTool
from .lsp_validate import LSPValidateTool, AsyncLSPValidateTool
from .patch_analysis import PatchAnalysisTool, FileChange, VulnerabilityPattern
from .project_analyzer import ProjectAnalyzerTool, ProjectInfo
from .multi_file_ops import MultiFileOpsTool
from .semantic_validate import SemanticValidateTool, ValidationResult
from .provider import ToolProviderOptions, build_tool_registry

# 尝试导入CodeQL工具（可能不存在）
try:
    from .codeql_generate import CodeQLGenerateTool
    from .codeql_analyze import CodeQLAnalyzeTool
    CODEQL_AVAILABLE = True
except ImportError:
    CODEQL_AVAILABLE = False

# 尝试导入分析器选择工具
try:
    from .analyzer_selector import AnalyzerSelectorTool
    ANALYZER_SELECTOR_AVAILABLE = True
except ImportError:
    ANALYZER_SELECTOR_AVAILABLE = False

def register_all_tools(tool_registry, config: dict = None, analyzer: str = "csa", silent: bool = False):
    """
    注册所有工具到工具注册中心

    Args:
        tool_registry: 工具注册中心实例
        config: 配置字典
        analyzer: 分析器类型 (csa/codeql/both)
    """
    build_tool_registry(
        config=config or {},
        options=ToolProviderOptions(
            analyzer=analyzer,
            silent=silent,
        ),
        tool_registry=tool_registry,
    )


__all__ = [
    # 文件操作
    "ApplyPatchTool",
    "ReadFileTool",
    "WriteFileTool",
    # 结构审查
    "ArtifactReviewTool",
    # 编译
    "CompileCheckerTool",
    # 知识库
    "SearchKnowledgeTool",
    # LSP验证
    "LSPValidateTool",
    "AsyncLSPValidateTool",
    # 补丁分析
    "PatchAnalysisTool",
    "FileChange",
    "VulnerabilityPattern",
    # 项目分析
    "ProjectAnalyzerTool",
    "ProjectInfo",
    # 多文件操作
    "MultiFileOpsTool",
    # 语义验证
    "SemanticValidateTool",
    "ValidationResult",
    "ToolProviderOptions",
    "build_tool_registry",
    # 工具注册函数
    "register_all_tools",
]

if CODEQL_AVAILABLE:
    __all__.extend(["CodeQLGenerateTool", "CodeQLAnalyzeTool"])

if ANALYZER_SELECTOR_AVAILABLE:
    __all__.append("AnalyzerSelectorTool")
