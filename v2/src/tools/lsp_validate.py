"""
LSP验证工具 - 供智能体调用

提供:
- LSPValidateTool: 使用LSP快速验证代码
"""

import asyncio
from typing import Dict, Any, Optional

from ..agent.tools import Tool, ToolResult
from ..lsp.diagnostic_manager import DiagnosticManager, DiagnosticSummary


class LSPValidateTool(Tool):
    """LSP验证工具 - 使用clangd进行代码诊断"""

    def __init__(self, diagnostic_manager: DiagnosticManager = None):
        """
        初始化

        Args:
            diagnostic_manager: 诊断管理器实例
        """
        self.dm = diagnostic_manager

    def set_work_dir(self, work_dir: str):
        """设置工作目录，约束 LSP 临时文件位置。"""
        if self.dm and hasattr(self.dm, "set_work_dir"):
            self.dm.set_work_dir(work_dir)

    @property
    def name(self) -> str:
        return "lsp_validate"

    @property
    def description(self) -> str:
        return """使用LSP快速验证代码语法和语义。

在编译前快速检测语法错误、类型错误等问题。
比完整编译更快，可以快速迭代修复问题。

验证级别:
- quick: 快速模式（默认，推荐）。优先使用编译器兼容语法检查，结果更贴近真实编译报错
- full: 完整模式。合并 clangd 诊断 + 编译器兼容检查（更全面，但比 quick 慢）

返回诊断信息和修复建议。"""

    @property
    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "code": {
                    "type": "string",
                    "description": "要验证的代码内容（完整的C++代码）"
                },
                "check_level": {
                    "type": "string",
                    "enum": ["quick", "full"],
                    "default": "quick",
                    "description": "验证级别: quick=仅语法检查, full=完整分析"
                },
                "file_name": {
                    "type": "string",
                    "default": "checker.cpp",
                    "description": "文件名（用于诊断信息显示）"
                }
            },
            "required": ["code"]
        }

    def execute(
        self,
        code: str,
        check_level: str = "quick",
        file_name: str = "checker.cpp"
    ) -> ToolResult:
        """
        执行LSP验证

        Args:
            code: 代码内容
            check_level: 验证级别
            file_name: 文件名

        Returns:
            ToolResult
        """
        if self.dm is None:
            return ToolResult(
                success=False,
                output="",
                error="诊断管理器未初始化"
            )

        try:
            # 运行异步验证
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

            try:
                if check_level == "quick":
                    success, error_messages = loop.run_until_complete(
                        self.dm.quick_syntax_check(code)
                    )

                    if success:
                        return ToolResult(
                            success=True,
                            output="✅ LSP快速验证通过，没有发现语法错误",
                            metadata={
                                "check_level": "quick",
                                "errors": 0
                            }
                        )
                    else:
                        return ToolResult(
                            success=False,
                            output="❌ 发现语法错误:\n" + "\n".join(f"  - {e}" for e in error_messages),
                            error=f"发现 {len(error_messages)} 个语法错误",
                            metadata={
                                "check_level": "quick",
                                "errors": len(error_messages),
                                "error_messages": error_messages
                            }
                        )

                else:  # full
                    success, summary, diagnostics = loop.run_until_complete(
                        self.dm.full_check(code, file_name)
                    )

                    formatted = self.dm.format_diagnostics(diagnostics)
                    suggestions = self.dm.get_fix_suggestions(diagnostics)

                    if success:
                        return ToolResult(
                            success=True,
                            output=f"✅ LSP完整验证通过\n{formatted}",
                            metadata={
                                "check_level": "full",
                                "summary": summary.to_dict(),
                                "diagnostics": [d.to_dict() for d in diagnostics]
                            }
                        )
                    else:
                        # 构建详细输出
                        output_parts = [f"❌ LSP验证失败:\n{formatted}"]

                        if suggestions:
                            output_parts.append("\n💡 修复建议:")
                            for s in suggestions[:5]:
                                output_parts.append(f"  Line {s['line']}: {s['possible_fix']}")

                        return ToolResult(
                            success=False,
                            output="\n".join(output_parts),
                            error=f"发现 {summary.errors} 个错误, {summary.warnings} 个警告",
                            metadata={
                                "check_level": "full",
                                "summary": summary.to_dict(),
                                "diagnostics": [d.to_dict() for d in diagnostics],
                                "suggestions": suggestions
                            }
                        )

            finally:
                loop.close()

        except Exception as e:
            return ToolResult(
                success=False,
                output="",
                error=f"LSP验证异常: {str(e)}"
            )


class AsyncLSPValidateTool(Tool):
    """异步LSP验证工具 - 用于异步智能体"""

    def __init__(self, diagnostic_manager: DiagnosticManager = None):
        self.dm = diagnostic_manager

    def set_work_dir(self, work_dir: str):
        """设置工作目录，约束 LSP 临时文件位置。"""
        if self.dm and hasattr(self.dm, "set_work_dir"):
            self.dm.set_work_dir(work_dir)

    @property
    def name(self) -> str:
        return "lsp_validate_async"

    @property
    def description(self) -> str:
        return LSPValidateTool(None).description + "\n\n这是异步版本。"

    @property
    def parameters_schema(self) -> Dict[str, Any]:
        return LSPValidateTool(None).parameters_schema

    async def execute(
        self,
        code: str,
        check_level: str = "quick",
        file_name: str = "checker.cpp"
    ) -> ToolResult:
        """异步执行LSP验证"""
        if self.dm is None:
            return ToolResult(
                success=False,
                output="",
                error="诊断管理器未初始化"
            )

        try:
            if check_level == "quick":
                success, error_messages = await self.dm.quick_syntax_check(code)

                if success:
                    return ToolResult(
                        success=True,
                        output="✅ LSP快速验证通过",
                        metadata={"check_level": "quick", "errors": 0}
                    )
                else:
                    return ToolResult(
                        success=False,
                        output="❌ 发现语法错误:\n" + "\n".join(f"  - {e}" for e in error_messages),
                        error=f"发现 {len(error_messages)} 个语法错误",
                        metadata={
                            "check_level": "quick",
                            "errors": len(error_messages),
                            "error_messages": error_messages
                        }
                    )

            else:  # full
                success, summary, diagnostics = await self.dm.full_check(code, file_name)

                formatted = self.dm.format_diagnostics(diagnostics)

                if success:
                    return ToolResult(
                        success=True,
                        output=f"✅ LSP完整验证通过\n{formatted}",
                        metadata={
                            "check_level": "full",
                            "summary": summary.to_dict(),
                            "diagnostics": [d.to_dict() for d in diagnostics]
                        }
                    )
                else:
                    return ToolResult(
                        success=False,
                        output=f"❌ LSP验证失败:\n{formatted}",
                        error=f"发现 {summary.errors} 个错误, {summary.warnings} 个警告",
                        metadata={
                            "check_level": "full",
                            "summary": summary.to_dict(),
                            "diagnostics": [d.to_dict() for d in diagnostics]
                        }
                    )

        except Exception as e:
            return ToolResult(
                success=False,
                output="",
                error=f"LSP验证异常: {str(e)}"
            )
