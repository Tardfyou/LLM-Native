"""
编译工具

提供:
- CompileCheckerTool: 编译 Clang 检测器
"""

import os
import subprocess
import tempfile
from typing import Dict, Any

from ..agent.tools import Tool, ToolResult


class CompileCheckerTool(Tool):
    """编译检测器工具"""

    def __init__(self, compilation_config: Dict[str, Any] = None):
        """
        初始化

        Args:
            compilation_config: 编译配置，包含:
                - llvm_dir: LLVM 安装目录
                - clang_path: clang++ 路径
                - timeout_seconds: 编译超时时间
        """
        self.config = compilation_config or {}
        self.work_dir = self.config.get("work_dir")
        self.llvm_dir = self.config.get("llvm_dir", "/usr/lib/llvm-18")
        self.clang_path = self.config.get("clang_path", f"{self.llvm_dir}/bin/clang++")
        self.timeout = self.config.get("timeout_seconds", 120)

    def set_work_dir(self, work_dir: str):
        """设置工作目录，确保编译输出留在任务输出目录内。"""
        self.work_dir = work_dir

    @property
    def name(self) -> str:
        return "compile_checker"

    @property
    def description(self) -> str:
        return """编译 Clang 静态分析检测器。
将检测器源代码编译为可加载的 .so 共享库。
如果编译失败，会返回详细的错误信息供分析和修复。
编译成功时返回 .so 文件的路径。"""

    @property
    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "checker_name": {
                    "type": "string",
                    "description": "检测器名称 (如 NullPointerChecker)，用于命名输出文件"
                },
                "source_code": {
                    "type": "string",
                    "description": "检测器源代码 (完整的 C++ 代码)"
                },
                "output_dir": {
                    "type": "string",
                    "description": "输出目录 (可选，不提供则使用临时目录)"
                }
            },
            "required": ["checker_name", "source_code"]
        }

    def execute(
        self,
        checker_name: str,
        source_code: str,
        output_dir: str = None
    ) -> ToolResult:
        """
        执行编译

        Args:
            checker_name: 检测器名称
            source_code: 源代码
            output_dir: 输出目录

        Returns:
            ToolResult
        """
        try:
            # 设置输出目录
            if output_dir is None:
                output_dir = self._default_output_dir(checker_name)
            os.makedirs(output_dir, exist_ok=True)

            # 保存源文件
            source_file = os.path.join(output_dir, f"{checker_name}.cpp")
            with open(source_file, 'w', encoding='utf-8') as f:
                f.write(source_code)

            # 输出文件
            output_file = os.path.join(output_dir, f"{checker_name}.so")

            # 构建编译命令
            cmd = [
                self.clang_path,
                "-shared", "-fPIC",
                "-std=c++20",
                "-O2",
                # Include 路径
                f"-I{self.llvm_dir}/include",
                f"-I{self.llvm_dir}/include/clang",
                f"-I{self.llvm_dir}/include/clang/StaticAnalyzer",
                f"-I{self.llvm_dir}/include/clang/StaticAnalyzer/Core",
                f"-I{self.llvm_dir}/include/clang/StaticAnalyzer/Frontend",
                f"-I{self.llvm_dir}/include/llvm",
                source_file,
                # 链接选项
                f"-L{self.llvm_dir}/lib",
                "-lclang-cpp",
                f"-Wl,-rpath,{self.llvm_dir}/lib",
                "-o", output_file
            ]

            # 执行编译
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )

            if result.returncode == 0:
                # 编译成功
                file_size = os.path.getsize(output_file) if os.path.exists(output_file) else 0
                return ToolResult(
                    success=True,
                    output=f"编译成功!\n输出文件: {output_file}\n文件大小: {file_size} 字节",
                    metadata={
                        "source_file": source_file,
                        "output_file": output_file,
                        "file_size": file_size,
                        "checker_name": checker_name
                    }
                )
            else:
                # 编译失败
                error_output = result.stderr or result.stdout

                # 统计错误
                error_lines = error_output.strip().split('\n')
                error_count = len([l for l in error_lines if 'error:' in l])
                warning_count = len([l for l in error_lines if 'warning:' in l])

                return ToolResult(
                    success=False,
                    output=error_output,
                    error=f"编译失败: {error_count} 个错误, {warning_count} 个警告",
                    metadata={
                        "source_file": source_file,
                        "error_count": error_count,
                        "warning_count": warning_count,
                        "checker_name": checker_name
                    }
                )

        except subprocess.TimeoutExpired:
            return ToolResult(
                success=False,
                output="",
                error=f"编译超时 ({self.timeout}秒)"
            )
        except FileNotFoundError:
            return ToolResult(
                success=False,
                output="",
                error=f"编译器未找到: {self.clang_path}"
            )
        except Exception as e:
            return ToolResult(
                success=False,
                output="",
                error=f"编译异常: {str(e)}"
            )

    def _default_output_dir(self, checker_name: str) -> str:
        """返回默认输出目录。"""
        if self.work_dir:
            work_dir_abs = os.path.abspath(self.work_dir)
            if os.path.basename(work_dir_abs) == "csa":
                return work_dir_abs
            return os.path.join(work_dir_abs, "csa")
        return tempfile.mkdtemp(prefix=f"checker_{checker_name}_")
