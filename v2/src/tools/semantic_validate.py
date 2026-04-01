"""
语义验证工具 - 使用生成的检测器验证目标代码

提供:
- SemanticValidateTool: 语义验证工具
"""

import os
import subprocess
import tempfile
from typing import Dict, Any, List, Optional
from pathlib import Path
from dataclasses import dataclass

from ..agent.tools import Tool, ToolResult
from loguru import logger


@dataclass
class ValidationResult:
    """验证结果"""
    file_path: str
    has_bugs: bool
    bug_reports: List[str]
    error: Optional[str] = None


class SemanticValidateTool(Tool):
    """语义验证工具 - 使用生成的检测器检查目标代码"""

    def __init__(self, config: Dict[str, Any] = None):
        """
        初始化

        Args:
            config: 配置，包含:
                - clang_path: clang++路径
                - llvm_dir: LLVM目录
                - timeout_seconds: 超时时间
        """
        self.config = config or {}
        self.clang_path = self.config.get("clang_path", "/usr/lib/llvm-18/bin/clang++")
        self.llvm_dir = self.config.get("llvm_dir", "/usr/lib/llvm-18")
        self.timeout = self.config.get("timeout_seconds", 120)

    @property
    def name(self) -> str:
        return "semantic_validate"

    @property
    def description(self) -> str:
        return """语义验证工具 - 使用生成的检测器检查目标代码。

在检测器编译成功后，使用它来分析目标文件或目录，验证检测器是否能够正确识别漏洞。

支持:
- 单文件验证
- 目录批量验证
- 生成详细的验证报告

返回验证结果，包括发现的漏洞数量和位置。"""

    @property
    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "checker_so_path": {
                    "type": "string",
                    "description": "编译好的检测器.so文件路径"
                },
                "checker_name": {
                    "type": "string",
                    "description": "检测器名称 (如 custom.NullDereferenceChecker)"
                },
                "target_path": {
                    "type": "string",
                    "description": "目标文件或目录路径"
                },
                "include_dirs": {
                    "type": "array",
                    "items": {"type": "string"},
                    "default": [],
                    "description": "额外的include目录"
                },
                "compile_commands_path": {
                    "type": "string",
                    "description": "compile_commands.json路径（可选，用于项目级分析）"
                }
            },
            "required": ["checker_so_path", "checker_name", "target_path"]
        }

    def execute(
        self,
        checker_so_path: str,
        checker_name: str,
        target_path: str,
        include_dirs: List[str] = None,
        compile_commands_path: str = None
    ) -> ToolResult:
        """
        执行语义验证

        Args:
            checker_so_path: 检测器.so文件路径
            checker_name: 检测器名称
            target_path: 目标路径
            include_dirs: include目录列表
            compile_commands_path: compile_commands.json路径

        Returns:
            ToolResult
        """
        include_dirs = include_dirs or []

        # 检查检测器文件
        if not os.path.exists(checker_so_path):
            return ToolResult(
                success=False,
                output="",
                error=f"检测器文件不存在: {checker_so_path}"
            )

        # 检查目标路径
        if not os.path.exists(target_path):
            return ToolResult(
                success=False,
                output="",
                error=f"目标路径不存在: {target_path}"
            )

        try:
            target = Path(target_path)

            if target.is_file():
                # 单文件验证
                result = self._validate_single_file(
                    checker_so_path, checker_name, target_path, include_dirs
                )
            else:
                # 目录验证
                result = self._validate_directory(
                    checker_so_path, checker_name, target_path, include_dirs, compile_commands_path
                )

            # 汇总结果
            total_bugs = sum(1 for r in result if r.has_bugs)
            total_reports = sum(len(r.bug_reports) for r in result)

            output_lines = [
                f"📊 语义验证完成",
                f"=" * 50,
                f"",
                f"检测器: {checker_name}",
                f"目标: {target_path}",
                f"分析文件数: {len(result)}",
                f"发现问题文件: {total_bugs}",
                f"漏洞报告数: {total_reports}",
                ""
            ]

            # 显示详细报告
            for r in result:
                if r.has_bugs:
                    output_lines.append(f"📄 {r.file_path}:")
                    for report in r.bug_reports:
                        output_lines.append(f"  ⚠️ {report}")
                    output_lines.append("")

            if total_bugs == 0:
                output_lines.append("✅ 未发现问题")

            return ToolResult(
                success=True,
                output="\n".join(output_lines),
                metadata={
                    "checker_name": checker_name,
                    "target_path": target_path,
                    "files_analyzed": len(result),
                    "files_with_bugs": total_bugs,
                    "total_bug_reports": total_reports,
                    "results": [
                        {
                            "file_path": r.file_path,
                            "has_bugs": r.has_bugs,
                            "bug_reports": r.bug_reports
                        }
                        for r in result
                    ]
                }
            )

        except Exception as e:
            return ToolResult(
                success=False,
                output="",
                error=f"语义验证失败: {str(e)}"
            )

    def _validate_single_file(
        self,
        checker_so_path: str,
        checker_name: str,
        file_path: str,
        include_dirs: List[str]
    ) -> List[ValidationResult]:
        """验证单个文件"""
        result = self._run_clang_analyze(
            checker_so_path, checker_name, file_path, include_dirs
        )
        return [result]

    def _validate_directory(
        self,
        checker_so_path: str,
        checker_name: str,
        dir_path: str,
        include_dirs: List[str],
        compile_commands_path: str = None
    ) -> List[ValidationResult]:
        """验证目录"""
        results = []

        # 查找C/C++源文件
        source_extensions = {'.c', '.cpp', '.cc', '.cxx', '.m', '.mm'}
        source_files = []

        for root, dirs, files in os.walk(dir_path):
            # 过滤排除目录
            dirs[:] = [d for d in dirs if d not in {'build', '.git', '__pycache__', 'node_modules'}]

            for f in files:
                if os.path.splitext(f)[1].lower() in source_extensions:
                    source_files.append(os.path.join(root, f))

        logger.info(f"找到 {len(source_files)} 个源文件")

        # 分析每个文件
        for source_file in source_files:
            result = self._run_clang_analyze(
                checker_so_path, checker_name, source_file, include_dirs
            )
            results.append(result)

        return results

    def _run_clang_analyze(
        self,
        checker_so_path: str,
        checker_name: str,
        source_file: str,
        include_dirs: List[str]
    ) -> ValidationResult:
        """运行clang --analyze"""
        try:
            # 构建命令
            cmd = [
                self.clang_path,
                "--analyze",
                f"-Xclang", "-load", "-Xclang", checker_so_path,
                "-Xclang", "-analyzer-checker", "-Xclang", checker_name,
                "-Xclang", "-analyzer-display-progress",
                "-Xclang", "-analyzer-output=text"
            ]

            # 添加include目录
            for inc_dir in include_dirs:
                cmd.extend(["-I", inc_dir])

            # 添加源文件
            cmd.append(source_file)

            logger.debug(f"运行: {' '.join(cmd)}")

            # 执行
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )

            # 解析输出
            output = result.stdout + result.stderr
            bug_reports = self._parse_analyzer_output(output)

            return ValidationResult(
                file_path=source_file,
                has_bugs=len(bug_reports) > 0,
                bug_reports=bug_reports
            )

        except subprocess.TimeoutExpired:
            return ValidationResult(
                file_path=source_file,
                has_bugs=False,
                bug_reports=[],
                error=f"分析超时 ({self.timeout}秒)"
            )
        except Exception as e:
            return ValidationResult(
                file_path=source_file,
                has_bugs=False,
                bug_reports=[],
                error=str(e)
            )

    def _parse_analyzer_output(self, output: str) -> List[str]:
        """解析分析器输出"""
        reports = []

        for line in output.split('\n'):
            # 匹配警告/错误行
            if 'warning:' in line.lower() or 'error:' in line.lower():
                # 提取关键信息
                if checker_match := self._extract_bug_info(line):
                    reports.append(checker_match)

        return reports

    def _extract_bug_info(self, line: str) -> Optional[str]:
        """提取漏洞信息"""
        import re

        # 匹配格式: file:line:col: warning: message
        pattern = r'.*?:(\d+):\d+: (warning|error): (.+)'
        if match := re.match(pattern, line):
            line_num = match.group(1)
            message = match.group(3).strip()
            return f"Line {line_num}: {message}"

        return None
