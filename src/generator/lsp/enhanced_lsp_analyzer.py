"""
增强型 LSP 代码分析器
提供更强大的代码分析、诊断和建议功能
"""

import asyncio
import json
import logging
import re
import tempfile
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

from loguru import logger
from .clangd_client import ClangdClient


class CodeIssueType(Enum):
    """代码问题类型"""
    SYNTAX_ERROR = "syntax_error"
    SEMANTIC_ERROR = "semantic_error"
    COMPILATION_ERROR = "compilation_error"
    WARNING = "warning"
    STYLE_ISSUE = "style_issue"
    PERFORMANCE_ISSUE = "performance_issue"
    SECURITY_ISSUE = "security_issue"


@dataclass
class CodeIssue:
    """代码问题"""
    type: CodeIssueType
    severity: int  # 1=error, 2=warning, 3=info, 4=hint
    message: str
    line: int
    column: int
    end_line: Optional[int] = None
    end_column: Optional[int] = None
    code: Optional[str] = ""
    suggested_fix: Optional[str] = None
    related_code: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type.value,
            "severity": self.severity,
            "message": self.message,
            "line": self.line,
            "column": self.column,
            "end_line": self.end_line,
            "end_column": self.end_column,
            "code": self.code,
            "suggested_fix": self.suggested_fix,
            "related_code": self.related_code
        }


@dataclass
class CodeAnalysisResult:
    """代码分析结果"""
    file_path: str
    code: str
    issues: List[CodeIssue] = field(default_factory=list)
    metrics: Dict[str, Any] = field(default_factory=dict)
    suggestions: List[str] = field(default_factory=list)
    ast_info: Dict[str, Any] = field(default_factory=dict)

    @property
    def has_errors(self) -> bool:
        return any(i.type in [CodeIssueType.SYNTAX_ERROR, CodeIssueType.COMPILATION_ERROR]
                   for i in self.issues)

    @property
    def error_count(self) -> int:
        return sum(1 for i in self.issues if i.severity == 1)

    @property
    def warning_count(self) -> int:
        return sum(1 for i in self.issues if i.severity == 2)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_path": self.file_path,
            "code": self.code,
            "issues": [i.to_dict() for i in self.issues],
            "metrics": self.metrics,
            "suggestions": self.suggestions,
            "ast_info": self.ast_info,
            "has_errors": self.has_errors,
            "error_count": self.error_count,
            "warning_count": self.warning_count
        }


class EnhancedLSPAnalyzer:
    """
    增强 LSP 分析器

    功能：
    1. 深度代码分析（语法、语义、风格）
    2. 智能修复建议
    3. 代码度量计算
    4. AST 信息提取
    5. 安全漏洞检测
    """

    def __init__(self, clangd_client: Optional[ClangdClient] = None):
        """
        初始化增强 LSP 分析器

        Args:
            clangd_client: Clangd 客户端（可选）
        """
        self.clangd_client = clangd_client or ClangdClient()
        self.is_lsp_available = False

    async def initialize(self, project_root: Path) -> bool:
        """
        初始化 LSP 分析器

        Args:
            project_root: 项目根目录

        Returns:
            是否成功初始化
        """
        self.is_lsp_available = await self.clangd_client.initialize_server(project_root)

        if self.is_lsp_available:
            logger.info("Enhanced LSP Analyzer initialized with LSP support")
        else:
            logger.warning("Enhanced LSP Analyzer initialized without LSP (using fallback)")

        return True

    async def analyze_code(
        self,
        code: str,
        file_path: str = "checker.cpp",
        analysis_level: str = "full"
    ) -> CodeAnalysisResult:
        """
        深度分析代码

        Args:
            code: 要分析的代码
            file_path: 文件路径（用于显示）
            analysis_level: 分析级别 (basic, standard, full)

        Returns:
            分析结果
        """
        result = CodeAnalysisResult(file_path=file_path, code=code)

        logger.info(f"Analyzing code: {file_path} (level: {analysis_level})")

        # 基础分析：语法检查
        syntax_result = await self._analyze_syntax(code, file_path)
        result.issues.extend(syntax_result.issues)

        # 标准分析：语义检查
        if analysis_level in ["standard", "full"]:
            semantic_result = await self._analyze_semantics(code, file_path)
            result.issues.extend(semantic_result.issues)

        # 完整分析：度量、安全检查
        if analysis_level == "full":
            # 计算代码度量
            result.metrics = self._calculate_metrics(code)

            # 安全检查
            security_issues = self._check_security_issues(code)
            result.issues.extend(security_issues)

            # AST 信息
            result.ast_info = await self._extract_ast_info(code)

            # 生成建议
            result.suggestions = self._generate_suggestions(result)

        logger.info(
            f"Analysis complete: {result.error_count} errors, "
            f"{result.warning_count} warnings"
        )

        return result

    async def _analyze_syntax(self, code: str, file_path: str) -> CodeAnalysisResult:
        """分析语法"""
        result = CodeAnalysisResult(file_path=file_path, code=code)

        if self.is_lsp_available:
            # 使用 LSP 进行语法检查
            validation = await self.clangd_client.validate_code(code, file_path)

            for error in validation.get("errors", []):
                issue = self._parse_error_to_issue(error, CodeIssueType.SYNTAX_ERROR)
                if issue:
                    result.issues.append(issue)

            for warning in validation.get("warnings", []):
                issue = self._parse_error_to_issue(warning, CodeIssueType.WARNING)
                if issue:
                    result.issues.append(issue)
        else:
            # 使用 clang++ 进行语法检查
            validation = await self.clangd_client._basic_syntax_check(code, file_path)

            for error in validation.get("errors", []):
                issue = self._parse_clang_error_to_issue(error)
                if issue:
                    result.issues.append(issue)

            for warning in validation.get("warnings", []):
                issue = self._parse_clang_error_to_issue(warning)
                if issue:
                    result.issues.append(issue)

        return result

    async def _analyze_semantics(self, code: str, file_path: str) -> CodeAnalysisResult:
        """分析语义"""
        result = CodeAnalysisResult(file_path=file_path, code=code)

        # 检查常见的语义问题

        # 1. 检查未使用的变量
        unused_vars = self._find_unused_variables(code)
        result.issues.extend(unused_vars)

        # 2. 检查可能的空指针解引用
        null_derefs = self._find_potential_null_dereferences(code)
        result.issues.extend(null_derefs)

        # 3. 检查内存泄漏
        memory_leaks = self._find_potential_memory_leaks(code)
        result.issues.extend(memory_leaks)

        return result

    def _calculate_metrics(self, code: str) -> Dict[str, Any]:
        """计算代码度量"""
        lines = code.split("\n")

        # 基本度量
        total_lines = len(lines)
        code_lines = len([l for l in lines if l.strip() and not l.strip().startswith("//")])
        comment_lines = len([l for l in lines if l.strip().startswith("//")])
        blank_lines = len([l for l in lines if not l.strip()])

        # 复杂度度量
        complexity = self._calculate_cyclomatic_complexity(code)

        # 函数统计
        functions = self._extract_functions(code)
        function_count = len(functions)

        # 包含语句
        includes = self._extract_includes(code)

        return {
            "total_lines": total_lines,
            "code_lines": code_lines,
            "comment_lines": comment_lines,
            "blank_lines": blank_lines,
            "cyclomatic_complexity": complexity,
            "function_count": function_count,
            "include_count": len(includes),
            "includes": includes,
            "functions": [f["name"] for f in functions]
        }

    def _check_security_issues(self, code: str) -> List[CodeIssue]:
        """检查安全问题"""
        issues = []

        # 检查不安全的函数
        unsafe_functions = {
            "strcpy": "Use strcpy_s or strncpy instead",
            "strcat": "Use strcat_s or strncat instead",
            "sprintf": "Use snprintf instead",
            "gets": "Use fgets instead",
            "scanf": "Use fgets + sscanf instead",
        }

        for func, suggestion in unsafe_functions.items():
            pattern = rf"\b{func}\s*\("
            matches = re.finditer(pattern, code)

            for match in matches:
                line_num = code[:match.start()].count("\n") + 1
                issues.append(CodeIssue(
                    type=CodeIssueType.SECURITY_ISSUE,
                    severity=1,
                    message=f"Unsafe function '{func}' detected",
                    line=line_num,
                    column=match.start() - code.rfind("\n", 0, match.start()),
                    suggested_fix=suggestion
                ))

        return issues

    async def _extract_ast_info(self, code: str) -> Dict[str, Any]:
        """提取 AST 信息"""
        # 简化的 AST 提取（实际实现可能需要 clang 工具）
        return {
            "classes": self._extract_classes(code),
            "functions": self._extract_functions(code),
            "variables": self._extract_variables(code),
            "includes": self._extract_includes(code)
        }

    def _generate_suggestions(self, result: CodeAnalysisResult) -> List[str]:
        """生成改进建议"""
        suggestions = []

        # 基于度量生成建议
        if result.metrics.get("cyclomatic_complexity", 0) > 10:
            suggestions.append(
                "Consider breaking down complex functions to reduce cyclomatic complexity"
            )

        if result.metrics.get("function_count", 0) > 20:
            suggestions.append(
                "Consider splitting this file into multiple files for better organization"
            )

        if result.metrics.get("comment_lines", 0) < result.metrics.get("code_lines", 1) * 0.1:
            suggestions.append(
                "Consider adding more documentation comments to improve code readability"
            )

        # 基于问题生成建议
        security_issues = [i for i in result.issues if i.type == CodeIssueType.SECURITY_ISSUE]
        if security_issues:
            suggestions.append(
                f"Address {len(security_issues)} security issue(s) to improve code safety"
            )

        return suggestions

    def _find_unused_variables(self, code: str) -> List[CodeIssue]:
        """查找未使用的变量"""
        issues = []
        # 简化实现
        return issues

    def _find_potential_null_dereferences(self, code: str) -> List[CodeIssue]:
        """查找可能的空指针解引用"""
        issues = []

        # 简单的模式匹配
        lines = code.split("\n")
        for i, line in enumerate(lines, 1):
            # 检查类似 if (p) 后面直接使用 p-> 的情况
            if re.search(r'if\s*\(\s*\w+\s*\)\s*{\s*\w+\s*->', line):
                issues.append(CodeIssue(
                    type=CodeIssueType.WARNING,
                    severity=2,
                    message="Potential null pointer dereference - add explicit null check",
                    line=i,
                    column=0
                ))

        return issues

    def _find_potential_memory_leaks(self, code: str) -> List[CodeIssue]:
        """查找可能的内存泄漏"""
        issues = []

        # 检查 malloc/new 没有 free/delete
        malloc_count = len(re.findall(r'\bmalloc\s*\(', code))
        free_count = len(re.findall(r'\bfree\s*\(', code))

        if malloc_count > free_count:
            lines = code.split("\n")
            for i, line in enumerate(lines, 1):
                if "malloc(" in line:
                    issues.append(CodeIssue(
                        type=CodeIssueType.WARNING,
                        severity=2,
                        message="Potential memory leak - malloc without matching free",
                        line=i,
                        column=line.find("malloc"),
                        related_code=line.strip()
                    ))

        return issues

    def _calculate_cyclomatic_complexity(self, code: str) -> int:
        """计算圈复杂度"""
        # 简化的圈复杂度计算
        complexity = 1  # 基础复杂度

        # 计算决策点
        decision_keywords = [
            r'\bif\b', r'\belse\b', r'\bfor\b', r'\bwhile\b',
            r'\bswitch\b', r'\bcase\b', r'\bcatch\b'
        ]

        for keyword in decision_keywords:
            complexity += len(re.findall(keyword, code))

        # 计算逻辑运算符
        complexity += len(re.findall(r'&&|\|\|', code))

        return complexity

    def _extract_functions(self, code: str) -> List[Dict[str, Any]]:
        """提取函数信息"""
        functions = []

        # C++ 函数正则表达式
        pattern = r'(\w+(?:\s*::\s*\w+)*)\s+(\w+)\s*\([^)]*\)\s*(?:const)?\s*{'

        for match in re.finditer(pattern, code):
            return_type = match.group(1)
            func_name = match.group(2)
            start_pos = match.start()

            # 找到函数结束
            brace_count = 0
            in_function = False
            end_pos = start_pos

            for i, char in enumerate(code[start_pos:], start_pos):
                if char == '{':
                    brace_count += 1
                    in_function = True
                elif char == '}':
                    brace_count -= 1
                    if brace_count == 0 and in_function:
                        end_pos = i
                        break

            # 计算行数
            func_code = code[start_pos:end_pos + 1]
            line_count = func_code.count("\n") + 1

            functions.append({
                "name": func_name,
                "return_type": return_type,
                "start_pos": start_pos,
                "end_pos": end_pos,
                "line_count": line_count,
                "complexity": self._calculate_cyclomatic_complexity(func_code)
            })

        return functions

    def _extract_classes(self, code: str) -> List[Dict[str, Any]]:
        """提取类信息"""
        classes = []

        pattern = r'class\s+(\w+)\s*(?::\s*[^{]+)?\s*{'

        for match in re.finditer(pattern, code):
            class_name = match.group(1)
            classes.append({
                "name": class_name,
                "line": code[:match.start()].count("\n") + 1
            })

        return classes

    def _extract_variables(self, code: str) -> List[Dict[str, Any]]:
        """提取变量信息"""
        variables = []

        # 简单的变量声明模式
        pattern = r'(?:const\s+)?(?:\w+(?:\s*::\s*\w+)*)\s+(\w+)\s*(?:=\s*[^;]+)?;'

        for match in re.finditer(pattern, code):
            var_name = match.group(1)
            line_num = code[:match.start()].count("\n") + 1
            variables.append({
                "name": var_name,
                "line": line_num
            })

        return variables

    def _extract_includes(self, code: str) -> List[str]:
        """提取 include 语句"""
        pattern = r'#include\s*[<"]([^>"]+)[>"]'
        return re.findall(pattern, code)

    def _parse_error_to_issue(
        self,
        error: str,
        issue_type: CodeIssueType
    ) -> Optional[CodeIssue]:
        """解析错误字符串为 CodeIssue"""
        try:
            # 尝试解析标准错误格式: file:line:col: error: message
            pattern = r':(\d+):(\d+):\s*(?:error|warning):\s*(.+)'
            match = re.search(pattern, error)

            if match:
                return CodeIssue(
                    type=issue_type,
                    severity=1 if "error" in error.lower() else 2,
                    message=match.group(3),
                    line=int(match.group(1)),
                    column=int(match.group(2)),
                    code=error
                )
        except Exception:
            pass

        # 如果解析失败，创建一个基本的问题对象
        return CodeIssue(
            type=issue_type,
            severity=1,
            message=error,
            line=0,
            column=0
        )

    def _parse_clang_error_to_issue(self, error: str) -> Optional[CodeIssue]:
        """解析 clang 错误输出"""
        # Clang 错误格式: file:line:col: error: message
        pattern = r'(.+):(\d+):(\d+):\s+(error|warning):\s+(.+)'
        match = re.search(pattern, error)

        if match:
            severity_str = match.group(4)
            severity = 1 if severity_str == "error" else 2

            issue_type = CodeIssueType.SYNTAX_ERROR if severity == 1 else CodeIssueType.WARNING

            # 提取相关代码行
            message = match.group(5)

            return CodeIssue(
                type=issue_type,
                severity=severity,
                message=message,
                line=int(match.group(2)),
                column=int(match.group(3)),
                code=error
            )

        return None

    async def get_smart_fixes(
        self,
        code: str,
        issues: List[CodeIssue]
    ) -> List[Dict[str, Any]]:
        """
        获取智能修复建议

        Args:
            code: 原始代码
            issues: 问题列表

        Returns:
            修复建议列表
        """
        fixes = []

        if self.is_lsp_available:
            # 使用 LSP 获取代码操作
            error_messages = [issue.message for issue in issues]
            lsp_fixes = await self.clangd_client.get_fix_suggestions(code, error_messages)
            fixes.extend(lsp_fixes)
        else:
            # 使用内置修复逻辑
            for issue in issues:
                fix = await self._generate_fix_for_issue(code, issue)
                if fix:
                    fixes.append(fix)

        return fixes

    async def _generate_fix_for_issue(
        self,
        code: str,
        issue: CodeIssue
    ) -> Optional[Dict[str, Any]]:
        """为问题生成修复"""
        # 基于问题类型生成修复

        if issue.type == CodeIssueType.SECURITY_ISSUE:
            if "strcpy" in issue.message:
                return {
                    "issue": issue.to_dict(),
                    "fix_type": "replace_function",
                    "description": "Replace unsafe strcpy with strncpy",
                    "replacement": "strncpy(dest, src, sizeof(dest) - 1)",
                    "suggestion": "Use bounded string copy function"
                }

        elif issue.type == CodeIssueType.SYNTAX_ERROR:
            if "expected ';'" in issue.message:
                return {
                    "issue": issue.to_dict(),
                    "fix_type": "insert_text",
                    "description": "Add missing semicolon",
                    "position": {"line": issue.line, "character": issue.column},
                    "text": ";"
                }

        return None

    async def close(self):
        """关闭分析器"""
        if self.clangd_client:
            await self.clangd_client.stop_server()


# 便捷函数
async def analyze_code_with_lsp(
    code: str,
    file_path: str = "checker.cpp",
    analysis_level: str = "full",
    project_root: Optional[Path] = None
) -> CodeAnalysisResult:
    """
    使用 LSP 分析代码

    Args:
        code: 要分析的代码
        file_path: 文件路径
        analysis_level: 分析级别
        project_root: 项目根目录

    Returns:
        分析结果
    """
    analyzer = EnhancedLSPAnalyzer()

    if project_root:
        await analyzer.initialize(project_root)

    result = await analyzer.analyze_code(code, file_path, analysis_level)

    await analyzer.close()

    return result
