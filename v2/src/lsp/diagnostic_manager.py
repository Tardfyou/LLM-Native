"""
诊断管理器 - 处理LSP诊断

提供:
- 代码诊断
- 快速语法预检
- 诊断格式化
- 错误统计
"""

import asyncio
import re
import os
import subprocess
import tempfile
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass
from pathlib import Path

from loguru import logger

from .async_clangd_client import AsyncClangdClient, Diagnostic


@dataclass
class DiagnosticSummary:
    """诊断摘要"""
    total: int
    errors: int
    warnings: int
    infos: int
    hints: int

    def has_errors(self) -> bool:
        return self.errors > 0

    def to_dict(self) -> Dict[str, int]:
        return {
            "total": self.total,
            "errors": self.errors,
            "warnings": self.warnings,
            "infos": self.infos,
            "hints": self.hints
        }


class DiagnosticManager:
    """诊断管理器"""

    def __init__(self, client: AsyncClangdClient):
        """
        初始化

        Args:
            client: 异步Clangd客户端
        """
        self.client = client
        self._diagnostics_cache: Dict[str, List[Diagnostic]] = {}
        self.enable_compiler_compat_check = True
        self._work_dir: Optional[str] = None

    def set_work_dir(self, work_dir: str):
        """设置工作目录，尽量将 LSP 临时文件约束到该目录下。"""
        self._work_dir = work_dir
        if hasattr(self.client, "set_work_dir"):
            self.client.set_work_dir(work_dir)

    async def warmup(self, timeout_seconds: float = 8.0) -> bool:
        """
        预热 LSP/编译器检查链路。

        作用：
        - 提前拉起 clangd，避免首次 lsp_validate 时额外等待。
        - 提前触发一次最小检查，建立基础缓存。
        """
        try:
            tiny_code = "int __lsp_warmup_fn() { return 0; }\n"

            # 先确保客户端可用
            if not self.client.is_available():
                await asyncio.wait_for(self.client.initialize(), timeout=timeout_seconds)

            # 触发一次轻量检查（超时可容忍）
            try:
                await asyncio.wait_for(
                    self.check_code(tiny_code, "__lsp_warmup__.cpp", use_cache=False),
                    timeout=timeout_seconds,
                )
            except asyncio.TimeoutError:
                logger.warning("LSP预热检查超时，但不影响后续流程")

            return True
        except Exception as e:
            logger.warning(f"LSP预热失败: {e}")
            return False

    async def check_code(
        self,
        code: str,
        file_name: str = "checker.cpp",
        use_cache: bool = False
    ) -> List[Diagnostic]:
        """
        检查代码

        Args:
            code: 代码内容
            file_name: 文件名
            use_cache: 是否使用缓存

        Returns:
            诊断列表
        """
        # 检查缓存
        cache_key = f"{file_name}:{hash(code)}"
        if use_cache and cache_key in self._diagnostics_cache:
            return self._diagnostics_cache[cache_key]

        # 确保客户端初始化
        if not self.client.is_available():
            await self.client.initialize()

        # 执行检查
        diagnostics = await self.client.check_code(code, file_name)

        # 缓存结果
        if use_cache:
            self._diagnostics_cache[cache_key] = diagnostics

        return diagnostics

    async def check_file(self, file_path: str) -> List[Diagnostic]:
        """
        检查文件

        Args:
            file_path: 文件路径

        Returns:
            诊断列表
        """
        path = Path(file_path)
        if not path.exists():
            logger.error(f"文件不存在: {file_path}")
            return []

        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        return await self.check_code(content, path.name)

    async def quick_syntax_check(self, code: str) -> Tuple[bool, List[str]]:
        """
        快速语法预检

        Args:
            code: 代码内容

        Returns:
            (has_errors, error_messages)
        """
        # 快速模式优先使用 clang++ -fsyntax-only，速度快且与编译器结果更一致
        diagnostics = await self.compiler_compatible_check(code, "quick_check.cpp")

        # 只关注错误
        errors = [d for d in diagnostics if d.severity == "error"]
        error_messages = [f"Line {d.line}: {d.message}" for d in errors]

        return len(errors) == 0, error_messages

    async def full_check(
        self,
        code: str,
        file_name: str = "checker.cpp"
    ) -> Tuple[bool, DiagnosticSummary, List[Diagnostic]]:
        """
        完整检查

        Args:
            code: 代码内容
            file_name: 文件名

        Returns:
            (success, summary, diagnostics)
        """
        # full 模式合并两路结果：
        # 1) clangd 诊断（更偏编辑器语义）
        # 2) clang++ 语法诊断（与真实编译更一致）
        diagnostics = []

        lsp_diagnostics = await self.check_code(code, file_name)
        diagnostics.extend(lsp_diagnostics)

        if self.enable_compiler_compat_check:
            compiler_diagnostics = await self.compiler_compatible_check(code, file_name)
            diagnostics.extend(compiler_diagnostics)

        # 去重（按 位置+严重度+消息）
        dedup = {}
        for d in diagnostics:
            key = (d.line, d.column, d.severity, d.message)
            if key not in dedup:
                dedup[key] = d
        diagnostics = list(dedup.values())

        summary = self.get_error_summary(diagnostics)

        return not summary.has_errors(), summary, diagnostics

    async def compiler_compatible_check(
        self,
        code: str,
        file_name: str = "checker.cpp"
    ) -> List[Diagnostic]:
        """
        使用 clang++ -fsyntax-only 做编译器兼容检查。
        目标：尽量与 compile_checker 的报错保持一致，同时避免链接开销。
        """
        return await asyncio.to_thread(self._compiler_compatible_check_sync, code, file_name)

    def _compiler_compatible_check_sync(self, code: str, file_name: str) -> List[Diagnostic]:
        diagnostics: List[Diagnostic] = []

        llvm_dir = getattr(self.client, "llvm_dir", "/usr/lib/llvm-18")
        clangpp_path = os.path.join(llvm_dir, "bin", "clang++")

        # 兜底路径
        if not os.path.exists(clangpp_path):
            clangpp_path = "/usr/lib/llvm-18/bin/clang++"

        temp_parent = None
        if self._work_dir:
            temp_parent = os.path.join(self._work_dir, ".lsp_tmp")
            os.makedirs(temp_parent, exist_ok=True)

        with tempfile.TemporaryDirectory(prefix="lsp_fast_syntax_", dir=temp_parent) as tmpdir:
            source_path = os.path.join(tmpdir, file_name)
            with open(source_path, "w", encoding="utf-8") as f:
                f.write(code)

            cmd = [
                clangpp_path,
                "-fsyntax-only",
                "-std=c++20",
                f"-I{llvm_dir}/include",
                f"-I{llvm_dir}/include/clang",
                f"-I{llvm_dir}/include/clang/StaticAnalyzer",
                f"-I{llvm_dir}/include/clang/StaticAnalyzer/Core",
                f"-I{llvm_dir}/include/clang/StaticAnalyzer/Frontend",
                f"-I{llvm_dir}/include/llvm",
                source_path,
            ]

            try:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=20,
                )
                output = (proc.stderr or "") + "\n" + (proc.stdout or "")
                diagnostics.extend(self._parse_compiler_output(output, source_path))
            except subprocess.TimeoutExpired:
                diagnostics.append(
                    Diagnostic(
                        file_path=file_name,
                        line=1,
                        column=1,
                        severity="warning",
                        message="clang++ 语法检查超时",
                        source="clang++",
                    )
                )
            except Exception as e:
                diagnostics.append(
                    Diagnostic(
                        file_path=file_name,
                        line=1,
                        column=1,
                        severity="warning",
                        message=f"clang++ 语法检查异常: {e}",
                        source="clang++",
                    )
                )

        return diagnostics

    def _parse_compiler_output(self, output: str, source_path: str) -> List[Diagnostic]:
        """解析 clang/clang++ 输出为 Diagnostic 列表。"""
        diagnostics: List[Diagnostic] = []

        # 格式: /path/file.cpp:62:44: error: xxx
        pattern = re.compile(rf"^{re.escape(source_path)}:(\d+):(\d+):\s+(error|warning|note):\s+(.*)$")

        for line in (output or "").splitlines():
            m = pattern.match(line.strip())
            if not m:
                continue

            row = int(m.group(1))
            col = int(m.group(2))
            sev_raw = m.group(3)
            msg = m.group(4).strip()

            # note 不作为阻塞项
            severity = "info" if sev_raw == "note" else sev_raw

            diagnostics.append(
                Diagnostic(
                    file_path=os.path.basename(source_path),
                    line=row,
                    column=col,
                    severity=severity,
                    message=msg,
                    source="clang++",
                )
            )

        return diagnostics

    def format_diagnostics(
        self,
        diagnostics: List[Diagnostic],
        max_length: int = 2000
    ) -> str:
        """
        格式化诊断信息

        Args:
            diagnostics: 诊断列表
            max_length: 最大长度

        Returns:
            格式化的文本
        """
        if not diagnostics:
            return "✅ 没有发现错误或警告"

        # 按严重程度分组
        by_severity = {
            "error": [],
            "warning": [],
            "info": [],
            "hint": []
        }

        for d in diagnostics:
            by_severity.get(d.severity, by_severity["info"]).append(d)

        parts = []

        # 错误
        if by_severity["error"]:
            parts.append(f"❌ 错误 ({len(by_severity['error'])}个):")
            for d in by_severity["error"][:10]:  # 最多显示10个
                parts.append(f"  Line {d.line}:{d.column}: {d.message}")

        # 警告
        if by_severity["warning"]:
            parts.append(f"⚠️ 警告 ({len(by_severity['warning'])}个):")
            for d in by_severity["warning"][:5]:  # 最多显示5个
                parts.append(f"  Line {d.line}:{d.column}: {d.message}")

        # 信息
        if by_severity["info"]:
            parts.append(f"ℹ️ 信息 ({len(by_severity['info'])}个)")

        result = "\n".join(parts)

        # 截断
        if len(result) > max_length:
            result = result[:max_length] + "\n... (输出已截断)"

        return result

    def get_error_summary(self, diagnostics: List[Diagnostic]) -> DiagnosticSummary:
        """
        获取错误摘要

        Args:
            diagnostics: 诊断列表

        Returns:
            DiagnosticSummary
        """
        counts = {"error": 0, "warning": 0, "info": 0, "hint": 0}

        for d in diagnostics:
            if d.severity in counts:
                counts[d.severity] += 1

        return DiagnosticSummary(
            total=len(diagnostics),
            errors=counts["error"],
            warnings=counts["warning"],
            infos=counts["info"],
            hints=counts["hint"]
        )

    def filter_diagnostics(
        self,
        diagnostics: List[Diagnostic],
        min_severity: str = "warning"
    ) -> List[Diagnostic]:
        """
        过滤诊断

        Args:
            diagnostics: 诊断列表
            min_severity: 最低严重程度

        Returns:
            过滤后的诊断列表
        """
        severity_order = {"error": 0, "warning": 1, "info": 2, "hint": 3}
        min_level = severity_order.get(min_severity, 1)

        return [
            d for d in diagnostics
            if severity_order.get(d.severity, 3) <= min_level
        ]

    def get_fix_suggestions(self, diagnostics: List[Diagnostic]) -> List[Dict[str, Any]]:
        """
        获取修复建议

        Args:
            diagnostics: 诊断列表

        Returns:
            修复建议列表
        """
        suggestions = []

        for d in diagnostics:
            suggestion = {
                "line": d.line,
                "column": d.column,
                "message": d.message,
                "severity": d.severity,
                "possible_fix": self._suggest_fix(d)
            }
            suggestions.append(suggestion)

        return suggestions

    def _suggest_fix(self, diagnostic: Diagnostic) -> str:
        """
        根据诊断信息生成修复建议

        Args:
            diagnostic: 诊断信息

        Returns:
            修复建议
        """
        msg = diagnostic.message.lower()

        # 常见错误模式
        if "undeclared" in msg:
            return "检查是否缺少头文件包含或变量声明"

        if "no member named" in msg:
            return "检查成员名称是否正确，或是否使用了正确的类型"

        if "cannot initialize" in msg:
            return "检查类型是否匹配，可能需要类型转换"

        if "expected" in msg:
            return "检查语法是否正确，可能缺少分号或括号"

        if "too few arguments" in msg:
            return "检查函数调用参数数量是否正确"

        if "too many arguments" in msg:
            return "检查函数调用参数数量是否超过定义"

        if "no matching function" in msg:
            return "检查函数签名是否匹配，可能需要包含正确的头文件"

        if "redefinition" in msg:
            return "检查是否有重复定义"

        if "use of undeclared identifier" in msg:
            match = re.search(r"'(\w+)'", diagnostic.message)
            if match:
                return f"标识符 '{match.group(1)}' 未声明，检查拼写或添加声明"
            return "标识符未声明"

        if "no type named" in msg:
            return "检查类型定义或命名空间"

        if "is private" in msg:
            return "成员是私有的，检查访问权限"

        if "no viable conversion" in msg:
            return "类型不兼容，检查是否需要显式转换"

        return "请根据错误信息检查代码"

    def clear_cache(self):
        """清除缓存"""
        self._diagnostics_cache.clear()


# 全局诊断管理器实例
_diagnostic_manager: Optional[DiagnosticManager] = None


def get_diagnostic_manager(client: Optional[AsyncClangdClient] = None) -> DiagnosticManager:
    """获取诊断管理器实例"""
    global _diagnostic_manager

    if _diagnostic_manager is None:
        if client is None:
            raise ValueError("首次调用需要提供AsyncClangdClient")
        _diagnostic_manager = DiagnosticManager(client)

    return _diagnostic_manager
