"""
分析器选择工具 - 智能选择 CSA 或 CodeQL

根据漏洞类型、代码复杂度等因素，智能选择最合适的静态分析工具。
"""

import os
import json
from typing import Dict, Any, List, Optional
from dataclasses import dataclass

from ..agent.tools import Tool, ToolResult
from ..utils.vulnerability_taxonomy import (
    is_arithmetic_vulnerability,
    is_memory_vulnerability,
    is_taint_vulnerability,
    normalize_vulnerability_type,
)
from loguru import logger


@dataclass
class AnalyzerProfile:
    """分析器配置"""
    name: str
    strengths: List[str]
    weaknesses: List[str]
    best_for: List[str]


# 分析器配置
ANALYZER_PROFILES = {
    "csa": AnalyzerProfile(
        name="Clang Static Analyzer",
        strengths=[
            "路径敏感分析",
            "精确的状态追踪",
            "内存漏洞检测",
            "与编译器紧密集成"
        ],
        weaknesses=[
            "跨文件分析困难",
            "可扩展性弱",
            "状态爆炸问题",
            "学习曲线陡峭"
        ],
        best_for=[
            "buffer_overflow",
            "null_dereference",
            "use_after_free",
            "memory_leak",
            "double_free",
            "integer_overflow"
        ]
    ),
    "codeql": AnalyzerProfile(
        name="CodeQL",
        strengths=[
            "全局/跨文件分析",
            "污点追踪",
            "声明式查询",
            "可扩展性好"
        ],
        weaknesses=[
            "非路径敏感",
            "CLI开源规则库闭源",
            "数据库构建耗时",
            "内存消耗大"
        ],
        best_for=[
            "sql_injection",
            "xss",
            "command_injection",
            "path_traversal",
            "taint_tracking",
            "cross_file_analysis"
        ]
    )
}


class AnalyzerSelectorTool(Tool):
    """分析器选择工具"""

    @property
    def name(self) -> str:
        return "select_analyzer"

    @property
    def description(self) -> str:
        return """智能选择静态分析工具。

根据漏洞类型和代码特征，选择最适合的静态分析工具（CSA 或 CodeQL）。

支持:
- 基于漏洞类型的推荐
- 基于代码复杂度的判断
- 返回选择建议和理由"""

    @property
    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "vulnerability_type": {
                    "type": "string",
                    "description": "漏洞类型 (如 buffer_overflow, sql_injection)"
                },
                "patch_content": {
                    "type": "string",
                    "description": "补丁内容（可选，用于分析）"
                },
                "code_complexity": {
                    "type": "string",
                    "enum": ["simple", "medium", "complex"],
                    "description": "代码复杂度"
                }
            },
            "required": ["vulnerability_type"]
        }

    def execute(
        self,
        vulnerability_type: str,
        patch_content: str = None,
        code_complexity: str = "medium"
    ) -> ToolResult:
        """
        执行分析器选择

        Args:
            vulnerability_type: 漏洞类型
            patch_content: 补丁内容
            code_complexity: 代码复杂度

        Returns:
            ToolResult
        """
        try:
            # 分析漏洞类型
            vuln_lower = normalize_vulnerability_type(vulnerability_type, vulnerability_type.lower())

            primary = None
            secondary = None
            reason = []

            if is_memory_vulnerability(vuln_lower) or is_arithmetic_vulnerability(vuln_lower):
                primary = "csa"
                secondary = "codeql"
                reason.append(f"内存相关漏洞 ({vulnerability_type}) 适合 CSA 的路径敏感分析")

            elif is_taint_vulnerability(vuln_lower):
                primary = "codeql"
                secondary = "csa"
                reason.append(f"污点追踪相关漏洞 ({vulnerability_type}) 适合 CodeQL 的全局分析")
            elif vuln_lower in {"race_condition", "toctou"}:
                primary = "codeql"
                secondary = "csa"
                reason.append(f"并发/时序漏洞 ({vulnerability_type}) 先由 CodeQL 做结构化召回，再由 CSA 做路径验证")

            else:
                # 分析补丁内容辅助判断
                if patch_content:
                    patch_lower = patch_content.lower()

                    # 检查内存相关关键字
                    if any(kw in patch_lower for kw in ["malloc", "free", "pointer", "buffer", "null"]):
                        primary = "csa"
                        secondary = "codeql"
                        reason.append("补丁涉及内存操作，推荐 CSA")
                    # 检查污点追踪关键字
                    elif any(kw in patch_lower for kw in ["sql", "query", "exec", "system", "input"]):
                        primary = "codeql"
                        secondary = "csa"
                        reason.append("补丁涉及用户输入/命令执行，推荐 CodeQL")
                    else:
                        primary = "csa"
                        secondary = "codeql"
                        reason.append("无法明确判断，默认推荐 CSA")
                else:
                    primary = "csa"
                    secondary = "codeql"
                    reason.append("未提供足够信息，默认推荐 CSA")

            # 根据复杂度调整
            if code_complexity == "complex" and primary == "csa":
                reason.append("代码复杂度高，CSA 可能遇到状态爆炸问题")
            elif code_complexity == "simple" and primary == "codeql":
                reason.append("代码简单，CodeQL 的全局分析优势不明显")

            # 构建结果
            result = {
                "primary": primary,
                "secondary": secondary,
                "use_both": False,
                "confidence": 0.8 if reason else 0.5,
                "reasons": reason,
                "analyzer_info": {
                    "csa": {
                        "name": ANALYZER_PROFILES["csa"].name,
                        "best_for": ANALYZER_PROFILES["csa"].best_for
                    },
                    "codeql": {
                        "name": ANALYZER_PROFILES["codeql"].name,
                        "best_for": ANALYZER_PROFILES["codeql"].best_for
                    }
                }
            }

            # 生成输出
            output_lines = [
                "📊 分析器选择结果",
                "=" * 40,
                "",
                f"🎯 推荐分析器: {primary.upper()}",
                f"📋 备选分析器: {secondary.upper()}",
                f"🔢 置信度: {result['confidence']:.0%}",
                "",
                "📝 选择理由:",
            ]
            for r in reason:
                output_lines.append(f"  - {r}")

            output_lines.extend([
                "",
                f"💡 {primary.upper()} 优势:",
            ])
            for s in ANALYZER_PROFILES[primary].strengths[:3]:
                output_lines.append(f"  - {s}")

            return ToolResult(
                success=True,
                output="\n".join(output_lines),
                metadata=result
            )

        except Exception as e:
            return ToolResult(
                success=False,
                output="",
                error=f"分析器选择失败: {str(e)}"
            )
