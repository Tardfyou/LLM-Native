"""
错误信息格式化
"""

from typing import Any, Dict

from .console_styles import Colors


class ErrorMessageFormatter:
    """错误信息格式化器。"""

    ERROR_PATTERNS = {
        "undefined reference": {
            "cause": "未定义的引用",
            "suggestions": ["检查函数声明与定义是否匹配", "确保链接了所有必要的库", "检查命名空间是否正确"],
        },
        "no member named": {
            "cause": "类型没有该成员",
            "suggestions": ["检查成员名称拼写", "检查类型定义", "可能需要包含额外的头文件"],
        },
        "expected ';'": {
            "cause": "缺少分号",
            "suggestions": ["在声明末尾添加分号"],
        },
        "no matching function": {
            "cause": "没有匹配的函数",
            "suggestions": ["检查函数参数类型", "检查函数重载", "可能需要类型转换"],
        },
        "incomplete type": {
            "cause": "不完整类型",
            "suggestions": ["确保类型已完整定义", "检查头文件包含顺序", "可能需要前向声明"],
        },
        "cannot bind": {
            "cause": "类型绑定错误",
            "suggestions": ["检查 const 正确性", "检查左值/右值引用", "可能需要 std::move"],
        },
    }

    @classmethod
    def format_error(cls, error_message: str, context: Dict[str, Any] = None) -> str:
        lines = [Colors.RED + "❌ 错误" + Colors.RESET, "", Colors.DIM + "原始错误:" + Colors.RESET, f"  {error_message}", ""]

        matched = False
        for key, pattern_info in cls.ERROR_PATTERNS.items():
            if key.lower() in error_message.lower():
                matched = True
                lines.append(Colors.YELLOW + "📝 分析:" + Colors.RESET)
                lines.append(f"  原因: {pattern_info['cause']}")
                lines.append("")
                lines.append(Colors.CYAN + "💡 建议:" + Colors.RESET)
                for index, suggestion in enumerate(pattern_info["suggestions"], start=1):
                    lines.append(f"  {index}. {suggestion}")
                break

        if not matched:
            lines.append(Colors.CYAN + "💡 通用建议:" + Colors.RESET)
            lines.append("  1. 检查代码语法")
            lines.append("  2. 确保所有依赖已正确安装")
            lines.append("  3. 查看完整错误日志")

        if context:
            lines.append("")
            lines.append(Colors.DIM + "📍 上下文:" + Colors.RESET)
            for key, value in context.items():
                if isinstance(value, str) and len(value) > 50:
                    value = value[:50] + "..."
                lines.append(f"  {key}: {value}")
        return "\n".join(lines)

    @classmethod
    def format_compilation_error(cls, compiler_output: str, source_file: str = None) -> str:
        import re

        lines = [Colors.RED + "❌ 编译失败" + Colors.RESET, ""]
        error_pattern = r"(.+?):(\d+):(\d+):\s*(error|warning):\s*(.+)"
        errors = []

        for line in compiler_output.split("\n"):
            match = re.match(error_pattern, line)
            if match:
                errors.append({
                    "file": match.group(1),
                    "line": int(match.group(2)),
                    "column": int(match.group(3)),
                    "severity": match.group(4),
                    "message": match.group(5),
                })

        if errors:
            lines.append(Colors.YELLOW + f"发现 {len(errors)} 个问题:" + Colors.RESET)
            for err in errors[:5]:
                severity_icon = "❌" if err["severity"] == "error" else "⚠️"
                severity_color = Colors.RED if err["severity"] == "error" else Colors.YELLOW
                lines.append(
                    f"  {severity_icon} {err['file']}:{err['line']}:{err['column']}: "
                    + severity_color + err["message"] + Colors.RESET
                )
            if len(errors) > 5:
                lines.append(Colors.DIM + f"  ... 还有 {len(errors) - 5} 个问题" + Colors.RESET)

        lines.append("")
        lines.append(Colors.DIM + "编译器输出 (最后10行):" + Colors.RESET)
        for line in compiler_output.strip().split("\n")[-10:]:
            lines.append(f"  {line}")
        return "\n".join(lines)
