"""
CLI 组装层
"""

import argparse
from typing import Optional, Sequence

from .handlers import (
    cmd_generate,
    cmd_refine,
    cmd_validate,
    cmd_knowledge,
    cmd_test,
    cmd_mcp,
)
from .runtime import print_banner, setup_logging


CLI_EPILOG = """
示例:
  # 生成CSA检测器
  python main.py generate -p tests/null_ptr.patch -o output/

  # 生成CodeQL查询
  python main.py generate -p tests/sql_injection.patch --analyzer codeql

  # 使用两种分析器
  python main.py generate -p tests/buffer_overflow.patch --analyzer both

  # 智能选择分析器
  python main.py generate -p tests/patch.diff --analyzer auto

  # 生成并验证
  python main.py generate -p tests/patch.diff -v tests/vulnerable.c

  # 基于已有输出执行 detector 精炼
  python main.py refine -i output/ -v tests/project

  # 验证检测器
  python main.py validate --checker output/checker.so --target tests/test.c

  # 导入知识库
  python main.py knowledge import

更多信息请参考: https://github.com/example/checker-generator
"""


def build_parser() -> argparse.ArgumentParser:
    """构建 CLI 参数解析器。"""
    parser = argparse.ArgumentParser(
        description="LLVM Checker Generator v2 - 基于补丁文件的Clang-18检测器自动生成",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=CLI_EPILOG,
    )
    parser.add_argument("--config", "-c", help="配置文件路径")
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="日志级别",
    )
    parser.add_argument("--quiet", "-q", action="store_true", help="安静模式，只显示错误")

    subparsers = parser.add_subparsers(dest="command", help="可用命令")

    gen_parser = subparsers.add_parser("generate", help="生成检测器")
    gen_parser.add_argument("--patch", "-p", required=True, help="补丁文件路径")
    gen_parser.add_argument("--output", "-o", help="输出目录")
    gen_parser.add_argument(
        "--validate-path",
        "-v",
        dest="validate_path",
        help="语义验证路径(文件或目录)，用于测试生成的检测器",
    )
    gen_parser.add_argument(
        "--analyzer",
        "-a",
        default="auto",
        help=(
            "静态分析工具选择：支持 csa/codeql/both/auto，"
            "也支持多分析器组合（如 csa,codeql 或 csa+codeql）。默认: auto"
        ),
    )
    gen_parser.add_argument("--verbose", action="store_true", default=True, help="显示详细输出 (默认: True)")
    gen_parser.add_argument(
        "--no-live",
        action="store_true",
        default=False,
        help="禁用实时表格显示（多分析器模式下使用简单输出）",
    )
    gen_parser.set_defaults(func=cmd_generate)

    refine_parser = subparsers.add_parser("refine", help="基于已有输出执行 detector 精炼")
    refine_parser.add_argument(
        "--input",
        "-i",
        required=True,
        help="generate/refine 阶段的输出目录；优先读取 refinement_input.json，旧目录结构仍兼容",
    )
    refine_parser.add_argument(
        "--validate-path",
        "-v",
        dest="validate_path",
        help="可选，覆盖已有输出中的验证路径(文件或目录)。未提供时优先复用已有输出中的路径",
    )
    refine_parser.add_argument("--patch", "-p", help="可选，显式提供原始补丁路径（用于老输出目录回填）")
    refine_parser.add_argument(
        "--analyzer",
        "-a",
        choices=["csa", "codeql"],
        help=(
            "可选，仅允许指定具体分析器（csa 或 codeql）。"
            "未提供时，默认按输入目录中已有产物分别执行精炼；不支持 both/auto。"
        ),
    )
    refine_parser.add_argument("--verbose", action="store_true", default=True, help="显示详细输出 (默认: True)")
    refine_parser.add_argument(
        "--no-live",
        action="store_true",
        default=False,
        help="禁用实时表格显示（多分析器模式下使用简单输出）",
    )
    refine_parser.set_defaults(func=cmd_refine)

    val_parser = subparsers.add_parser("validate", help="验证检测器")
    val_parser.add_argument("--checker", required=True, help="检测器文件路径 (.so 或 .ql)")
    val_parser.add_argument("--target", required=True, help="目标代码路径")
    val_parser.add_argument("--checker-name", help="检测器名称 (CSA)")
    val_parser.add_argument("--database", help="CodeQL 数据库路径")
    val_parser.add_argument(
        "--analyzer",
        choices=["csa", "codeql", "auto"],
        default="auto",
        help="分析器类型 (默认: auto)",
    )
    val_parser.add_argument("--verbose", action="store_true", default=True, help="显示详细输出")
    val_parser.set_defaults(func=cmd_validate)

    kb_parser = subparsers.add_parser("knowledge", help="知识库操作")
    kb_parser.add_argument("action", choices=["status", "search", "import"], help="操作类型")
    kb_parser.add_argument("--query", "-q", help="搜索查询")
    kb_parser.add_argument("--top-k", type=int, default=3, help="返回结果数量")
    kb_parser.add_argument("--clear", action="store_true", help="导入前清空知识库")
    kb_parser.add_argument("--csa-only", action="store_true", help="仅导入CSA知识")
    kb_parser.add_argument("--codeql-only", action="store_true", help="仅导入CodeQL知识")
    kb_parser.set_defaults(func=cmd_knowledge)

    test_parser = subparsers.add_parser("test", help="运行测试")
    test_parser.add_argument("--test-llm", action="store_true", help="测试LLM连接")
    test_parser.add_argument("--test-kb", action="store_true", help="测试知识库连接")
    test_parser.add_argument("--test-validator", action="store_true", help="测试验证器")
    test_parser.add_argument("--all", action="store_true", help="运行所有测试")
    test_parser.set_defaults(func=cmd_test)

    mcp_parser = subparsers.add_parser("mcp", help="MCP标准化工具接口")
    mcp_parser.add_argument("action", choices=["list-tools", "call", "export-manifest"], help="操作类型")
    mcp_parser.add_argument("--tool", help="工具名称（action=call时必填）")
    mcp_parser.add_argument("--args-json", help="工具参数JSON字符串（action=call时可选）")
    mcp_parser.add_argument("--output", "-o", help="输出文件路径（action=export-manifest时可选）")
    mcp_parser.set_defaults(func=cmd_mcp)

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    """CLI 主入口。"""
    parser = build_parser()
    args = parser.parse_args(argv)

    setup_logging(args.log_level, verbose=not getattr(args, "quiet", False))

    if hasattr(args, "func"):
        return args.func(args)

    print_banner()
    parser.print_help()
    return 0
