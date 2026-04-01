"""
应用运行时辅助函数
"""

import sys
from pathlib import Path
from typing import Optional

from loguru import logger


def setup_logging(log_level: str = "INFO", log_file: Optional[str] = None, verbose: bool = True):
    """配置日志输出。"""
    logger.remove()

    if verbose:
        logger.add(
            sys.stderr,
            level=log_level,
            format="<green>{time:HH:mm:ss}</green> | <level>{level: <8}</level> | <level>{message}</level>",
            colorize=True,
        )
    else:
        logger.add(
            sys.stderr,
            level="WARNING",
            format="<level>{message}</level>",
            colorize=True,
        )

    if log_file:
        logger.add(
            log_file,
            level="DEBUG",
            format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} - {message}",
            rotation="10 MB",
        )


def print_banner():
    """打印 CLI 横幅。"""
    banner = """
╔══════════════════════════════════════════════════════════════╗
║       LLVM Checker Generator v2.2.0                         ║
║       基于补丁文件的Clang-18检测器自动生成框架                ║
║       支持 CSA (Clang Static Analyzer) 和 CodeQL            ║
╚══════════════════════════════════════════════════════════════╝
"""
    print(banner)


def resolve_config_path(explicit_path: Optional[str], current_file: str) -> Optional[str]:
    """解析配置文件路径。"""
    if explicit_path:
        return explicit_path

    current_path = Path(current_file).resolve()
    possible_paths = [Path.cwd() / "config" / "config.yaml"]
    possible_paths.extend(
        parent / "config" / "config.yaml"
        for parent in current_path.parents
    )
    for path in possible_paths:
        if path.exists():
            return str(path)
    return None
