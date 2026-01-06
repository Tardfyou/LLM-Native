"""
Frameworks Module
静态分析框架的抽象层和实现
"""

from .base import Framework, FrameworkConfig
from .codeql import CodeQLFramework
# from .clang import ClangFramework  # 暂时不实现，留待后续扩展

__all__ = ["Framework", "FrameworkConfig", "CodeQLFramework"]
