"""
LLM-Native Static Analysis Framework
面向缺陷检测的大预言模型原生静态分析框架
"""

__version__ = "0.1.0"
__author__ = "Your Name"
__description__ = "An LLM-native framework for automatic static analysis detector generation"

# Import main classes for easy access
from core.config import Config
from core.orchestrator import Orchestrator

__all__ = [
    "Config",
    "Orchestrator",
    "__version__",
    "__author__",
    "__description__"
]
