"""
Knowledge Base System for LLM-Native Static Analysis Framework
知识库系统 - 面向缺陷检测的大预言模型原生静态分析框架
"""

from .manager import KnowledgeBaseManager

# 暂时只导入实际存在的模块，避免导入错误
# TODO: 实现完整的知识库系统模块

__all__ = [
    # 主要管理器
    'KnowledgeBaseManager',
]
