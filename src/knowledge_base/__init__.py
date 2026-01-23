"""
Knowledge Base System for LLM-Native Static Analysis Framework
知识库系统 - 面向缺陷检测的大预言模型原生静态分析框架
"""

# 导入不依赖外部库的模块
from .models import KnowledgeEntry, SearchResult, KnowledgeStats, DataSourceConfig

# 主要管理器需要外部依赖，延迟导入
def get_knowledge_base_manager():
    """获取知识库管理器（延迟导入）"""
    from .manager import KnowledgeBaseManager
    return KnowledgeBaseManager

__all__ = [
    # 数据模型
    'KnowledgeEntry',
    'SearchResult',
    'KnowledgeStats',
    'DataSourceConfig',

    # 工厂函数
    'get_knowledge_base_manager',
]
