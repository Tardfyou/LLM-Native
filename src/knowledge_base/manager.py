"""
Knowledge Base Manager
知识库管理器 - 负责知识库的搜索和管理
"""

from typing import Dict, Any, List, Optional
from dataclasses import dataclass
import logging

# 使用标准logging而不是loguru，以避免依赖问题
logger = logging.getLogger(__name__)


@dataclass
class SearchResult:
    """搜索结果"""
    content: str
    score: float
    metadata: Dict[str, Any]
    source: str


class KnowledgeBaseManager:
    """知识库管理器"""

    def __init__(self, config):
        """
        初始化知识库管理器

        Args:
            config: 配置对象
        """
        self.config = config
        logger.info("KnowledgeBaseManager initialized with mock implementation")

    def search(self, query: str, top_k: int = 5, filters: Optional[Dict[str, Any]] = None) -> List[SearchResult]:
        """
        搜索知识库

        Args:
            query: 搜索查询
            top_k: 返回结果数量
            filters: 过滤条件

        Returns:
            搜索结果列表
        """
        logger.info(f"Mock search called with query: {query}, top_k: {top_k}, filters: {filters}")

        # 返回模拟的搜索结果
        return [
            SearchResult(
                content=f"Mock knowledge result for query: {query}",
                score=0.95,
                metadata={"type": "mock", "framework": filters.get("framework", "unknown") if filters else "unknown"},
                source="mock_knowledge_base"
            )
        ]

    def is_available(self) -> bool:
        """
        检查知识库是否可用

        Returns:
            是否可用
        """
        return True

    def get_stats(self) -> Dict[str, Any]:
        """
        获取知识库统计信息

        Returns:
            统计信息
        """
        return {
            "total_entries": 1000,
            "frameworks": ["clang", "codeql"],
            "last_updated": "2024-01-01",
            "status": "mock"
        }
