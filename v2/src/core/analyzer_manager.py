"""
分析器管理器

统一负责：
- 枚举可用分析器
- 暴露分析器目录信息
- 按名称创建分析器实例
"""

from dataclasses import asdict
from typing import Any, Dict, List, Optional

from .analyzer_base import AnalyzerDescriptor, AnalyzerRegistry


class AnalyzerManager:
    """分析器管理器。"""

    def __init__(self, config: Dict[str, Any], llm_client=None):
        self.config = config
        self.llm_client = llm_client

    def list_available_ids(self) -> List[str]:
        """返回当前可用分析器 ID 列表。"""
        ids: List[str] = []
        for descriptor in self.list_descriptors():
            if descriptor.id and descriptor.id not in ids:
                ids.append(descriptor.id)
        return ids

    def list_descriptors(self) -> List[AnalyzerDescriptor]:
        """返回已注册分析器的描述列表。"""
        return AnalyzerRegistry.list_descriptors()

    def get_catalog(self) -> List[Dict[str, Any]]:
        """返回供 LLM/CLI 使用的分析器目录。"""
        return [asdict(descriptor) for descriptor in self.list_descriptors()]

    def create(
        self,
        analyzer_name: str,
        llm_client=None,
        progress_callback=None,
        suppress_output: bool = False,
    ):
        """按名称创建分析器实例。"""
        analyzer = AnalyzerRegistry.create_by_name(
            analyzer_name=analyzer_name,
            config=self.config,
            llm_client=llm_client if llm_client is not None else self.llm_client,
            progress_callback=progress_callback,
            suppress_output=suppress_output,
        )
        if analyzer is None:
            raise ValueError(f"不支持的分析器: {analyzer_name}")
        return analyzer
