"""
Knowledge Base Models
知识库数据模型

定义知识库中使用的数据类，避免循环导入问题
"""

from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class KnowledgeEntry:
    """知识库条目"""
    id: str
    content: str
    title: str
    category: str  # framework_docs, api_examples, cwe_patterns, expert_knowledge
    framework: str  # clang, codeql, general
    language: str  # cpp, java, python, general
    metadata: Dict[str, Any] = field(default_factory=dict)
    embedding: Optional[List[float]] = None
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class SearchResult:
    """搜索结果"""
    entry: KnowledgeEntry
    score: float
    source: str
    matched_terms: List[str] = field(default_factory=list)


@dataclass
class KnowledgeStats:
    """知识库统计信息"""
    total_entries: int = 0
    entries_by_category: Dict[str, int] = field(default_factory=dict)
    entries_by_framework: Dict[str, int] = field(default_factory=dict)
    entries_by_language: Dict[str, int] = field(default_factory=dict)
    last_updated: Optional[str] = None
    vector_db_status: str = "not_initialized"


@dataclass
class DataSourceConfig:
    """数据源配置"""
    name: str
    type: str  # api_docs, code_examples, cwe_patterns, expert_knowledge
    framework: str
    language: str
    source_url: Optional[str] = None
    local_path: Optional[str] = None
    enabled: bool = True
    update_frequency: str = "weekly"  # daily, weekly, monthly
