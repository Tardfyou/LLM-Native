"""
Knowledge Base Manager
知识库管理器 - 负责知识库的构建、搜索和管理
支持多种数据源和混合检索

支持环境感知：
- 容器内运行：使用 /app 路径前缀
- 宿主机运行：自动检测项目根目录
"""

import os
from typing import Dict, Any, List, Optional, Union, Tuple
from dataclasses import dataclass, field
from pathlib import Path
import json
import logging
from datetime import datetime
import hashlib

import logging
logger = logging.getLogger(__name__)

# Import shared models
from .models import KnowledgeEntry, SearchResult, KnowledgeStats

# Import related modules (延迟导入以避免循环依赖)
# from .vector_db import VectorDatabase
# from .data_sources import DataSourceProcessor


def _get_project_root() -> Path:
    """
    获取项目根目录（支持容器和宿主机环境）

    Returns:
        Path: 项目根目录
    """
    # 检查环境变量
    env_root = os.environ.get("LLM_NATIVE_ROOT")
    if env_root:
        return Path(env_root)

    # 检查是否在容器内
    if Path("/app/config/config.yaml").exists():
        return Path("/app")

    # 从当前文件位置向上查找项目根
    current = Path(__file__).resolve()
    for parent in current.parents:
        if (parent / "config" / "config.yaml").exists():
            return parent
        if (parent / "LLM-Native" / "config" / "config.yaml").exists():
            return parent / "LLM-Native"

    # 回退到默认位置
    return current.parent.parent.parent


class KnowledgeBaseManager:
    """
    知识库管理器

    支持多种数据源：
    1. 框架API文档 (Clang/LLVM, CodeQL)
    2. 代码示例和查询模板
    3. CWE漏洞模式描述
    4. 专家知识和最佳实践

    环境感知：
    - 自动检测运行环境（容器/宿主机）
    - 自动适配路径配置
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        初始化知识库管理器

        Args:
            config: 配置字典
        """
        self.config = config or {}

        # 环境感知的路径配置
        project_root = _get_project_root()

        # 优先使用配置中的路径，否则使用环境感知的默认路径
        config_paths = self.config.get('paths', {})

        # 处理配置中的路径（替换环境变量）
        def resolve_path(config_path: str, default: str) -> Path:
            if config_path:
                # 替换环境变量占位符
                path = config_path.replace('${LLM_NATIVE_ROOT:-/app}', str(project_root))
                path = path.replace('${LLM_NATIVE_ROOT}', str(project_root))
                return Path(path)
            return project_root / default

        self.knowledge_dir = resolve_path(
            config_paths.get('knowledge_dir'),
            'data/knowledge'
        )
        self.knowledge_dir.mkdir(parents=True, exist_ok=True)

        # 初始化向量数据库
        self.vector_db = None

        # 知识库文件路径
        self.entries_file = self.knowledge_dir / "knowledge_entries.json"
        self.metadata_file = self.knowledge_dir / "metadata.json"

        # 加载现有知识库
        self.entries: Dict[str, KnowledgeEntry] = {}
        self._load_knowledge_base()

        # 初始化向量数据库
        self._init_vector_db()

        # 检查向量数据库状态
        if not hasattr(self, 'vector_db') or self.vector_db is None or not self.vector_db.embedding_models:
            logger.warning("Vector database not available - knowledge base will work in file-only mode")
            logger.warning("To enable vector search, install compatible sentence-transformer models")
        else:
            logger.info("Vector database ready for hybrid search")

        logger.info(f"KnowledgeBaseManager initialized with {len(self.entries)} entries (root={project_root})")

    def _init_vector_db(self):
        """初始化向量数据库"""
        try:
            # 延迟导入以避免循环依赖
            from .vector_db import VectorDatabase

            self.vector_db = VectorDatabase(self.config)
            if self.vector_db.initialize():
                logger.info("Vector database initialized successfully")
                # 初始化嵌入模型
                if self.vector_db.initialize_embedding_model():
                    logger.info("Embedding model initialized successfully")
                else:
                    logger.warning("Failed to initialize embedding model - operating in file-only mode")
                    logger.warning("To fix: Download sentence-transformer compatible models")
            else:
                logger.warning("Failed to initialize vector database - operating in file-only mode")
                self.vector_db = None
        except Exception as e:
            logger.error(f"Error initializing vector database: {e}")
            self.vector_db = None

    def _load_knowledge_base(self):
        """加载现有知识库"""
        try:
            if self.entries_file.exists():
                with open(self.entries_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    for entry_data in data.get('entries', []):
                        entry = KnowledgeEntry(**entry_data)
                        self.entries[entry.id] = entry
                logger.info(f"Loaded {len(self.entries)} knowledge entries")
        except Exception as e:
            logger.warning(f"Failed to load knowledge base: {e}")

    def _save_knowledge_base(self):
        """保存知识库到文件"""
        try:
            data = {
                'entries': [entry.__dict__ for entry in self.entries.values()],
                'last_updated': datetime.now().isoformat()
            }
            with open(self.entries_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            logger.info(f"Saved {len(self.entries)} knowledge entries")
        except Exception as e:
            logger.error(f"Failed to save knowledge base: {e}")

    def add_entry(self, entry: KnowledgeEntry) -> bool:
        """
        添加知识条目

        Args:
            entry: 知识条目

        Returns:
            是否成功
        """
        try:
            # 生成唯一ID（如果没有提供）
            if not entry.id:
                content_hash = hashlib.md5(entry.content.encode()).hexdigest()[:8]
                entry.id = f"{entry.category}_{entry.framework}_{content_hash}"

            # 检查是否已存在
            if entry.id in self.entries:
                logger.warning(f"Entry {entry.id} already exists, updating")
                entry.updated_at = datetime.now().isoformat()
            else:
                entry.created_at = datetime.now().isoformat()

            self.entries[entry.id] = entry
            self._save_knowledge_base()

            # 添加到向量数据库
            if self.vector_db:
                self.vector_db.add_entries([entry])

            logger.info(f"Added knowledge entry: {entry.title} ({entry.id})")
            return True

        except Exception as e:
            logger.error(f"Failed to add entry: {e}")
            return False

    def bulk_add_entries(self, entries: List[KnowledgeEntry]) -> Dict[str, int]:
        """
        批量添加知识条目

        Args:
            entries: 知识条目列表

        Returns:
            包含成功和失败计数的字典
        """
        success_count = 0
        failed_count = 0

        try:
            # 处理每个条目
            for entry in entries:
                try:
                    # 生成唯一ID（如果没有提供）
                    if not entry.id:
                        content_hash = hashlib.md5(entry.content.encode()).hexdigest()[:8]
                        entry.id = f"{entry.category}_{entry.framework}_{content_hash}"

                    # 检查是否已存在
                    if entry.id in self.entries:
                        logger.warning(f"Entry {entry.id} already exists, updating")
                        entry.updated_at = datetime.now().isoformat()
                    else:
                        entry.created_at = datetime.now().isoformat()

                    self.entries[entry.id] = entry
                    success_count += 1

                except Exception as e:
                    logger.error(f"Failed to process entry: {e}")
                    failed_count += 1
                    continue

            # 保存到文件
            if success_count > 0:
                self._save_knowledge_base()

            # 批量添加到向量数据库
            if self.vector_db and success_count > 0:
                # 过滤出成功处理的条目
                successful_entries = [entry for entry in entries if entry.id in self.entries]
                self.vector_db.add_entries(successful_entries)

            logger.info(f"Bulk added {success_count} entries, failed {failed_count}")
            return {
                'success': success_count,
                'failed': failed_count
            }

        except Exception as e:
            logger.error(f"Failed to bulk add entries: {e}")
            return {
                'success': success_count,
                'failed': len(entries) - success_count
            }

    def search(self,
               query: str,
               top_k: int = 5,
               filters: Optional[Dict[str, Any]] = None,
               search_mode: str = "advanced",
               include_metadata: bool = True) -> List[SearchResult]:
        """
        高级知识库搜索

        支持多种搜索模式：
        - "vector": 纯向量检索
        - "hybrid": 混合检索（推荐）
        - "advanced": 高级检索（向量+重排序）
        - "text": 纯文本关键词检索

        Args:
            query: 搜索查询
            top_k: 返回结果数量
            filters: 过滤条件 (category, framework, language, tags等)
            search_mode: 搜索模式
            include_metadata: 是否包含元数据信息

        Returns:
            搜索结果列表
        """
        try:
            # 预处理查询和过滤条件
            processed_query = self._preprocess_query(query)
            enhanced_filters = self._enhance_filters(filters, processed_query)

            results = []

            if search_mode == "vector" and self.vector_db:
                # 纯向量检索
                vector_results = self.vector_db._dense_search(processed_query, top_k, enhanced_filters)
                results.extend([result for result, _ in vector_results])

            elif search_mode == "hybrid" and self.vector_db:
                # 混合检索（稠密+稀疏）
                hybrid_results = self.vector_db.search(
                    processed_query,
                    top_k=top_k,
                    filters=enhanced_filters,
                    use_hybrid=True,
                    use_reranking=False
                )
                results.extend(hybrid_results)

            elif search_mode == "advanced" and self.vector_db:
                # 高级检索（完整流程）
                advanced_results = self.vector_db.search(
                    processed_query,
                    top_k=top_k,
                    filters=enhanced_filters,
                    use_hybrid=True,
                    use_reranking=True
                )
                results.extend(advanced_results)

            else:
                # 回退到文本搜索
                candidates = self._apply_filters(enhanced_filters)
                if candidates:
                    text_results = self._text_search(processed_query, candidates, top_k)
                    results.extend(text_results)

            # 后处理结果
            if include_metadata:
                results = self._enrich_results_with_metadata(results, processed_query)

            logger.info(f"Knowledge search mode='{search_mode}' for '{query}' returned {len(results)} results")
            return results

        except Exception as e:
            logger.error(f"Search failed: {e}")
            return []

    async def search_async(self,
                          query: str,
                          top_k: int = 5,
                          filters: Optional[Dict[str, Any]] = None,
                          search_mode: str = "advanced",
                          include_metadata: bool = True) -> List[SearchResult]:
        """
        异步高级知识库搜索

        异步版本的search方法，支持在异步上下文中使用。

        Args:
            query: 搜索查询
            top_k: 返回结果数量
            filters: 过滤条件
            search_mode: 搜索模式
            include_metadata: 是否包含元数据信息

        Returns:
            搜索结果列表
        """
        import asyncio

        # 在线程池中运行同步搜索方法
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            lambda: self.search(query, top_k, filters, search_mode, include_metadata)
        )

    def _preprocess_query(self, query: str) -> str:
        """
        预处理查询字符串

        - 清理特殊字符
        - 提取关键词
        - 规范化格式

        Args:
            query: 原始查询

        Returns:
            处理后的查询
        """
        import re

        # 清理特殊字符
        query = re.sub(r'[^\w\s\u4e00-\u9fff]', ' ', query)

        # 规范化空格
        query = ' '.join(query.split())

        return query.strip()

    def _enhance_filters(self, filters: Optional[Dict[str, Any]], query: str) -> Optional[Dict[str, Any]]:
        """
        增强过滤条件

        基于查询内容智能推断过滤条件：
        - 检测语言特征
        - 识别框架关键词
        - 推断内容类型

        Args:
            filters: 原始过滤条件
            query: 处理后的查询

        Returns:
            增强的过滤条件
        """
        enhanced = filters.copy() if filters else {}

        # 检测语言特征
        if 'language' not in enhanced:
            if any(keyword in query.lower() for keyword in ['clang', 'llvm', 'checker', 'c++', 'cpp']):
                enhanced['language'] = 'cpp'
            elif any(keyword in query.lower() for keyword in ['codeql', 'ql', 'query']):
                enhanced['language'] = 'ql'
            elif any(keyword in query.lower() for keyword in ['java', 'jvm']):
                enhanced['language'] = 'java'

        # 检测框架特征
        if 'framework' not in enhanced:
            if 'clang' in query.lower() or 'llvm' in query.lower():
                enhanced['framework'] = 'clang'
            elif 'codeql' in query.lower():
                enhanced['framework'] = 'codeql'

        # 检测内容类型
        if 'category' not in enhanced:
            if any(keyword in query.lower() for keyword in ['api', 'function', 'method', 'class']):
                enhanced['category'] = 'framework_api'
            elif any(keyword in query.lower() for keyword in ['example', 'sample', 'checker']):
                enhanced['category'] = 'code_examples'
            elif any(keyword in query.lower() for keyword in ['cwe', 'vulnerability', 'bug', 'exploit']):
                enhanced['category'] = 'cwe_patterns'

        return enhanced if enhanced else None

    def _enrich_results_with_metadata(self, results: List[SearchResult], query: str) -> List[SearchResult]:
        """
        为搜索结果添加额外的元数据信息

        Args:
            results: 搜索结果列表
            query: 原始查询

        Returns:
            增强的搜索结果
        """
        for result in results:
            # 添加查询相关性信息
            result.query_relevance = self._calculate_query_relevance(query, result)

            # 添加使用建议
            result.usage_suggestion = self._generate_usage_suggestion(result.entry)

        return results

    def _calculate_query_relevance(self, query: str, result: SearchResult) -> Dict[str, Any]:
        """
        计算查询与结果的相关性指标

        Args:
            query: 查询字符串
            result: 搜索结果

        Returns:
            相关性指标字典
        """
        query_terms = set(query.lower().split())
        content_lower = result.entry.content.lower()

        # 计算关键词匹配率
        matched_terms = [term for term in query_terms if term in content_lower]
        match_ratio = len(matched_terms) / len(query_terms) if query_terms else 0

        # 计算内容类型匹配度
        type_match_score = 0
        if 'api' in query.lower() and result.entry.category == 'framework_api':
            type_match_score = 0.8
        elif 'example' in query.lower() and result.entry.category == 'code_examples':
            type_match_score = 0.8
        elif 'cwe' in query.lower() and result.entry.category == 'cwe_patterns':
            type_match_score = 0.8

        return {
            'keyword_match_ratio': match_ratio,
            'matched_keywords': matched_terms,
            'type_match_score': type_match_score,
            'overall_relevance': (match_ratio + type_match_score) / 2
        }

    def _generate_usage_suggestion(self, entry: KnowledgeEntry) -> str:
        """
        根据条目类型生成使用建议

        Args:
            entry: 知识条目

        Returns:
            使用建议文本
        """
        if entry.category == 'framework_api':
            return f"此API可用于{entry.framework}框架的{entry.language}开发中"
        elif entry.category == 'code_examples':
            return f"此示例展示了如何在{entry.framework}中实现类似功能"
        elif entry.category == 'cwe_patterns':
            return f"此模式描述了{entry.title}的安全漏洞检测方法"
        elif entry.category == 'expert_knowledge':
            return f"此最佳实践可帮助优化{entry.framework}的使用"
        else:
            return "此条目包含相关技术信息"

    def _apply_filters(self, filters: Optional[Dict[str, Any]]) -> List[KnowledgeEntry]:
        """应用过滤条件"""
        candidates = list(self.entries.values())

        if not filters:
            return candidates

        filtered = []
        for entry in candidates:
            match = True

            if 'category' in filters and entry.category != filters['category']:
                match = False
            if 'framework' in filters and entry.framework != filters['framework']:
                match = False
            if 'language' in filters and entry.language != filters['language']:
                match = False
            if 'tags' in filters and not any(tag in entry.metadata.get('tags', []) for tag in filters['tags']):
                match = False

            if match:
                filtered.append(entry)

        return filtered


    def _text_search(self, query: str, candidates: List[KnowledgeEntry], top_k: int) -> List[SearchResult]:
        """基于文本的关键词搜索"""
        results = []
        query_lower = query.lower()

        for entry in candidates:
            # 简单的关键词匹配
            title_match = query_lower in entry.title.lower()
            content_match = query_lower in entry.content.lower()

            if title_match or content_match:
                # 计算简单相关性分数
                score = 0.8 if title_match else 0.6
                matched_terms = [term for term in query_lower.split() if term in entry.content.lower()]

                results.append(SearchResult(
                    entry=entry,
                    score=score,
                    source="text_search",
                    matched_terms=matched_terms
                ))

        return sorted(results, key=lambda x: x.score, reverse=True)[:top_k]

    def _rank_and_deduplicate(self, results: List[SearchResult], top_k: int) -> List[SearchResult]:
        """排序和去重"""
        seen_ids = set()
        unique_results = []

        for result in sorted(results, key=lambda x: x.score, reverse=True):
            if result.entry.id not in seen_ids:
                unique_results.append(result)
                seen_ids.add(result.entry.id)
                if len(unique_results) >= top_k:
                    break

        return unique_results


    def initialize_vector_db(self) -> bool:
        """
        初始化ChromaDB向量数据库

        Returns:
            是否成功
        """
        try:
            import chromadb
            from chromadb.config import Settings

            # 创建ChromaDB客户端
            chroma_path = self.knowledge_dir / "chroma_db"
            chroma_path.mkdir(parents=True, exist_ok=True)

            self.chroma_client = chromadb.PersistentClient(
                path=str(chroma_path),
                settings=Settings(anonymized_telemetry=False)
            )

            # 创建或获取集合
            collection_name = self.config.get('knowledge_base', {}).get('vector_db', {}).get('collection', 'api_knowledge')
            self.collection = self.chroma_client.get_or_create_collection(
                name=collection_name,
                metadata={"description": "LLM-Native Static Analysis Knowledge Base"}
            )

            logger.info("ChromaDB vector database initialized successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to initialize ChromaDB: {e}")
            return False

    def build_embeddings(self) -> bool:
        """
        构建所有条目的向量嵌入

        Returns:
            是否成功
        """
        try:
            if not self.collection:
                logger.error("Vector database not initialized")
                return False

            # 检查是否有条目需要嵌入
            if not self.entries:
                logger.info("No entries to embed")
                return True

            # 获取项目根目录（环境感知）
            project_root = _get_project_root()
            pretrained_dir = project_root / 'pretrained_models'

            # 加载嵌入模型
            from sentence_transformers import SentenceTransformer
            from transformers import AutoTokenizer, AutoModel
            import torch

            # 加载模型
            bge_model = None
            unixcoder_model = None
            unixcoder_tokenizer = None

            # 加载BGE-M3
            bge_path = pretrained_dir / "BAI" / "bge-m3"
            if bge_path.exists():
                bge_model = SentenceTransformer(str(bge_path))
                logger.info("Loaded BGE-M3 model")

            # 加载UniXcoder
            unixcoder_path = pretrained_dir / "microsoft" / "unixcoder-base"
            if unixcoder_path.exists():
                unixcoder_tokenizer = AutoTokenizer.from_pretrained(str(unixcoder_path))
                unixcoder_model = AutoModel.from_pretrained(str(unixcoder_path))
                logger.info("Loaded UniXcoder model")

            if not bge_model and not unixcoder_model:
                logger.error("No embedding models available")
                return False

            # 批量生成嵌入
            documents = []
            embeddings = []
            metadatas = []
            ids = []

            for entry in self.entries.values():
                try:
                    # 选择合适的模型
                    use_unixcoder = entry.category in ['framework_api', 'code_examples', 'checker_code']

                    if use_unixcoder and unixcoder_model:
                        # 使用UniXcoder
                        tokens = unixcoder_tokenizer(entry.content, return_tensors='pt', truncation=True, max_length=512)
                        with torch.no_grad():
                            outputs = unixcoder_model(**tokens)
                            embedding = outputs.last_hidden_state.mean(dim=1).squeeze().tolist()
                    elif bge_model:
                        # 使用BGE-M3
                        embedding = bge_model.encode(entry.content).tolist()
                    else:
                        continue

                    documents.append(entry.content)
                    embeddings.append(embedding)
                    metadatas.append({
                        "id": entry.id,
                        "title": entry.title,
                        "category": entry.category,
                        "framework": entry.framework,
                        "language": entry.language,
                        "created_at": entry.created_at
                    })
                    ids.append(entry.id)

                except Exception as e:
                    logger.warning(f"Failed to embed entry {entry.id}: {e}")
                    continue

            # 批量添加到ChromaDB
            if documents:
                self.collection.add(
                    documents=documents,
                    embeddings=embeddings,
                    metadatas=metadatas,
                    ids=ids
                )
                logger.info(f"Successfully embedded {len(documents)} entries")

            logger.info("Embeddings built successfully")
            return True

        except Exception as e:
            logger.error(f"Failed to build embeddings: {e}")
            return False

    def is_available(self) -> bool:
        """
        检查知识库是否可用

        Returns:
            是否可用
        """
        return len(self.entries) > 0

    def get_stats(self) -> KnowledgeStats:
        """
        获取知识库统计信息

        Returns:
            统计信息
        """
        stats = KnowledgeStats()
        stats.total_entries = len(self.entries)

        # 统计各类别
        for entry in self.entries.values():
            stats.entries_by_category[entry.category] = stats.entries_by_category.get(entry.category, 0) + 1
            stats.entries_by_framework[entry.framework] = stats.entries_by_framework.get(entry.framework, 0) + 1
            stats.entries_by_language[entry.language] = stats.entries_by_language.get(entry.language, 0) + 1

        # 向量数据库状态
        stats.vector_db_status = "initialized" if self.vector_db else "not_initialized"

        # 最后更新时间
        if self.entries:
            latest_update = max(entry.updated_at for entry in self.entries.values())
            stats.last_updated = latest_update

        return stats

    def export_to_json(self, output_path: Path):
        """
        导出知识库到JSON文件

        Args:
            output_path: 输出文件路径
        """
        try:
            data = {
                'metadata': self.get_stats().__dict__,
                'entries': [entry.__dict__ for entry in self.entries.values()]
            }

            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)

            logger.info(f"Knowledge base exported to {output_path}")
        except Exception as e:
            logger.error(f"Failed to export knowledge base: {e}")

    def import_from_json(self, input_path: Path) -> bool:
        """
        从JSON文件导入知识库

        Args:
            input_path: 输入文件路径

        Returns:
            是否成功
        """
        try:
            with open(input_path, 'r', encoding='utf-8') as f:
                data = json.load(f)

            for entry_data in data.get('entries', []):
                entry = KnowledgeEntry(**entry_data)
                self.add_entry(entry)

            logger.info(f"Imported {len(data.get('entries', []))} entries from {input_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to import knowledge base: {e}")
            return False
