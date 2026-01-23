"""
Vector Database Integration
向量数据库集成模块

支持ChromaDB和Milvus的混合检索：
- 稠密检索（Dense）：基于语义嵌入的相似度搜索
- 稀疏检索（Sparse）：基于关键词的精确匹配
- 混合检索（Hybrid）：结合两种方法的加权结果
"""

from typing import Dict, Any, List, Optional, Tuple, Union
import json
from pathlib import Path
import logging

# 延迟导入numpy，避免在不支持的环境中出错
try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    np = None
    NUMPY_AVAILABLE = False

import logging
logger = logging.getLogger(__name__)

try:
    import chromadb
    from chromadb.config import Settings
    CHROMADB_AVAILABLE = True
except ImportError:
    CHROMADB_AVAILABLE = False
    logger.warning("ChromaDB not available. Install with: pip install chromadb")

try:
    from sentence_transformers import SentenceTransformer
    SENTENCE_TRANSFORMERS_AVAILABLE = True
except ImportError:
    SENTENCE_TRANSFORMERS_AVAILABLE = False
    logger.warning("sentence-transformers not available. Install with: pip install sentence-transformers")

from .models import KnowledgeEntry, SearchResult


class VectorDatabase:
    """
    向量数据库管理器 - 基于ChromaDB的混合检索系统

    核心特性：
    1. 智能嵌入模型选择：根据内容类型自动选择UniXcoder或BGE-M3
    2. 混合检索：稠密检索 + 稀疏检索 + 重排序
    3. 元数据过滤：基于语言、框架、模块的多级过滤
    4. 多路召回：先召回更多候选，再用交叉编码器重排序
    5. 增量更新：支持动态添加和更新条目
    """

    def __init__(self, config: Dict[str, Any]):
        """
        初始化向量数据库

        Args:
            config: 配置字典
        """
        self.config = config
        self.db_type = config.get('knowledge_base', {}).get('vector_db', {}).get('type', 'chromadb')
        self.collection_name = config.get('knowledge_base', {}).get('vector_db', {}).get('collection', 'api_knowledge')

        # 检索权重配置
        self.dense_weight = config.get('knowledge_base', {}).get('vector_db', {}).get('dense_weight', 0.7)
        self.sparse_weight = config.get('knowledge_base', {}).get('vector_db', {}).get('sparse_weight', 0.3)

        # 嵌入模型配置
        self.embedding_models = {}  # 支持多个模型
        self.default_embedding_model = config.get('knowledge_base', {}).get('vector_db', {}).get('embedding_model', 'BAAI/bge-m3')
        self.embedding_model_name = self.default_embedding_model  # 用于统计信息

        # 交叉编码器（用于重排序）
        self.cross_encoder = None
        self.cross_encoder_name = config.get('knowledge_base', {}).get('vector_db', {}).get('cross_encoder', 'BAAI/bge-reranker-base')

        # 检索配置
        self.recall_candidates = config.get('knowledge_base', {}).get('vector_db', {}).get('recall_candidates', 20)
        self.final_results = config.get('knowledge_base', {}).get('vector_db', {}).get('final_results', 5)

        # 数据库客户端
        self.client = None
        self.collection = None

        # 本地缓存
        # 修复：优先使用 knowledge_base.vector_db.persist_directory 配置
        # 如果没有配置，则使用默认的 knowledge_dir / 'vector_cache'
        configured_persist_dir = config.get('knowledge_base', {}).get('vector_db', {}).get('persist_directory')
        if configured_persist_dir:
            self.cache_dir = Path(configured_persist_dir)
        else:
            self.cache_dir = Path(config.get('paths', {}).get('knowledge_dir', 'data/knowledge')) / 'vector_cache'
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def initialize(self) -> bool:
        """
        初始化向量数据库连接

        Returns:
            是否成功
        """
        try:
            if self.db_type == 'chromadb':
                return self._init_chromadb()
            elif self.db_type == 'milvus':
                return self._init_milvus()
            else:
                logger.error(f"Unsupported vector database type: {self.db_type}")
                return False

        except Exception as e:
            logger.error(f"Failed to initialize vector database: {e}")
            return False

    def _init_chromadb(self) -> bool:
        """初始化ChromaDB"""
        if not CHROMADB_AVAILABLE:
            logger.error("ChromaDB not installed")
            return False

        try:
            # 设置环境变量以使用本地模型（在初始化前设置）
            import os
            os.environ['HF_HUB_OFFLINE'] = '1'
            os.environ['TRANSFORMERS_OFFLINE'] = '1'
            # 指向本地模型缓存目录
            pretrained_path = Path('./pretrained_models').absolute()
            if pretrained_path.exists():
                os.environ['HF_HOME'] = str(pretrained_path)
                os.environ['HUGGINGFACE_HUB_CACHE'] = str(pretrained_path)
                logger.info(f"Set HF_HOME to local cache: {pretrained_path}")
            # 首先初始化本地嵌入模型（用于ChromaDB的embedding function）
            if not self.embedding_models:
                if not self.initialize_embedding_model():
                    logger.warning("Failed to initialize local embedding models, ChromaDB will use default embedding")

            # 配置ChromaDB
            settings = Settings(
                persist_directory=str(self.cache_dir),
                is_persistent=True
                # 注意: 新版ChromaDB不再支持 anonymously_telemetry 参数
            )

            self.client = chromadb.PersistentClient(path=str(self.cache_dir), settings=settings)

            # 创建自定义 embedding function（使用本地模型）
            embedding_function = None
            if self.embedding_models and 'sentence_transformer' in self.embedding_models:
                # 使用本地的 sentence-transformer 模型
                from chromadb.utils import embedding_functions

                # 构建本地模型路径
                local_model_name = "all-MiniLM-L6-v2"
                local_model_path = Path('./pretrained_models') / f"models--sentence-transformers--{local_model_name}"

                # 查找实际的模型目录（在snapshots子目录中）
                if local_model_path.exists():
                    snapshot_dirs = list(local_model_path.glob("snapshots/*"))
                    if snapshot_dirs:
                        actual_model_path = str(snapshot_dirs[0])
                    else:
                        actual_model_path = str(local_model_path)
                else:
                    # 如果本地路径不存在，回退到HuggingFace标识符
                    actual_model_path = "sentence-transformers/all-MiniLM-L6-v2"

                embedding_function = embedding_functions.SentenceTransformerEmbeddingFunction(
                    model_name=actual_model_path,  # 使用本地路径
                    device="cpu"
                )
                logger.info(f"Using local sentence-transformers model for ChromaDB: {actual_model_path}")

            elif self.embedding_models and 'unixcoder' in self.embedding_models:
                # 回退到使用本地 unixcoder 模型
                from chromadb.utils import embedding_functions

                # 构建本地模型路径
                local_model_path = Path('./pretrained_models') / f"models--microsoft--unixcoder-base"

                if local_model_path.exists():
                    snapshot_dirs = list(local_model_path.glob("snapshots/*"))
                    actual_model_path = str(snapshot_dirs[0]) if snapshot_dirs else str(local_model_path)
                else:
                    actual_model_path = "microsoft/unixcoder-base"

                embedding_function = embedding_functions.SentenceTransformerEmbeddingFunction(
                    model_name=actual_model_path,
                    device="cpu"
                )
                logger.info(f"Using local unixcoder model for ChromaDB: {actual_model_path}")

            # 获取或创建集合
            try:
                self.collection = self.client.get_collection(
                    name=self.collection_name,
                    embedding_function=embedding_function  # 使用本地模型
                )
                logger.info(f"Loaded existing ChromaDB collection: {self.collection_name}")
            except (ValueError, Exception) as e:
                # 集合不存在或其他错误，创建新的
                if "does not exist" in str(e) or "not found" in str(e).lower() or isinstance(e, ValueError):
                    try:
                        self.collection = self.client.create_collection(
                            name=self.collection_name,
                            embedding_function=embedding_function  # 使用本地模型
                        )
                        logger.info(f"Created new ChromaDB collection: {self.collection_name} (with local embedding)")
                    except Exception as create_e:
                        logger.error(f"Failed to create ChromaDB collection: {create_e}")
                        return False
                else:
                    logger.error(f"Failed to get ChromaDB collection: {e}")
                    return False

            return True

        except Exception as e:
            logger.error(f"Failed to initialize ChromaDB: {e}")
            return False

    def _init_milvus(self) -> bool:
        """初始化Milvus（占位符）"""
        # TODO: 实现Milvus集成
        logger.warning("Milvus integration not implemented yet")
        return False

    def initialize_embedding_model(self) -> bool:
        """
        初始化嵌入模型和交叉编码器

        支持多个嵌入模型：
        - UniXcoder: 代码专用嵌入
        - BGE-M3: 多语言通用嵌入
        - 交叉编码器: 用于重排序

        Returns:
            是否成功
        """
        if not SENTENCE_TRANSFORMERS_AVAILABLE:
            logger.error("sentence-transformers not available")
            return False

        try:
            # 优先加载兼容sentence-transformers的通用嵌入模型
            primary_models = [
                ('sentence-transformers/all-MiniLM-L6-v2', 'sentence_transformer'),  # ⭐ 主要的句子嵌入模型
            ]

            # 代码专用模型暂时只使用通用sentence-transformers模型
            # BAAI/bge-m3虽然下载了但与sentence-transformers不兼容
            code_models = [
                # ('BAAI/bge-m3', 'bge'),  # 暂时禁用，等待兼容性修复
                # ('BAAI/bge-large-zh-v1.5', 'bge_zh')  # 中文增强版本（如果下载了）
            ]

            # 合并模型列表
            models_to_load = primary_models + code_models

            for model_name, model_key in models_to_load:
                try:
                    logger.info(f"Loading embedding model: {model_name}")

                    # 对于sentence-transformers模型，设置环境变量强制使用本地缓存
                    if model_name.startswith('sentence-transformers/'):
                        try:
                            # 设置离线模式环境变量
                            import os
                            os.environ['HF_HUB_OFFLINE'] = '1'
                            os.environ['TRANSFORMERS_OFFLINE'] = '1'

                            # 构建本地模型路径
                            local_model_name = model_name.replace('sentence-transformers/', '')
                            local_model_path = Path('./pretrained_models') / f"models--sentence-transformers--{local_model_name.replace('/', '--')}"

                            if local_model_path.exists():
                                # 查找实际的模型目录（可能在snapshots子目录中）
                                snapshot_dirs = list(local_model_path.glob("snapshots/*"))
                                if snapshot_dirs:
                                    actual_model_path = snapshot_dirs[0]  # 使用第一个snapshot
                                else:
                                    actual_model_path = local_model_path

                                # 使用本地路径加载
                                self.embedding_models[model_key] = SentenceTransformer(
                                    str(actual_model_path),
                    device='cpu'  # 可以配置为GPU
                )
                                logger.info(f"✅ Loaded {model_key}: {model_name} (local sentence-transformers)")
                                continue
                            else:
                                logger.warning(f"❌ {model_name} 本地路径未找到")
                                continue
                        except Exception as st_e:
                            logger.warning(f"❌ {model_name} 模型加载失败")
                            continue

                    # 对于其他模型，检查本地文件是否存在
                    model_path = Path('./pretrained_models') / f"models--{model_name.replace('/', '--')}"
                    if not model_path.exists():
                        logger.warning(f"❌ {model_name} 模型路径未找到")
                        continue

                    # 检查模型类型是否被sentence-transformers支持
                    config_path = model_path / "config.json"
                    if config_path.exists():
                        import json
                        with open(config_path, 'r') as f:
                            config = json.load(f)
                        model_type = config.get('model_type', '')

                        # sentence-transformers不支持的模型类型
                        unsupported_types = ['roberta', 'bert', 'gpt2', 'electra']
                        # 注意：xlm-roberta 是被支持的（BGE-M3等模型使用此架构）
                        if model_type in unsupported_types:
                            logger.warning(f"❌ {model_name} 模型类型不兼容")
                            logger.warning("⚠️  将使用文件模式")
                            continue

                    # 尝试加载模型
                    try:
                        self.embedding_models[model_key] = SentenceTransformer(
                            str(model_path),
                            device='cpu'  # 可以配置为GPU
                        )
                        logger.info(f"✅ Loaded {model_key}: {model_name}")
                    except Exception as load_e:
                        logger.warning(f"❌ {model_name} 模型加载失败: {str(load_e)}")
                        continue

                except Exception as model_e:
                    logger.warning(f"❌ {model_name} 初始化失败")
                    continue

            # 检查至少有一个模型加载成功
            if not self.embedding_models:
                logger.error("No embedding models were successfully loaded")
                return False

            # 设置默认模型
            if 'unixcoder' in self.embedding_models:
                self.default_model_key = 'unixcoder'
            elif 'bge' in self.embedding_models:
                self.default_model_key = 'bge'
            else:
                self.default_model_key = list(self.embedding_models.keys())[0]

            logger.info(f"Default embedding model: {self.default_model_key}")

            # 尝试加载交叉编码器（用于重排序）
            try:
                if self.cross_encoder_name:
                    from sentence_transformers import CrossEncoder
                    # 设置离线模式
                    import os
                    os.environ['HF_HUB_OFFLINE'] = '1'
                    os.environ['TRANSFORMERS_OFFLINE'] = '1'

                    # 构建本地模型路径
                    local_model_path = Path('./pretrained_models') / f"models--{self.cross_encoder_name.replace('/', '--')}"

                    if local_model_path.exists():
                        # 查找实际的模型目录（可能在snapshots子目录中）
                        snapshot_dirs = list(local_model_path.glob("snapshots/*"))
                        if snapshot_dirs:
                            actual_model_path = snapshot_dirs[0]  # 使用第一个snapshot
                        else:
                            actual_model_path = local_model_path

                        self.cross_encoder = CrossEncoder(str(actual_model_path))
                        logger.info(f"✅ Loaded cross-encoder: {self.cross_encoder_name} (local)")
                    else:
                        logger.warning("❌ 交叉编码器本地路径未找到")
                        logger.warning("Operating without cross-encoder re-ranking")
                        self.cross_encoder = None
                else:
                    logger.info("Cross-encoder not configured, using simple re-ranking")
            except Exception as ce_e:
                logger.warning("❌ 交叉编码器加载失败")
                logger.warning("⚠️  将使用简单重排序")
                self.cross_encoder = None

            logger.info(f"Embedding models initialized: {list(self.embedding_models.keys())}")
            return True

        except Exception as e:
            logger.error(f"Failed to initialize embedding models: {e}")
            return False

    def add_entries(self, entries: List[KnowledgeEntry]) -> bool:
        """
        添加知识条目到向量数据库

        Args:
            entries: 知识条目列表

        Returns:
            是否成功
        """
        if not self.collection:
            logger.error("Vector database not initialized")
            return False

        try:
            # 准备数据
            ids = []
            documents = []
            embeddings = []
            metadatas = []

            for entry in entries:
                # 生成嵌入向量（如果还没有）
                if entry.embedding is None:
                    # 根据条目类型选择合适的嵌入模型
                    model_key = self._select_model_for_entry(entry)
                    entry.embedding = self._generate_embedding(entry.content, model_key)

                if entry.embedding is not None:
                    ids.append(entry.id)
                    documents.append(entry.content)
                    embeddings.append(entry.embedding)
                    # 过滤metadata，只保留ChromaDB支持的类型 (str, int, float, bool)
                    filtered_metadata = {}
                    for k, v in entry.metadata.items():
                        if isinstance(v, (str, int, float, bool)):
                            filtered_metadata[k] = v
                        # 对于列表类型，转换为逗号分隔的字符串
                        elif isinstance(v, list):
                            filtered_metadata[k] = ', '.join(str(x) for x in v)

                    metadatas.append({
                        'title': entry.title,
                        'category': entry.category,
                        'framework': entry.framework,
                        'language': entry.language,
                        **filtered_metadata
                    })

            if ids:
                # 批量添加到数据库
                self.collection.add(
                    ids=ids,
                    documents=documents,
                    embeddings=embeddings,
                    metadatas=metadatas
                )

                logger.info(f"Added {len(ids)} entries to vector database")
                return True
            else:
                logger.warning("No valid entries to add")
                return False

        except Exception as e:
            logger.error(f"Failed to add entries to vector database: {e}")
            return False

    def _select_model_for_entry(self, entry: 'KnowledgeEntry') -> Optional[str]:
        """
        根据知识条目类型选择合适的嵌入模型

        Args:
            entry: 知识条目

        Returns:
            模型键名
        """
        # 基于类别和语言选择模型
        if entry.category in ['framework_api', 'code_examples', 'checker_code']:
            # 代码相关内容使用UniXcoder
            if 'unixcoder' in self.embedding_models:
                return 'unixcoder'
        elif entry.language == 'cpp' or entry.language == 'java':
            # C++/Java代码使用UniXcoder
            if 'unixcoder' in self.embedding_models:
                return 'unixcoder'
        elif entry.language == 'zh' or any('\u4e00' <= c <= '\u9fff' for c in entry.content):
            # 中文内容使用BGE中文模型
            if 'bge_zh' in self.embedding_models:
                return 'bge_zh'

        # 默认使用通用模型
        return self.default_model_key

    def search(self,
               query: str,
               top_k: int = 5,
               filters: Optional[Dict[str, Any]] = None,
               use_hybrid: bool = True,
               use_reranking: bool = True) -> List[SearchResult]:
        """
        高级混合检索系统

        检索流程：
        1. 多路召回：使用稠密检索获取候选结果
        2. 混合检索：结合稠密和稀疏检索结果
        3. 交叉编码器重排序：使用Cross-Encoder进行精确重排序
        4. 最终筛选：返回最相关的top_k结果

        Args:
            query: 查询字符串
            top_k: 返回结果数量
            filters: 元数据过滤条件
            use_hybrid: 是否使用混合检索
            use_reranking: 是否使用交叉编码器重排序

        Returns:
            搜索结果列表
        """
        if not self.collection:
            logger.error("Vector database not initialized")
            return []

        try:
            # 第一阶段：多路召回 - 获取更多候选
            recall_k = max(self.recall_candidates, top_k * 4)  # 至少召回4倍候选

            candidates = []

            # 稠密检索（主要检索方式）
            dense_candidates = self._dense_search(query, recall_k, filters)
            candidates.extend(dense_candidates)

            # 混合检索：添加稀疏检索结果
            if use_hybrid:
                sparse_candidates = self._sparse_search(query, recall_k, filters)
                candidates.extend(sparse_candidates)

            if not candidates:
                logger.debug(f"无候选结果: {query}")
                return []

            # 第二阶段：初步合并和过滤
            merged_candidates = self._merge_candidates(candidates, recall_k)

            # 第三阶段：交叉编码器重排序（可选）
            if use_reranking and self.cross_encoder and len(merged_candidates) > top_k:
                reranked_candidates = self._cross_encoder_rerank(query, merged_candidates, top_k * 2)
            else:
                # 使用简单重排序
                reranked_candidates = self._simple_rerank(merged_candidates, top_k * 2)

            # 第四阶段：最终筛选和格式化
            final_results = []
            for candidate in reranked_candidates[:top_k]:
                search_result = SearchResult(
                    entry=candidate['entry'],
                    score=candidate['score'],
                    source=candidate['source'],
                    matched_terms=candidate.get('matched_terms', [])
                )
                final_results.append(search_result)

            logger.info(f"Advanced search for '{query}' returned {len(final_results)} results")
            return final_results

        except Exception as e:
            logger.error(f"Advanced search failed: {e}")
            return []

    def _dense_search(self,
                     query: str,
                     top_k: int,
                     filters: Optional[Dict[str, Any]] = None) -> List[Tuple[SearchResult, float]]:
        """
        稠密检索

        Returns:
            (SearchResult, score) 元组列表
        """
        try:
            # 生成查询嵌入
            query_embedding = self._generate_embedding(query)
            if query_embedding is None:
                return []

            # 构建where子句
            where_clause = None
            if filters:
                where_clause = self._build_where_clause(filters)

            # 执行搜索
            results = self.collection.query(
                query_embeddings=[query_embedding],
                n_results=top_k,
                where=where_clause
            )

            search_results = []
            if results['ids'] and results['ids'][0]:
                for i, doc_id in enumerate(results['ids'][0]):
                    distance = results['distances'][0][i] if 'distances' in results else 0.0
                    metadata = results['metadatas'][0][i] if 'metadatas' in results else {}

                    # 将距离转换为相似度分数（ChromaDB使用余弦距离）
                    similarity_score = 1.0 - distance

                    # 重建KnowledgeEntry（简化版）
                    entry = KnowledgeEntry(
                        id=doc_id,
                        content=results['documents'][0][i] if 'documents' in results else "",
                        title=metadata.get('title', 'Unknown'),
                        category=metadata.get('category', 'unknown'),
                        framework=metadata.get('framework', 'unknown'),
                        language=metadata.get('language', 'unknown'),
                        metadata=metadata
                    )

                    search_result = SearchResult(
                        entry=entry,
                        score=similarity_score,
                        source="dense_search"
                    )

                    search_results.append((search_result, similarity_score))

            return search_results

        except Exception as e:
            logger.error(f"Dense search failed: {e}")
            return []

    def _sparse_search(self,
                      query: str,
                      top_k: int,
                      filters: Optional[Dict[str, Any]] = None) -> List[Tuple[SearchResult, float]]:
        """
        稀疏检索（关键词匹配）

        Returns:
            (SearchResult, score) 元组列表
        """
        try:
            # 构建where子句
            where_clause = None
            if filters:
                where_clause = self._build_where_clause(filters)

            # 使用ChromaDB的全文搜索功能
            results = self.collection.query(
                query_texts=[query],
                n_results=top_k,
                where=where_clause
            )

            search_results = []
            if results['ids'] and results['ids'][0]:
                for i, doc_id in enumerate(results['ids'][0]):
                    metadata = results['metadatas'][0][i] if 'metadatas' in results else {}

                    # 计算关键词匹配分数
                    content = results['documents'][0][i] if 'documents' in results else ""
                    keyword_score = self._calculate_keyword_score(query, content)

                    # 重建KnowledgeEntry（简化版）
                    entry = KnowledgeEntry(
                        id=doc_id,
                        content=content,
                        title=metadata.get('title', 'Unknown'),
                        category=metadata.get('category', 'unknown'),
                        framework=metadata.get('framework', 'unknown'),
                        language=metadata.get('language', 'unknown'),
                        metadata=metadata
                    )

                    search_result = SearchResult(
                        entry=entry,
                        score=keyword_score,
                        source="sparse_search"
                    )

                    search_results.append((search_result, keyword_score))

            return search_results

        except Exception as e:
            logger.error(f"Sparse search failed: {e}")
            return []

    def _merge_candidates(self, candidates: List[Tuple[SearchResult, float]], top_k: int) -> List[Dict[str, Any]]:
        """
        合并候选结果，去重并计算综合分数

        Args:
            candidates: (SearchResult, score) 元组列表
            top_k: 保留的候选数量

        Returns:
            合并后的候选列表，每个包含entry, score, source等信息
        """
        # 按文档ID分组
        doc_scores = {}

        for search_result, score in candidates:
            doc_id = search_result.entry.id

            if doc_id not in doc_scores:
                doc_scores[doc_id] = {
                    'entry': search_result.entry,
                    'dense_score': 0.0,
                    'sparse_score': 0.0,
                    'sources': set(),
                    'matched_terms': []
                }

            # 根据来源类型更新分数
            if search_result.source == 'dense_search':
                doc_scores[doc_id]['dense_score'] = max(doc_scores[doc_id]['dense_score'], score)
            elif search_result.source == 'sparse_search':
                doc_scores[doc_id]['sparse_score'] = max(doc_scores[doc_id]['sparse_score'], score)

            doc_scores[doc_id]['sources'].add(search_result.source)
            if hasattr(search_result, 'matched_terms') and search_result.matched_terms:
                doc_scores[doc_id]['matched_terms'].extend(search_result.matched_terms)

        # 计算综合分数并格式化
        merged_candidates = []
        for doc_data in doc_scores.values():
            # 加权综合分数
            combined_score = (
                self.dense_weight * doc_data['dense_score'] +
                self.sparse_weight * doc_data['sparse_score']
            )

            # 确定主要来源
            if doc_data['dense_score'] > doc_data['sparse_score']:
                source = 'dense_search'
            elif doc_data['sparse_score'] > 0:
                source = 'sparse_search'
            else:
                source = 'hybrid_search'

            merged_candidates.append({
                'entry': doc_data['entry'],
                'score': combined_score,
                'source': source,
                'matched_terms': list(set(doc_data['matched_terms'])),
                'dense_score': doc_data['dense_score'],
                'sparse_score': doc_data['sparse_score']
            })

        # 按分数排序并返回top_k
        merged_candidates.sort(key=lambda x: x['score'], reverse=True)
        return merged_candidates[:top_k]

    def _cross_encoder_rerank(self, query: str, candidates: List[Dict[str, Any]], top_k: int) -> List[Dict[str, Any]]:
        """
        使用交叉编码器进行重排序

        Args:
            query: 查询字符串
            candidates: 候选结果列表
            top_k: 返回结果数量

        Returns:
            重排序后的候选列表
        """
        if not self.cross_encoder or not candidates:
            return candidates[:top_k]

        try:
            # 准备输入对
            query_doc_pairs = []
            for candidate in candidates:
                query_doc_pairs.append([query, candidate['entry'].content])

            # 计算相关性分数
            scores = self.cross_encoder.predict(query_doc_pairs)

            # 更新候选分数
            for i, candidate in enumerate(candidates):
                # 结合原始分数和交叉编码器分数
                cross_score = float(scores[i])
                # 归一化交叉编码器分数到0-1范围（假设输出是logits）
                if NUMPY_AVAILABLE:
                    cross_score_normalized = 1.0 / (1.0 + np.exp(-cross_score))
                else:
                    # 简化的sigmoid计算
                    cross_score_normalized = 1.0 / (1.0 + 2.718281828459045 ** (-cross_score))

                # 加权组合：70% 原始分数 + 30% 交叉编码器分数
                combined_score = 0.7 * candidate['score'] + 0.3 * cross_score_normalized
                candidate['score'] = combined_score
                candidate['reranked'] = True

            # 重新排序
            candidates.sort(key=lambda x: x['score'], reverse=True)

        except Exception as e:
            logger.warning(f"Cross-encoder reranking failed: {e}, using simple reranking")
            return self._simple_rerank(candidates, top_k)

        return candidates[:top_k]

    def _simple_rerank(self, candidates: List[Dict[str, Any]], top_k: int) -> List[Dict[str, Any]]:
        """
        简单的重排序（基于分数和多样性）

        Args:
            candidates: 候选结果列表
            top_k: 返回结果数量

        Returns:
            重排序后的候选列表
        """
        if not candidates:
            return []

        # 按分数排序
        candidates.sort(key=lambda x: x['score'], reverse=True)

        # 多样性调整：避免同一框架的条目过于集中
        if len(candidates) > top_k:
            selected = []
            framework_count = {}

            for candidate in candidates:
                framework = candidate['entry'].framework

                # 控制每个框架的最大条目数
                max_per_framework = max(2, top_k // 3)

                if framework_count.get(framework, 0) < max_per_framework:
                    selected.append(candidate)
                    framework_count[framework] = framework_count.get(framework, 0) + 1

                    if len(selected) >= top_k:
                        break

            return selected

        return candidates[:top_k]

    def _generate_embedding(self, text: str, model_key: Optional[str] = None) -> Optional[List[float]]:
        """
        生成文本嵌入向量

        智能选择嵌入模型：
        - 代码相关内容：使用UniXcoder
        - 中文内容：优先使用BGE中文模型
        - 其他：使用默认模型

        Args:
            text: 输入文本
            model_key: 指定模型键名，如果为None则自动选择

        Returns:
            嵌入向量
        """
        if not self.embedding_models:
            logger.warning("❌ 无可用嵌入模型")
            return None

        # 智能选择模型
        if model_key is None:
            model_key = self._select_embedding_model(text)

        if model_key not in self.embedding_models:
            logger.warning(f"⚠️  使用默认模型")
            model_key = self.default_model_key

        model = self.embedding_models[model_key]

        try:
            # 根据模型类型设置不同的参数
            encode_kwargs = {}

            # 使用最基本的参数，避免兼容性问题
            if model_key != 'unixcoder':
                # 只对通用句子嵌入模型使用标准化
                encode_kwargs.update({
                    'normalize_embeddings': True
                })

            # 生成嵌入
            embedding = model.encode(text, **encode_kwargs)

            # 确保返回列表格式
            if hasattr(embedding, 'tolist'):
                return embedding.tolist()
            elif isinstance(embedding, list):
                return embedding
            else:
                return [float(x) for x in embedding]

        except Exception as e:
            # 避免重复打印相同的错误，减少日志噪音
            if not hasattr(self, '_embedding_error_logged'):
                logger.error(f"❌ 嵌入生成失败 ({model_key}): {str(e)[:100]}...")
                logger.warning("⚠️  后续相同错误将被静默处理")
                self._embedding_error_logged = True
            return None

    def _select_embedding_model(self, text: str) -> str:
        """
        根据文本内容智能选择嵌入模型

        选择逻辑：
        1. 优先使用 SentenceTransformers 通用模型（高质量嵌入）
        2. 检测代码特征 → UniXcoder（如果可用）
        3. 检测中文内容 → BGE中文模型（如果可用）
        4. 默认 → 其他可用模型

        Args:
            text: 输入文本

        Returns:
            模型键名
        """
        # 优先使用sentence-transformers模型（通用高质量嵌入）
        if 'sentence_transformer' in self.embedding_models:
            return 'sentence_transformer'

        # 代码特征检测 - 仅当有专用代码模型时使用
        code_indicators = [
            'int main', '#include', 'void ', 'class ', 'public:', 'private:',
            'std::', 'llvm::', 'clang::', 'Checker<', 'REGISTER_CHECKER',
            'DataFlow::', 'TaintTracking::', 'from ', 'import ', 'def ',
            'if __name__', 'SELECT ', 'WHERE ', 'JOIN '
        ]

        if any(indicator in text for indicator in code_indicators):
            if 'unixcoder' in self.embedding_models:
                return 'unixcoder'

        # 中文内容检测
        chinese_chars = sum(1 for char in text if '\u4e00' <= char <= '\u9fff')
        if chinese_chars > len(text) * 0.1:  # 超过10%的中文字符
            if 'bge_zh' in self.embedding_models:
                return 'bge_zh'

        # 默认模型
        return self.default_model_key

    def _calculate_keyword_score(self, query: str, content: str) -> float:
        """计算关键词匹配分数"""
        query_terms = set(query.lower().split())
        content_lower = content.lower()

        matched_terms = 0
        for term in query_terms:
            if term in content_lower:
                matched_terms += 1

        # 计算匹配率
        if len(query_terms) == 0:
            return 0.0

        match_ratio = matched_terms / len(query_terms)

        # 额外奖励：标题匹配、完全匹配等
        score = match_ratio

        # 如果查询完全匹配内容片段，加分
        if query.lower() in content_lower:
            score += 0.3

        return min(score, 1.0)  # 确保不超过1.0

    def _build_where_clause(self, filters: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        构建ChromaDB的where子句

        ChromaDB只支持单个条件查询，这里优先使用最重要的过滤条件。
        """
        if not filters:
            return None

        # 优先级：category > framework > language
        priority_filters = ['category', 'framework', 'language']

        for filter_key in priority_filters:
            if filter_key in filters:
                return {filter_key: filters[filter_key]}

        return None

    def delete_entries(self, entry_ids: List[str]) -> bool:
        """
        删除知识条目

        Args:
            entry_ids: 要删除的条目ID列表

        Returns:
            是否成功
        """
        if not self.collection:
            return False

        try:
            self.collection.delete(ids=entry_ids)
            logger.info(f"Deleted {len(entry_ids)} entries from vector database")
            return True
        except Exception as e:
            logger.error(f"Failed to delete entries: {e}")
            return False

    def get_stats(self) -> Dict[str, Any]:
        """
        获取向量数据库统计信息

        Returns:
            统计信息字典
        """
        if not self.collection:
            return {"status": "not_initialized"}

        try:
            count = self.collection.count()
            return {
                "status": "initialized",
                "collection_name": self.collection_name,
                "total_entries": count,
                "embedding_model": self.embedding_model_name,
                "db_type": self.db_type
            }
        except Exception as e:
            return {"status": "error", "error": str(e)}

    def clear_collection(self) -> bool:
        """
        清空集合

        Returns:
            是否成功
        """
        if not self.collection:
            return False

        try:
            # 删除并重新创建集合（使用本地embedding function）
            # 获取当前使用的embedding function
            from chromadb.utils import embedding_functions

            embedding_function = None
            if self.embedding_models and 'sentence_transformer' in self.embedding_models:
                # 构建本地模型路径
                local_model_name = "all-MiniLM-L6-v2"
                local_model_path = Path('./pretrained_models') / f"models--sentence-transformers--{local_model_name}"

                if local_model_path.exists():
                    snapshot_dirs = list(local_model_path.glob("snapshots/*"))
                    actual_model_path = str(snapshot_dirs[0]) if snapshot_dirs else str(local_model_path)
                else:
                    actual_model_path = "sentence-transformers/all-MiniLM-L6-v2"

                embedding_function = embedding_functions.SentenceTransformerEmbeddingFunction(
                    model_name=actual_model_path,
                    device="cpu"
                )

            self.client.delete_collection(self.collection_name)
            self.collection = self.client.create_collection(
                name=self.collection_name,
                embedding_function=embedding_function  # 使用本地embedding function
            )
            logger.info(f"Cleared collection: {self.collection_name} (with local embedding)")
            return True
        except Exception as e:
            logger.error(f"Failed to clear collection: {e}")
            return False
