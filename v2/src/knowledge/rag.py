"""
RAG知识库 - 基于ChromaDB和LlamaIndex

提供:
- 向量检索
- 混合检索(稠密+稀疏)
- 知识增强生成
"""

import os
import threading
from pathlib import Path
from typing import Optional, List, Dict, Any

from loguru import logger

try:
    import chromadb
    from chromadb.config import Settings
    CHROMADB_AVAILABLE = True
except ImportError:
    CHROMADB_AVAILABLE = False
    logger.warning("ChromaDB未安装，RAG功能不可用")

try:
    from llama_index.core import VectorStoreIndex, SimpleDirectoryReader, Settings as LlamaSettings
    from llama_index.vector_stores.chroma import ChromaVectorStore
    from llama_index.embeddings.huggingface import HuggingFaceEmbedding
    LLAMAINDEX_AVAILABLE = True
except ImportError as e:
    LLAMAINDEX_AVAILABLE = False
    logger.warning(f"LlamaIndex未安装，RAG功能受限: {e}")

# 预训练模型目录
def _get_pretrained_models_dir() -> str:
    """获取预训练模型目录"""
    # 尝试多个可能的路径
    possible_paths = [
        Path(__file__).parent.parent.parent / "pretrained_models",
        Path(__file__).parent.parent.parent.parent / "pretrained_models",
        Path("/home/spa/LLM-Native/v2/pretrained_models"),
        Path("/home/spa/LLM-Native/pretrained_models"),
    ]

    for path in possible_paths:
        if path.exists():
            logger.info(f"[RAG] 找到预训练模型目录: {path}")
            return str(path)

    # 默认返回相对路径
    default_path = str(Path(__file__).parent.parent.parent / "pretrained_models")
    logger.warning(f"[RAG] 未找到预训练模型目录，使用默认路径: {default_path}")
    return default_path


class KnowledgeBase:
    """RAG知识库"""

    def __init__(self, config: Dict[str, Any]):
        """
        初始化知识库

        Args:
            config: 知识库配置
        """
        self.config = config
        self.chroma_config = config.get("chromadb", {})
        self.embedding_config = config.get("embedding", {})
        self.retrieval_config = config.get("retrieval", {})

        self.client = None
        self.collection = None
        self.embed_model = None
        self.vector_store = None
        self.index = None

        self._initialized = False
        self._init_lock = threading.RLock()

    def initialize(self) -> bool:
        """
        初始化知识库连接

        Returns:
            是否初始化成功
        """
        with self._init_lock:
            if self._initialized:
                return True

            if not CHROMADB_AVAILABLE:
                logger.warning("ChromaDB不可用，RAG功能禁用")
                return False

            try:
                # 连接ChromaDB
                host = self.chroma_config.get("host", "localhost")
                port = self.chroma_config.get("port", 8001)
                collection_name = self.chroma_config.get("collection", "checker_knowledge")

                logger.info(f"连接ChromaDB: {host}:{port}")

                self.client = chromadb.HttpClient(
                    host=host,
                    port=port
                )

                # 获取或创建集合
                self.collection = self.client.get_or_create_collection(
                    name=collection_name,
                    metadata={"hnsw:space": "cosine"}
                )

                doc_count = self.collection.count()
                logger.info(f"ChromaDB集合 '{collection_name}' 就绪, 文档数: {doc_count}")
                if doc_count == 0:
                    specialized_counts = self._list_specialized_collection_counts(collection_name)
                    if specialized_counts:
                        rendered = ", ".join(
                            f"{name}={count}"
                            for name, count in specialized_counts.items()
                        )
                        logger.warning(
                            "统一知识库集合为空，但专项集合仍有可检索文档: "
                            f"{rendered}。`search_knowledge` 仍可直接检索这些专项集合；"
                            "如需补齐统一集合，可重新运行 `python3 scripts/import_knowledge.py`。"
                        )
                    else:
                        logger.warning(
                            "知识库集合为空，RAG 当前不会提供任何参考。"
                            "如需启用知识增强，请先运行 `python3 scripts/import_knowledge.py` 导入数据。"
                        )

                # 初始化嵌入模型
                if LLAMAINDEX_AVAILABLE:
                    self._init_embedding_model()

                self._initialized = True
                return True

            except Exception as e:
                logger.error(f"知识库初始化失败: {e}")
                return False

    def _list_specialized_collection_counts(self, primary_collection: str) -> Dict[str, int]:
        """Inspect other collections to avoid误报“知识库为空”."""
        if not self.client:
            return {}
        counts: Dict[str, int] = {}
        try:
            collections = self.client.list_collections()
        except Exception:
            return {}

        for item in collections:
            name = str(getattr(item, "name", "") or "").strip()
            if not name or name == primary_collection:
                continue
            try:
                count = int(self.client.get_collection(name).count() or 0)
            except Exception:
                continue
            if count > 0:
                counts[name] = count
        return counts

    def _init_embedding_model(self):
        """初始化嵌入模型"""
        model_name = self.embedding_config.get("model", "all-MiniLM-L6-v2")
        cache_dir = self.embedding_config.get("cache_dir")
        # 默认保持历史行为：允许在线回退。
        # 仅在明确配置时关闭，或在“本地已找到但加载失败”场景下禁止无意义的在线降级。
        allow_online_fallback = bool(self.embedding_config.get("allow_online_fallback", True))
        fallback_on_local_load_failure = bool(
            self.embedding_config.get("fallback_on_local_load_failure", False)
        )

        # 查找本地模型路径
        pretrained_dir = _get_pretrained_models_dir()
        local_model_path = self._find_local_model_path(pretrained_dir, model_name)

        # 优先使用本地模型
        if local_model_path:
            logger.info(f"[RAG] 使用本地预训练模型: {local_model_path}")
            model_path = local_model_path
        else:
            if not allow_online_fallback:
                logger.warning(
                    f"[RAG] 本地模型未找到且禁用在线回退，跳过嵌入模型加载: {model_name}"
                )
                self.embed_model = None
                return

            logger.info(f"[RAG] 本地模型未找到，尝试在线下载: {model_name}")
            model_path = model_name

        try:
            logger.info(f"[RAG] 正在加载嵌入模型...")

            self.embed_model = HuggingFaceEmbedding(
                model_name=model_path,
                cache_folder=cache_dir
            )

            LlamaSettings.embed_model = self.embed_model
            logger.info(f"[RAG] 嵌入模型加载完成: {model_path}")

        except Exception as e:
            logger.error(f"[RAG] 嵌入模型加载失败: {e}")
            # 本地模型已找到但加载失败时，默认不走在线回退（常见于并发/设备状态问题，在线回退通常无效且会超时）。
            if local_model_path and not fallback_on_local_load_failure:
                logger.warning("[RAG] 本地模型加载失败，默认不启用在线回退，使用无嵌入模式继续")
                self.embed_model = None
                return

            if not allow_online_fallback:
                logger.warning("[RAG] 已禁用在线回退，使用无嵌入模式继续")
                self.embed_model = None
                return

            logger.info("[RAG] 尝试使用默认嵌入模型...")
            try:
                # 回退到最简单的模型
                self.embed_model = HuggingFaceEmbedding(
                    model_name="sentence-transformers/all-MiniLM-L6-v2"
                )
                LlamaSettings.embed_model = self.embed_model
                logger.info("[RAG] 默认嵌入模型加载成功")
            except Exception as e2:
                logger.error(f"[RAG] 默认模型也加载失败: {e2}")
                self.embed_model = None

    def _find_local_model_path(self, pretrained_dir: str, model_name: str) -> Optional[str]:
        """
        查找本地模型路径

        HuggingFace缓存格式的目录结构为:
        pretrained_models/models--org--model_name/snapshots/commit_hash/

        Args:
            pretrained_dir: 预训练模型根目录
            model_name: 模型名称 (如 "sentence-transformers--all-MiniLM-L6-v2")

        Returns:
            模型实际路径，未找到返回None
        """
        import glob

        # 尝试直接路径
        direct_path = os.path.join(pretrained_dir, model_name)
        if os.path.exists(direct_path):
            # 检查是否有config.json (直接可用)
            if os.path.exists(os.path.join(direct_path, "config.json")):
                return direct_path

            # HuggingFace缓存格式: 查找snapshots目录
            snapshots_dir = os.path.join(direct_path, "snapshots")
            if os.path.exists(snapshots_dir):
                # 获取最新的snapshot
                snapshots = glob.glob(os.path.join(snapshots_dir, "*"))
                if snapshots:
                    # 按修改时间排序，取最新的
                    latest_snapshot = max(snapshots, key=lambda x: os.path.getmtime(x))
                    if os.path.exists(os.path.join(latest_snapshot, "config.json")):
                        return latest_snapshot

        # 尝试根据模型名查找对应的缓存目录
        # 如 "all-MiniLM-L6-v2" -> "models--sentence-transformers--all-MiniLM-L6-v2"
        if "/" in model_name:
            org, name = model_name.split("/", 1)
            cache_dir_name = f"models--{org}--{name}"
        elif "--" in model_name:
            # 已经是缓存格式
            cache_dir_name = f"models--{model_name}" if not model_name.startswith("models--") else model_name
        else:
            # 尝试常见的组织名
            cache_dir_name = f"models--sentence-transformers--{model_name}"

        cache_path = os.path.join(pretrained_dir, cache_dir_name)
        if os.path.exists(cache_path):
            snapshots_dir = os.path.join(cache_path, "snapshots")
            if os.path.exists(snapshots_dir):
                snapshots = glob.glob(os.path.join(snapshots_dir, "*"))
                if snapshots:
                    latest_snapshot = max(snapshots, key=lambda x: os.path.getmtime(x))
                    if os.path.exists(os.path.join(latest_snapshot, "config.json")):
                        return latest_snapshot

        return None

    def search(self, query: str, top_k: int = None) -> List[Dict[str, Any]]:
        """
        搜索相关文档

        Args:
            query: 查询文本
            top_k: 返回结果数量

        Returns:
            相关文档列表
        """
        if not self._initialized or not self.collection:
            logger.warning("知识库未初始化，返回空结果")
            return []

        top_k = top_k or self.retrieval_config.get("top_k", 3)
        similarity_threshold = float(self.retrieval_config.get("similarity_threshold", 0.0) or 0.0)

        try:
            results = self.collection.query(
                query_texts=[query],
                n_results=top_k
            )

            documents = []
            if results and results.get("documents"):
                for i, doc in enumerate(results["documents"][0]):
                    item = {
                        "content": doc,
                        "metadata": {}
                    }
                    if results.get("metadatas") and results["metadatas"][0]:
                        item["metadata"] = results["metadatas"][0][i]
                    if results.get("distances") and results["distances"][0]:
                        distance = results["distances"][0][i]
                        similarity = 1 - distance
                        item["distance"] = distance
                        item["similarity"] = similarity

                        if similarity_threshold > 0 and similarity < similarity_threshold:
                            continue
                    documents.append(item)

            if bool(self.retrieval_config.get("log_search", False)):
                logger.info(
                    f"RAG搜索返回 {len(documents)} 条结果"
                    f" (threshold={similarity_threshold:.2f})"
                )
            return documents

        except Exception as e:
            logger.error(f"RAG搜索失败: {e}")
            return []

    def add_documents(self, documents: List[Dict[str, Any]]) -> bool:
        """
        添加文档到知识库

        Args:
            documents: 文档列表 [{"content": "...", "metadata": {...}}]

        Returns:
            是否成功
        """
        if not self._initialized or not self.collection:
            return False

        try:
            ids = [f"doc_{i}_{hash(doc['content']) % 1000000}"
                   for i, doc in enumerate(documents)]

            self.collection.add(
                documents=[doc["content"] for doc in documents],
                metadatas=[doc.get("metadata", {}) for doc in documents],
                ids=ids
            )

            logger.info(f"添加 {len(documents)} 个文档到知识库")
            return True

        except Exception as e:
            logger.error(f"添加文档失败: {e}")
            return False

    def get_context_for_generation(self, query: str, max_length: int = 4000) -> str:
        """
        获取用于生成的上下文

        Args:
            query: 查询文本
            max_length: 最大长度

        Returns:
            拼接的上下文文本
        """
        documents = self.search(query)

        if not documents:
            return ""

        context_parts = []
        total_length = 0

        for i, doc in enumerate(documents):
            content = doc["content"]
            if total_length + len(content) > max_length:
                break

            context_parts.append(f"### 参考文档 {i+1}\n{content}\n")
            total_length += len(content)

        return "\n".join(context_parts)

    def is_available(self) -> bool:
        """检查知识库是否可用"""
        return self._initialized and self.collection is not None


# 全局知识库实例
_knowledge_base: Optional[KnowledgeBase] = None
_knowledge_base_lock = threading.Lock()


def get_knowledge_base(config: Optional[Dict[str, Any]] = None) -> KnowledgeBase:
    """
    获取知识库实例

    Args:
        config: 配置字典(首次调用时需要)

    Returns:
        KnowledgeBase实例
    """
    global _knowledge_base

    if _knowledge_base is None:
        with _knowledge_base_lock:
            if _knowledge_base is None:
                if config is None:
                    config = {}
                _knowledge_base = KnowledgeBase(config)

    return _knowledge_base
