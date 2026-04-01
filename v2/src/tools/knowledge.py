"""
知识库工具

提供:
- SearchKnowledgeTool: 搜索知识库
"""

import hashlib
import re
from typing import Dict, Any, List, Optional

from ..agent.tools import Tool, ToolResult

# 猱物日志
from loguru import logger

# 集合名称映射
CSA_COLLECTIONS = [
    "checker_cwe_patterns",
    "checker_api_rules",
    "checker_examples"
]

CODEQL_COLLECTIONS = [
    "codeql_examples",
    "codeql_patterns"
]

SHARED_COLLECTIONS = [
    "analyzer_comparison",
    "shared_cwe_catalog",
]

ALLOWED_COLLECTIONS = set(CSA_COLLECTIONS + CODEQL_COLLECTIONS + SHARED_COLLECTIONS)

UNSAFE_API_TERMS = (
    "strcpy",
    "strcat",
    "gets",
    "sprintf",
    "memcpy",
    "memmove",
)

BASELINE_TERMS = (
    "基线",
    "危险函数",
    "unsafe-api",
    "最小可编译起点",
    "可编译基线",
    "compile baseline",
)

GENERIC_STRUCTURAL_TERMS = (
    "guard",
    "barrier",
    "bound",
    "bounds",
    "length",
    "size",
    "constraint",
    "path-sensitive",
    "路径敏感",
    "约束",
    "长度",
    "边界",
    "静默条件",
    "no-report",
)

CSA_STRUCTURAL_TERMS = GENERIC_STRUCTURAL_TERMS + (
    "programstate",
    "checkercontext",
    "callevent",
    "memregion",
    "symbol",
    "checkprecall",
    "checklocation",
)

CODEQL_STRUCTURAL_TERMS = GENERIC_STRUCTURAL_TERMS + (
    "variableaccess",
    "ifstmt",
    "binaryoperation",
    "getargument",
    "taint",
    "污点",
    "source",
    "sink",
)

TOPIC_TERMS = (
    "buffer",
    "overflow",
    "out-of-bounds",
    "bounds",
    "strcpy",
    "strcat",
    "gets",
    "sprintf",
    "memcpy",
    "memmove",
    "free",
    "use-after-free",
    "uaf",
    "double free",
    "leak",
    "null",
    "uninitialized",
    "divide by zero",
    "underflow",
    "printf",
    "format",
    "race",
    "toctou",
    "mutex",
    "lock",
    "sql",
    "command",
    "path",
    "traversal",
    "taint",
    "source",
    "sink",
    "programstate",
    "guard",
    "barrier",
    "size",
    "length",
    "stale",
    "dangling",
    "lifetime",
    "relookup",
    "stable handle",
    "cached pointer",
    "authoritative",
    "缓冲区",
    "溢出",
    "空指针",
    "释放",
    "竞态",
    "锁",
    "污点",
)

QUERY_TOKEN_STOPWORDS = {
    "guard",
    "barrier",
    "size",
    "length",
    "state",
    "patch",
    "clang",
    "checker",
    "codeql",
    "static",
    "analyzer",
    "api",
    "usage",
    "example",
    "constructor",
    "function",
    "member",
}

EXACT_API_HINT_TERMS = (
    "exact api",
    "exact symbol",
    "api usage",
    "constructor",
    "namespace",
    "trait",
    "no member named",
    "no matching function",
    "cannot be resolved",
    "could not resolve type",
    "undeclared identifier",
    "精确 api",
    "精确符号",
    "命名空间",
    "构造器",
    "成员方法",
    "找不到成员",
)

CSA_EXACT_API_SYMBOL_HINTS = {
    "calldescription",
    "programstatetrait",
    "register_trait_with_programstate",
    "checkercontext",
    "callevent",
    "memberexpr",
    "fieldregion",
    "memregion",
    "typedvalueregion",
    "getargsval",
    "getasregion",
    "stripcasts",
    "dyn_cast",
    "dyn_cast_or_null",
    "astcontext",
    "getparents",
    "parentmap",
}

RELOOKUP_QUERY_TERMS = (
    "stale-cache",
    "stale cache",
    "cached pointer",
    "cached field",
    "missing-relookup",
    "missing relookup",
    "relookup",
    "stable-handle",
    "stable handle",
    "authoritative lookup",
    "authoritative relookup",
    "consumer-side",
    "consumer-local",
    "memberexpr",
    "cache",
    "lookup",
    "find_",
    "权威重查找",
    "稳定句柄",
    "缓存指针",
)

RELOOKUP_DOCUMENT_TERMS = (
    "stale-cache",
    "missing-relookup",
    "stable-handle",
    "authoritative",
    "relookup",
    "cached pointer",
    "consumer-side",
    "consumer-local",
    "memberexpr",
)

DIRECT_CACHE_QUERY_TERMS = (
    "cached pointer",
    "stable handle",
    "stable-handle",
    "authoritative relookup",
    "authoritative lookup",
    "missing-relookup",
    "consumer-side",
    "consumer-local",
    "direct dereference",
    "stale cache",
    "memberexpr",
    "fieldaccess",
)

DIRECT_CACHE_DOCUMENT_TERMS = (
    "cached pointer",
    "stable handle",
    "stable-handle",
    "authoritative",
    "relookup",
    "consumer-side",
    "consumer-local",
    "missing-relookup",
    "memberexpr",
    "fieldaccess",
    "cached managed pointer",
)

UAF_QUERY_TERMS = (
    "use-after-free",
    "use after free",
    "uaf",
    "stale",
    "dangling",
    "released",
    "lifetime",
    "cached pointer",
    "stable handle",
    "stable-handle",
    "authoritative lookup",
    "authoritative relookup",
    "relookup",
)

UAF_DOCUMENT_TERMS = (
    "use-after-free",
    "use after free",
    "uaf",
    "stale",
    "dangling",
    "released",
    "lifetime",
    "cached pointer",
    "stable handle",
    "stable-handle",
    "authoritative",
    "relookup",
    "consumer-side",
    "consumer-local",
    "missing-relookup",
)

NULL_DOCUMENT_TERMS = (
    "null pointer",
    "null dereference",
    "cwe-476",
)

GENERIC_FREED_SYMBOL_TERMS = (
    "freedsymbol",
    "checklocation",
    "checkbind",
    "programstate",
    "programstatetrait",
    "释放后再次使用",
    "generic freed-symbol",
)

BUFFER_QUERY_TERMS = (
    "buffer",
    "overflow",
    "bounds-write",
    "bound write",
    "fixed destination",
    "destination capacity",
    "strlen",
    "strnlen",
    "strcpy",
    "strcat",
    "sprintf",
    "snprintf",
    "memcpy",
    "memmove",
    "guard",
    "barrier",
    "size",
    "length",
    "缓冲区",
    "溢出",
    "边界",
    "长度",
)

BUFFER_SEMANTIC_DOCUMENT_TERMS = (
    "fieldregion",
    "elementregion",
    "stripcasts",
    "getsuperregion(",
    "fixed destination",
    "destination capacity",
    "same-sink barrier",
    "same-sink",
    "same-call barrier",
    "symbolic size carrier",
    "strlen(x)+1",
    "len+1",
    "checked snprintf",
    "snprintf return",
    "getstaticdestinationbytes",
    "lookslikelengthcarrier",
    "hassameblockstringbarrier",
    "hassameblockmemcpybarrier",
    "observed_bounds_contract",
    "family_semantic_seed",
)

SCAFFOLD_ONLY_TERMS = (
    "插件片段",
    "示例展示",
    "适合作为",
    "重点是",
)

SOURCE_PREFERENCE = {
    "checker_api_rules": 6,
    "ql_patterns": 7,
    "codeql_patterns": 7,
    "checker_examples": 4,
    "cwe_patterns": 3,
    "checker_cwe_patterns": 3,
    "cwe_catalog": 2,
    "shared_cwe_catalog": 2,
    "analyzer_comparison": 2,
    "ql_examples": 5,
    "codeql_examples": 5,
}


class SearchKnowledgeTool(Tool):
    """搜索知识库工具"""

    def __init__(self, knowledge_base=None, analyzer: str = "csa"):
        """
        初始化

        Args:
            knowledge_base: KnowledgeBase 实例
            analyzer: 分析器类型 (csa/codeql/both)
        """
        self.kb = knowledge_base
        self.analyzer = analyzer
        self._chroma_client = None
        self.similarity_threshold = 0.0

        if self.kb is not None and hasattr(self.kb, "retrieval_config"):
            # similarity = 1 - distance
            # 当阈值 <= 0 时表示不启用过滤
            self.similarity_threshold = float(
                self.kb.retrieval_config.get("similarity_threshold", 0.0)
            )
        self._last_collection_status = {
            "searched": [],
            "available": [],
            "empty_or_missing": [],
        }

    def _get_chroma_client(self):
        """获取 ChromaDB 客户端"""
        if self._chroma_client is None:
            try:
                import chromadb
                host = "localhost"
                port = 8001

                # 优先从知识库配置读取
                if self.kb is not None and hasattr(self.kb, "chroma_config"):
                    host = self.kb.chroma_config.get("host", host)
                    port = self.kb.chroma_config.get("port", port)

                self._chroma_client = chromadb.HttpClient(host=host, port=port)
            except Exception as e:
                logger.error(f"无法连接 ChromaDB: {e}")
                return None
        return self._chroma_client

    def _infer_analyzer_from_query(self, query: str, analyzer: str = None) -> str:
        """根据查询内容推断检索路由，保证特定工具仅检索特定知识。"""
        if analyzer in {"csa", "codeql", "both", "auto"}:
            return analyzer

        q = (query or "").lower()

        codeql_keywords = [
            "codeql", "ql", "taint", "sink", "source", "select", "predicate"
        ]
        csa_keywords = [
            "clang", "checker", "checkerregistry", "bugreport", "programstate",
            "explodednode", "call_event", "checkprecall", "checkpostcall"
        ]

        has_codeql = any(k in q for k in codeql_keywords)
        has_csa = any(k in q for k in csa_keywords)

        if has_codeql and not has_csa:
            return "codeql"
        if has_csa and not has_codeql:
            return "csa"

        # 无明显特征时沿用当前智能体分析器；若未知则同时检索
        if self.analyzer in {"csa", "codeql", "both", "auto"}:
            return self.analyzer
        return "both"

    @property
    def name(self) -> str:
        return "search_knowledge"

    @property
    def description(self) -> str:
        return """搜索知识库获取相关参考信息。
可以搜索:
- Clang Static Analyzer API 用法
- 检测器编写示例
- 漏洞模式和检测策略
- 常见编译错误解决方案

返回与查询最相关的文档片段。"""

    @property
    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "搜索查询 (描述你想查找的内容)"
                },
                "top_k": {
                    "type": "integer",
                    "description": "返回结果数量 (默认3，最多10)",
                    "default": 3,
                    "minimum": 1,
                    "maximum": 10
                },
                "analyzer": {
                    "type": "string",
                    "description": "分析器类型 (csa/codeql/both，默认根据当前上下文)",
                    "enum": ["csa", "codeql", "both", "auto"]
                },
                "min_similarity": {
                    "type": "number",
                    "description": "最小相似度阈值(0-1)，不传则使用配置 knowledge_base.retrieval.similarity_threshold",
                    "minimum": 0,
                    "maximum": 1
                }
            },
            "required": ["query"]
        }

    def _get_collections_to_search(self, analyzer: str = None) -> List[str]:
        """根据分析器类型获取要搜索的集合列表"""
        analyzer = analyzer or self.analyzer

        if analyzer == "csa":
            collections = CSA_COLLECTIONS + SHARED_COLLECTIONS
        elif analyzer == "codeql":
            collections = CODEQL_COLLECTIONS + SHARED_COLLECTIONS
        elif analyzer == "both":
            collections = CSA_COLLECTIONS + CODEQL_COLLECTIONS + SHARED_COLLECTIONS
        elif analyzer == "auto":
            collections = CSA_COLLECTIONS + CODEQL_COLLECTIONS + SHARED_COLLECTIONS
        else:
            collections = CSA_COLLECTIONS + CODEQL_COLLECTIONS + SHARED_COLLECTIONS

        return [name for name in collections if name in ALLOWED_COLLECTIONS]

    def _query_collection(
        self,
        client,
        coll_name: str,
        query: str,
        n_results: int,
        threshold: float,
    ) -> List[Dict[str, Any]]:
        results_out: List[Dict[str, Any]] = []
        collection = client.get_collection(coll_name)
        if collection.count() == 0:
            self._last_collection_status["empty_or_missing"].append(coll_name)
            return results_out

        self._last_collection_status["available"].append(coll_name)
        results = collection.query(
            query_texts=[query],
            n_results=n_results,
        )

        if not results or not results.get("documents"):
            return results_out

        for i, doc in enumerate(results["documents"][0]):
            item = {
                "content": doc,
                "metadata": {"source": coll_name}
            }
            if results.get("metadatas") and results["metadatas"][0]:
                item["metadata"].update(results["metadatas"][0][i])
            if results.get("distances") and results["distances"][0]:
                distance = results["distances"][0][i]
                similarity = 1 - distance
                item["distance"] = distance
                item["similarity"] = similarity

            if threshold > 0 and "similarity" in item and item["similarity"] < threshold:
                continue

            results_out.append(item)

        return results_out

    def _extract_primary_block(self, content: str) -> str:
        text = str(content or "")
        blocks = re.findall(
            r"```(?:ql|cpp|c\+\+)?\n(.*?)\n```",
            text,
            flags=re.IGNORECASE | re.DOTALL,
        )
        core = max(blocks, key=len) if blocks else text
        normalized = re.sub(r"\s+", " ", core).strip()
        return normalized[:6000]

    def _result_fingerprint(self, item: Dict[str, Any]) -> str:
        content = str(item.get("content", "") or "")
        core = self._extract_primary_block(content)
        if len(core) < 80:
            core = re.sub(r"\s+", " ", content).strip()[:6000]
        return hashlib.sha1(core.encode("utf-8", errors="ignore")).hexdigest()

    def _result_preference_score(
        self,
        item: Dict[str, Any],
        analyzer: str,
        query_hints: Dict[str, Any],
    ) -> int:
        metadata = item.get("metadata", {}) or {}
        source = str(metadata.get("source", "") or "").lower()
        content = str(item.get("content", "") or "")
        lower = content.lower()
        score = SOURCE_PREFERENCE.get(source, 0)

        if query_hints.get("exact_api") and source == "checker_api_rules":
            score += 4
        if source in {"ql_patterns", "codeql_patterns"}:
            score += 1
        if '"retrieval_priority": "high"' in lower or "retrieval_priority: high" in lower:
            score += 2
        if '"retrieval_priority": "low"' in lower or "retrieval_priority: low" in lower:
            score -= 2
        if analyzer == "csa" and self._is_scaffold_only_example(content):
            score -= 3
        if str(metadata.get("pattern_type", "") or "").lower() == "sink_review_baseline":
            score -= 1
        return score

    def _dedupe_results(
        self,
        results: List[Dict[str, Any]],
        analyzer: str,
        query_hints: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        kept: Dict[str, Dict[str, Any]] = {}
        for item in results:
            key = self._result_fingerprint(item)
            existing = kept.get(key)
            if existing is None:
                kept[key] = item
                continue
            current_score = self._result_preference_score(item, analyzer, query_hints)
            existing_score = self._result_preference_score(existing, analyzer, query_hints)
            if current_score > existing_score:
                kept[key] = item
        deduped = list(kept.values())
        deduped.sort(
            key=lambda item: (
                item.get("distance", 1.0),
                -self._result_preference_score(item, analyzer, query_hints),
            )
        )
        return deduped

    def _extract_symbol_tokens(self, query: str, analyzer: str) -> List[str]:
        symbols: List[str] = []
        seen = set()
        raw_query = str(query or "")
        lowered = raw_query.lower()
        for token in re.findall(r"[A-Za-z_][A-Za-z0-9_:]{2,}", raw_query):
            normalized = token.strip(":").lower()
            if len(normalized) < 4 or normalized in QUERY_TOKEN_STOPWORDS:
                continue
            looks_like_symbol = (
                "::" in token
                or "_" in token
                or any(ch.isupper() for ch in token)
            )
            if analyzer == "csa" and normalized in CSA_EXACT_API_SYMBOL_HINTS:
                looks_like_symbol = True
            if not looks_like_symbol:
                continue
            if normalized in seen:
                continue
            seen.add(normalized)
            symbols.append(normalized)

        if analyzer == "csa":
            for hint in CSA_EXACT_API_SYMBOL_HINTS:
                if hint in lowered and hint not in seen:
                    seen.add(hint)
                    symbols.append(hint)
        return symbols

    def _extract_query_hints(self, query: str, analyzer: str) -> Dict[str, Any]:
        q = (query or "").lower()
        symbol_tokens = self._extract_symbol_tokens(query, analyzer)
        exact_api = any(token in q for token in EXACT_API_HINT_TERMS) or bool(symbol_tokens)
        relookup_mode = any(token in q for token in RELOOKUP_QUERY_TERMS)
        buffer_family = any(token in q for token in BUFFER_QUERY_TERMS)
        uaf_family = any(token in q for token in UAF_QUERY_TERMS)
        direct_cache_mode = any(token in q for token in DIRECT_CACHE_QUERY_TERMS)
        return {
            "query": q,
            "semantic": any(
                token in q for token in (
                    "guard",
                    "barrier",
                    "bound",
                    "bounds",
                    "length",
                    "size",
                    "constraint",
                    "state",
                    "programstate",
                    "taint",
                    "patch",
                    "overflow",
                    "buffer",
                    "边界",
                    "长度",
                    "约束",
                    "路径",
                    "污点",
                    "补丁",
                )
            ),
            "guard": any(
                token in q for token in (
                    "guard",
                    "barrier",
                    "check",
                    "if",
                    "bounds",
                    "size",
                    "length",
                    "边界",
                    "长度",
                    "守卫",
                    "静默",
                )
            ),
            "state": any(
                token in q for token in (
                    "state",
                    "programstate",
                    "path",
                    "symbol",
                    "taint",
                    "污点",
                    "路径",
                    "约束",
                )
            ),
            "patch": any(token in q for token in ("patch", "补丁", "修复", "泛化")),
            "exact_api": exact_api,
            "symbol_tokens": symbol_tokens,
            "relookup_mode": relookup_mode,
            "direct_cache_mode": direct_cache_mode,
            "memberexpr_mode": "memberexpr" in q,
            "fieldaccess_mode": "fieldaccess" in q,
            "buffer_family": buffer_family,
            "uaf_family": uaf_family,
            "analyzer": analyzer or self.analyzer,
        }

    def _topic_overlap(self, query: str, content: str) -> int:
        """估算查询主题词与文档主题词的重合度，避免跨漏洞家族串味。"""
        q = query.lower()
        query_terms = {term for term in TOPIC_TERMS if term in q}
        query_terms.update(
            token
            for token in re.findall(r"[a-zA-Z_][a-zA-Z0-9_+-]{2,}", q)
            if token not in QUERY_TOKEN_STOPWORDS
        )

        if not query_terms:
            return 0

        return sum(1 for term in query_terms if term in content)

    def _structural_terms_for_analyzer(self, analyzer: str) -> tuple:
        if analyzer == "csa":
            return CSA_STRUCTURAL_TERMS
        if analyzer == "codeql":
            return CODEQL_STRUCTURAL_TERMS
        return GENERIC_STRUCTURAL_TERMS

    def _is_api_only_baseline(self, content: str, analyzer: str) -> bool:
        lower = content.lower()
        has_unsafe_api = any(term in lower for term in UNSAFE_API_TERMS)
        has_baseline_language = any(term in lower for term in BASELINE_TERMS)
        has_structural_terms = any(
            term in lower for term in self._structural_terms_for_analyzer(analyzer)
        )
        return has_unsafe_api and (has_baseline_language or not has_structural_terms)

    def _is_scaffold_only_example(self, content: str) -> bool:
        lower = (content or "").lower()
        if not any(term in lower for term in SCAFFOLD_ONLY_TERMS):
            return False
        has_plugin_skeleton = (
            "clang_analyzerapiversionstring" in lower
            and "clang_registercheckers" in lower
        )
        return not has_plugin_skeleton

    def _adjust_distance_for_query(
        self,
        item: Dict[str, Any],
        analyzer: str,
        query_hints: Dict[str, Any],
    ) -> float:
        distance = float(item.get("distance", 1.0))
        content = item.get("content", "")
        lower = content.lower()
        metadata = item.get("metadata", {}) or {}
        source = str(metadata.get("source", "") or "").lower()
        structural_terms = self._structural_terms_for_analyzer(analyzer)
        structural_hits = sum(1 for term in structural_terms if term in lower)
        topic_overlap = self._topic_overlap(query_hints.get("query", ""), lower)
        adjusted = distance

        if topic_overlap == 0:
            adjusted += 0.18
        elif topic_overlap == 1:
            adjusted += 0.05
        else:
            adjusted -= min(0.03 * topic_overlap, 0.12)

        if query_hints.get("semantic"):
            adjusted -= min(0.02 * structural_hits, 0.16)

            if query_hints.get("guard") and any(
                term in lower for term in ("guard", "barrier", "bound", "size", "length", "边界", "长度", "约束")
            ):
                adjusted -= 0.08

            if query_hints.get("state") and any(
                term in lower for term in ("programstate", "symbol", "path-sensitive", "路径敏感", "taint", "污点", "variableaccess")
            ):
                adjusted -= 0.08

            if self._is_api_only_baseline(content, analyzer):
                adjusted += 0.18
            elif any(term in lower for term in BASELINE_TERMS):
                adjusted += 0.05
            if analyzer == "csa" and self._is_scaffold_only_example(content):
                adjusted += 0.24
            if analyzer == "codeql" and source in {"ql_examples", "codeql_examples"}:
                adjusted -= 0.06
            if analyzer == "codeql" and source in {"ql_patterns", "codeql_patterns"}:
                adjusted -= 0.08
            if analyzer == "codeql" and source in {"cwe_catalog", "shared_cwe_catalog"}:
                adjusted += 0.10

        if query_hints.get("exact_api"):
            symbols = query_hints.get("symbol_tokens", []) or []
            if symbols:
                matched = sum(1 for symbol in symbols if symbol in lower)
                symbol_match_ratio = matched / max(len(symbols), 1)
                if symbol_match_ratio == 0:
                    adjusted += 0.36
                elif symbol_match_ratio < 0.34:
                    adjusted += 0.10
                elif symbol_match_ratio >= 0.67:
                    adjusted -= 0.08
            if analyzer == "csa":
                if source == "checker_api_rules":
                    adjusted -= 0.14
                elif source in {"checker_examples", "cwe_patterns", "cwe_catalog"} and not any(symbol in lower for symbol in (query_hints.get("symbol_tokens", []) or [])):
                    adjusted += 0.12

        if query_hints.get("relookup_mode"):
            has_relookup_signal = any(term in lower for term in RELOOKUP_DOCUMENT_TERMS)
            has_generic_freed_symbol_signal = any(term in lower for term in GENERIC_FREED_SYMBOL_TERMS)
            has_direct_cache_signal = any(term in lower for term in DIRECT_CACHE_DOCUMENT_TERMS)
            if has_relookup_signal:
                adjusted -= 0.24
            if query_hints.get("direct_cache_mode"):
                if has_direct_cache_signal:
                    adjusted -= 0.18
                if has_generic_freed_symbol_signal and not has_relookup_signal:
                    adjusted += 0.44
            if query_hints.get("memberexpr_mode"):
                if "memberexpr" in lower:
                    adjusted -= 0.12
                elif has_generic_freed_symbol_signal and not has_relookup_signal:
                    adjusted += 0.08
            if query_hints.get("fieldaccess_mode"):
                if "fieldaccess" in lower:
                    adjusted -= 0.10
                elif has_generic_freed_symbol_signal and not has_relookup_signal:
                    adjusted += 0.06
            if has_generic_freed_symbol_signal and not has_relookup_signal and not query_hints.get("exact_api"):
                adjusted += 0.30

        if query_hints.get("buffer_family"):
            buffer_semantic_hits = sum(
                1 for term in BUFFER_SEMANTIC_DOCUMENT_TERMS if term in lower
            )
            if buffer_semantic_hits:
                adjusted -= min(0.025 * buffer_semantic_hits, 0.18)

            if analyzer == "codeql" and source in {"ql_patterns", "codeql_patterns"}:
                adjusted -= 0.08
            if analyzer == "codeql" and source in {"ql_examples", "codeql_examples"}:
                adjusted -= 0.05
            if analyzer == "codeql" and source in {"cwe_catalog", "shared_cwe_catalog"}:
                adjusted += 0.14

            if source == "checker_examples" and (
                '"quality_tier": "family_semantic_seed"' in lower
                or "quality_tier: family_semantic_seed" in lower
            ):
                adjusted -= 0.08

            if source == "cwe_patterns" and buffer_semantic_hits < 3:
                adjusted += 0.12

            if (
                '"quality_tier": "baseline_compile_skeleton"' in lower
                or "quality_tier: baseline_compile_skeleton" in lower
            ):
                adjusted += 0.10

            has_generic_freed_symbol_signal = any(
                term in lower for term in GENERIC_FREED_SYMBOL_TERMS
            )
            if has_generic_freed_symbol_signal and buffer_semantic_hits == 0:
                adjusted += 0.22

            if query_hints.get("exact_api") and source == "cwe_patterns":
                adjusted += 0.08

        if query_hints.get("uaf_family"):
            uaf_hits = sum(1 for term in UAF_DOCUMENT_TERMS if term in lower)
            if uaf_hits:
                adjusted -= min(0.03 * uaf_hits, 0.20)

            if analyzer == "codeql" and source in {"ql_patterns", "codeql_patterns"}:
                adjusted -= 0.10
            if analyzer == "codeql" and source in {"ql_examples", "codeql_examples"}:
                adjusted -= 0.06
            if analyzer == "codeql" and source in {"cwe_catalog", "shared_cwe_catalog"} and uaf_hits < 3:
                adjusted += 0.16

            if analyzer == "csa" and source == "checker_examples" and uaf_hits:
                adjusted -= 0.08

            if any(term in lower for term in BUFFER_SEMANTIC_DOCUMENT_TERMS) and uaf_hits == 0:
                adjusted += 0.18
            if any(term in lower for term in NULL_DOCUMENT_TERMS) and uaf_hits == 0:
                adjusted += 0.18

        if '"retrieval_priority": "high"' in lower or "retrieval_priority: high" in lower:
            adjusted -= 0.06
        if '"retrieval_priority": "low"' in lower or "retrieval_priority: low" in lower:
            adjusted += 0.06
        if '"quality_tier": "baseline_compile_skeleton"' in lower or "quality_tier: baseline_compile_skeleton" in lower:
            adjusted += 0.08
        if "fragment_scaffold" in lower:
            adjusted += 0.18
        if str(metadata.get("pattern_type", "") or "").lower() == "sink_review_baseline":
            adjusted += 0.10

        if query_hints.get("patch") and any(
            term in lower for term in ("不应退化", "guard", "barrier", "约束", "静默条件", "no-report")
        ):
            adjusted -= 0.04

        return adjusted

    def _rerank_results(
        self,
        results: List[Dict[str, Any]],
        query: str,
        analyzer: str,
        top_k: int,
    ) -> List[Dict[str, Any]]:
        query_hints = self._extract_query_hints(query, analyzer)
        for item in results:
            item["adjusted_distance"] = self._adjust_distance_for_query(item, analyzer, query_hints)

        results.sort(
            key=lambda item: (
                item.get("adjusted_distance", item.get("distance", 1.0)),
                item.get("distance", 1.0),
            )
        )
        return results[:top_k]

    def _search_collections(
        self,
        query: str,
        collections: List[str],
        top_k: int,
        analyzer: str,
        min_similarity: float = None
    ) -> List[Dict[str, Any]]:
        """搜索多个集合并合并结果"""
        all_results = []
        client = self._get_chroma_client()
        threshold = self.similarity_threshold if min_similarity is None else float(min_similarity)
        query_hints = self._extract_query_hints(query, analyzer)
        per_collection_budget = min(max(top_k, 3), 10)
        if query_hints.get("exact_api") or query_hints.get("relookup_mode"):
            per_collection_budget = min(max(top_k, 6), 10)
        self._last_collection_status = {
            "searched": list(collections),
            "available": [],
            "empty_or_missing": [],
        }

        if client is None:
            return []

        for coll_name in collections:
            try:
                all_results.extend(
                    self._query_collection(
                        client=client,
                        coll_name=coll_name,
                        query=query,
                        n_results=per_collection_budget,
                        threshold=threshold,
                    )
                )
            except Exception as e:
                logger.debug(f"搜索集合 {coll_name} 失败: {e}")
                self._last_collection_status["empty_or_missing"].append(coll_name)
                continue

        # 按相关度排序并限制数量
        if all_results:
            all_results = self._dedupe_results(all_results, analyzer, query_hints)
            all_results = self._rerank_results(all_results, query, analyzer, top_k)

        return all_results

    def _format_result_excerpt(self, content: str, query_hints: Dict[str, Any]) -> str:
        text = str(content or "")
        limit = 1800 if (query_hints.get("exact_api") or query_hints.get("relookup_mode")) else 1000
        if len(text) <= limit:
            return text

        lowered = text.lower()
        anchors: List[int] = []
        for symbol in query_hints.get("symbol_tokens", []) or []:
            pos = lowered.find(symbol)
            if pos >= 0:
                anchors.append(pos)
        if query_hints.get("relookup_mode"):
            for term in RELOOKUP_DOCUMENT_TERMS:
                pos = lowered.find(term)
                if pos >= 0:
                    anchors.append(pos)
                    break

        if anchors:
            start = max(0, min(anchors) - 260)
            end = min(len(text), start + limit)
            snippet = text[start:end]
            if start > 0:
                snippet = "...\n" + snippet
            if end < len(text):
                snippet = snippet + "\n..."
            return snippet

        return text[:limit] + "..."

    def _is_relookup_seed_document(self, content: str) -> bool:
        lower = str(content or "").lower()
        return any(term in lower for term in RELOOKUP_DOCUMENT_TERMS) and any(
            term in lower for term in DIRECT_CACHE_DOCUMENT_TERMS
        )

    def _is_generic_freed_symbol_document(self, content: str) -> bool:
        lower = str(content or "").lower()
        return any(term in lower for term in GENERIC_FREED_SYMBOL_TERMS) and not any(
            term in lower for term in RELOOKUP_DOCUMENT_TERMS
        )

    def _render_mechanism_hint(
        self,
        results: List[Dict[str, Any]],
        query_hints: Dict[str, Any],
        analyzer: str,
    ) -> str:
        if not (query_hints.get("relookup_mode") and query_hints.get("direct_cache_mode")):
            return ""

        has_relookup_seed = any(
            self._is_relookup_seed_document(item.get("content", ""))
            for item in results
        )
        has_generic_freedsymbol = any(
            self._is_generic_freed_symbol_document(item.get("content", ""))
            for item in results
        )
        if not has_relookup_seed:
            return ""

        if analyzer == "csa":
            return (
                "检索建议: 当前补丁更像 cached-pointer / stable-handle / authoritative-relookup family；"
                "优先参考 consumer-side relookup skeleton，ProgramState/FreedSymbols 仅作兜底。"
            )

        if analyzer == "codeql":
            suffix = (
                "保留 FieldAccess / stable-handle skeleton 的 exact API，"
                "不要扩展成跨函数 release/use 配对。"
            )
            if has_generic_freedsymbol:
                suffix = (
                    "优先沿用 stable-handle / cached-pointer 骨架，"
                    "不要退化成 generic free/use family。"
                )
            return f"检索建议: {suffix}"

        return ""

    def execute(
        self,
        query: str,
        top_k: int = 3,
        analyzer: str = None,
        min_similarity: float = None
    ) -> ToolResult:
        """
        执行搜索

        Args:
            query: 搜索查询
            top_k: 返回结果数量
            analyzer: 分析器类型 (覆盖默认值)

        Returns:
            ToolResult
        """
        try:
            # 限制 top_k
            top_k = min(max(1, top_k), 10)

            # 获取要搜索的集合
            search_analyzer = self._infer_analyzer_from_query(query, analyzer)
            collections = self._get_collections_to_search(search_analyzer)

            # 执行搜索
            results = self._search_collections(
                query,
                collections,
                top_k,
                search_analyzer,
                min_similarity=min_similarity,
            )

            if not results:
                available = self._last_collection_status.get("available", [])
                threshold_info = (
                    "可能是相似度阈值过高导致过滤，可降低 knowledge_base.retrieval.similarity_threshold。"
                )
                if not available:
                    threshold_info = (
                        "当前知识集合为空或尚未导入，可先运行 "
                        "`python3 scripts/import_knowledge.py` 初始化知识库。"
                    )
                return ToolResult(
                    success=True,
                    output=(
                        "未找到相关文档。"
                        + threshold_info
                    ),
                    metadata={
                        "query": query,
                        "analyzer": search_analyzer,
                        "collections": collections,
                        "available_collections": available,
                        "empty_or_missing_collections": self._last_collection_status.get("empty_or_missing", []),
                        "min_similarity": self.similarity_threshold if min_similarity is None else min_similarity,
                        "threshold_used": self.similarity_threshold if min_similarity is None else min_similarity,
                        "top_similarity": 0.0,
                        "qualified_count": 0,
                        "count": 0,
                    }
                )

            # 格式化结果
            output_parts = [f"找到 {len(results)} 条相关文档:\n"]
            available = self._last_collection_status.get("available", [])
            empty_or_missing = self._last_collection_status.get("empty_or_missing", [])
            threshold_used = self.similarity_threshold if min_similarity is None else float(min_similarity)
            top_similarity = max(
                float(doc.get("similarity", 0.0) or 0.0)
                for doc in results
            ) if results else 0.0
            qualified_count = sum(
                1
                for doc in results
                if float(doc.get("similarity", 0.0) or 0.0) >= threshold_used
            )
            query_hints = self._extract_query_hints(query, search_analyzer)
            mechanism_hint = self._render_mechanism_hint(results, query_hints, search_analyzer)
            if mechanism_hint:
                output_parts.append(mechanism_hint + "\n")

            for i, doc in enumerate(results, 1):
                content = doc.get("content", "")
                metadata = doc.get("metadata", {})
                distance = doc.get("distance", None)
                source = metadata.get("source", "unknown")

                content = self._format_result_excerpt(content, query_hints)

                output_parts.append(f"### 文档 {i} (来源: {source})")
                if distance is not None:
                    output_parts.append(f"相关度: {1 - distance:.2%}")
                output_parts.append(f"内容:\n{content}\n")

            output = "\n".join(output_parts)

            return ToolResult(
                success=True,
                output=output,
                metadata={
                    "query": query,
                    "analyzer": search_analyzer,
                    "collections": collections,
                    "available_collections": available,
                    "empty_or_missing_collections": empty_or_missing,
                    "min_similarity": threshold_used,
                    "threshold_used": threshold_used,
                    "top_similarity": top_similarity,
                    "qualified_count": qualified_count,
                    "count": len(results),
                    "results": results
                }
            )

        except Exception as e:
            logger.error(f"知识库搜索失败: {e}")
            return ToolResult(
                success=False,
                output="",
                error=f"搜索失败: {str(e)}。请直接使用你的知识继续工作。"
            )

    def set_analyzer(self, analyzer: str):
        """设置分析器类型"""
        self.analyzer = analyzer
