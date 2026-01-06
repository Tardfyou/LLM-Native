"""
Knowledge Base Manager
知识库管理器，负责向量数据库的操作和检索
"""

from typing import List, Dict, Any, Optional
from pathlib import Path

from loguru import logger

from core.config import Config


class KnowledgeBaseManager:
    """Knowledge Base Manager for API documentation and examples"""

    def __init__(self, config: Config):
        """
        Initialize the knowledge base manager

        Args:
            config: Framework configuration
        """
        self.config = config
        self.vector_db = None
        self.is_initialized = False

    def setup(self, force_rebuild: bool = False) -> bool:
        """
        Set up the knowledge base

        Args:
            force_rebuild: Force rebuild of the knowledge base

        Returns:
            True if setup successful
        """
        try:
            logger.info("Setting up knowledge base...")

            # Initialize vector database
            self._init_vector_db()

            # Check if knowledge base exists
            if not force_rebuild and self._knowledge_base_exists():
                logger.info("Knowledge base already exists, skipping build")
                self.is_initialized = True
                return True

            # Build knowledge base from data sources
            self._build_knowledge_base()

            self.is_initialized = True
            logger.success("Knowledge base setup completed")
            return True

        except Exception as e:
            logger.error(f"Failed to setup knowledge base: {e}")
            return False

    def _init_vector_db(self):
        """Initialize vector database connection"""
        db_type = self.config.get('knowledge_base.vector_db.type', 'chromadb')

        if db_type == 'chromadb':
            try:
                import chromadb
                from chromadb.config import Settings

                # Initialize ChromaDB client
                self.vector_db = chromadb.PersistentClient(
                    path=str(self.config.knowledge_dir / "chromadb")
                )

                # Create or get collection
                collection_name = self.config.get('knowledge_base.vector_db.collection', 'api_knowledge')
                self.collection = self.vector_db.get_or_create_collection(
                    name=collection_name,
                    metadata={"hnsw:space": "cosine"}
                )

                logger.info("ChromaDB initialized successfully")

            except ImportError:
                logger.error("ChromaDB not installed. Install with: pip install chromadb")
                raise
        else:
            logger.error(f"Unsupported vector database type: {db_type}")
            raise ValueError(f"Unsupported vector database type: {db_type}")

    def _knowledge_base_exists(self) -> bool:
        """Check if knowledge base already exists"""
        try:
            count = self.collection.count()
            return count > 0
        except Exception:
            return False

    def _build_knowledge_base(self):
        """Build knowledge base from configured data sources"""
        logger.info("Building knowledge base from data sources...")

        # For now, add some sample data
        # In a full implementation, this would crawl and process actual API docs
        sample_data = [
            {
                "id": "clang_array_bound_checker",
                "content": """
                Clang Static Analyzer Array Bound Checker

                The ArrayBoundChecker checks for out-of-bound array element accesses.

                Key APIs:
                - checkLocation(): Main callback for location checks
                - ElementRegion: Represents array element access
                - getDynamicElementCount(): Get array size information
                - assumeInBoundDual(): Check bounds constraints

                Example usage:
                ```cpp
                void ArrayBoundChecker::checkLocation(SVal l, bool isLoad, const Stmt* S,
                                                     CheckerContext &C) const {
                  const MemRegion *R = l.getAsRegion();
                  if (const ElementRegion *ER = dyn_cast<ElementRegion>(R)) {
                    // Check array bounds
                  }
                }
                ```
                """,
                "metadata": {
                    "framework": "clang",
                    "category": "array_bounds",
                    "cwe": "CWE-119"
                }
            },
            {
                "id": "codeql_tainted_path",
                "content": """
                CodeQL Tainted Path Query

                Detects path traversal vulnerabilities using taint tracking.

                Key predicates:
                - isSource(): Define taint sources
                - isSink(): Define taint sinks
                - isSanitizer(): Define sanitizers

                Example:
                ```ql
                predicate isSource(DataFlow::Node source) {
                  // Define sources like user input
                }

                predicate isSink(DataFlow::Node sink) {
                  // Define sinks like file operations
                }
                ```
                """,
                "metadata": {
                    "framework": "codeql",
                    "category": "path_traversal",
                    "cwe": "CWE-22"
                }
            }
        ]

        # Add documents to vector database
        for doc in sample_data:
            self.collection.add(
                ids=[doc["id"]],
                documents=[doc["content"]],
                metadatas=[doc["metadata"]]
            )

        logger.info(f"Added {len(sample_data)} documents to knowledge base")

    def search(self, query: str, top_k: int = 5, filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """
        Search the knowledge base

        Args:
            query: Search query
            top_k: Number of results to return
            filters: Metadata filters

        Returns:
            List of search results
        """
        if not self.is_initialized:
            logger.warning("Knowledge base not initialized")
            return []

        try:
            # Perform search
            results = self.collection.query(
                query_texts=[query],
                n_results=top_k,
                where=filters
            )

            # Format results
            formatted_results = []
            for i, doc_id in enumerate(results['ids'][0]):
                formatted_results.append({
                    'id': doc_id,
                    'content': results['documents'][0][i],
                    'metadata': results['metadatas'][0][i],
                    'score': results['distances'][0][i] if 'distances' in results else 0.0
                })

            logger.info(f"Knowledge search completed, found {len(formatted_results)} results")
            return formatted_results

        except Exception as e:
            logger.error(f"Error during knowledge search: {e}")
            return []

    def add_document(self, doc_id: str, content: str, metadata: Optional[Dict[str, Any]] = None):
        """
        Add a document to the knowledge base

        Args:
            doc_id: Unique document ID
            content: Document content
            metadata: Document metadata
        """
        if not self.is_initialized:
            logger.warning("Knowledge base not initialized")
            return

        try:
            self.collection.add(
                ids=[doc_id],
                documents=[content],
                metadatas=[metadata or {}]
            )
            logger.info(f"Added document: {doc_id}")

        except Exception as e:
            logger.error(f"Error adding document {doc_id}: {e}")

    def get_document(self, doc_id: str) -> Optional[Dict[str, Any]]:
        """
        Get a document by ID

        Args:
            doc_id: Document ID

        Returns:
            Document data or None if not found
        """
        if not self.is_initialized:
            return None

        try:
            result = self.collection.get(ids=[doc_id])
            if result['documents']:
                return {
                    'id': doc_id,
                    'content': result['documents'][0],
                    'metadata': result['metadatas'][0]
                }
            return None

        except Exception as e:
            logger.error(f"Error getting document {doc_id}: {e}")
            return None
