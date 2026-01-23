#!/usr/bin/env python3
"""
Debug script to test knowledge retrieval exactly as orchestrator does
"""
import sys
from pathlib import Path

# Add src directory to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root / 'src'))

import yaml
from knowledge_base.manager import KnowledgeBaseManager

def load_config(config_file: str = "config/config.yaml") -> dict:
    """Load configuration file"""
    config_path = Path(config_file)
    if not config_path.exists():
        print(f"[ERROR] Config file not found: {config_path}")
        return {}

    with open(config_path, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f)

def test_kb_retrieval():
    """Test knowledge base retrieval the same way orchestrator does"""
    print("=" * 60)
    print("Testing Knowledge Base Retrieval (Orchestrator Style)")
    print("=" * 60)

    # 1. Load config (as main.py does)
    print("\n[1] Loading config...")
    config = load_config()
    if not config:
        print("[ERROR] Failed to load config")
        return False
    print(f"[OK] Config loaded")

    # 2. Show config details
    print("\n[2] Config details:")
    kb_config = config.get('knowledge_base', {})
    print(f"    vector_db.type: {kb_config.get('vector_db', {}).get('type')}")
    print(f"    vector_db.collection: {kb_config.get('vector_db', {}).get('collection')}")
    print(f"    vector_db.persist_directory: {kb_config.get('vector_db', {}).get('persist_directory')}")
    print(f"    paths.knowledge_dir: {config.get('paths', {}).get('knowledge_dir')}")

    # 3. Create KnowledgeBaseManager WITH config (as fixed main.py does)
    print("\n[3] Creating KnowledgeBaseManager WITH config...")
    kb = KnowledgeBaseManager(config)
    print(f"[OK] KnowledgeBaseManager created")
    print(f"     Entries loaded: {len(kb.entries)}")

    # 4. Check vector DB status
    print("\n[4] Checking vector DB status...")
    if kb.vector_db:
        print(f"[OK] Vector DB initialized")
        print(f"     DB type: {kb.vector_db.db_type}")
        print(f"     Collection name: {kb.vector_db.collection_name}")
        print(f"     Cache dir (persist_directory): {kb.vector_db.cache_dir}")
        print(f"     Embedding models: {list(kb.vector_db.embedding_models.keys())}")
    else:
        print("[ERROR] Vector DB not initialized!")
        return False

    # 5. Check if collection exists and has data
    print("\n[5] Checking ChromaDB collection...")
    try:
        if kb.vector_db.collection:
            count = kb.vector_db.collection.count()
            print(f"[OK] Collection '{kb.vector_db.collection_name}' has {count} documents")
        else:
            print("[ERROR] Collection is None!")
            return False
    except Exception as e:
        print(f"[ERROR] Failed to check collection: {e}")
        return False

    # 6. Test search with the EXACT query orchestrator uses
    print("\n[6] Testing search with orchestrator's query...")
    test_queries = [
        "buffer overflow",           # Test script uses this
        "buffer overflow checker patterns",  # Orchestrator uses this
        "buffer overflow static analyzer",
        "CWE-120",
        "strcpy",
    ]

    for query in test_queries:
        print(f"\n    Query: '{query}'")
        results = kb.search(query, top_k=5, search_mode="advanced")
        print(f"    Results: {len(results)} items")
        if results:
            for i, r in enumerate(results[:3], 1):
                print(f"      {i}. [{r.entry.category}] {r.entry.title} (score: {r.score:.4f})")

    # 7. Test async search (as knowledge_agent does)
    print("\n[7] Testing async search (as knowledge_agent does)...")
    import asyncio

    async def test_async():
        query = "buffer overflow checker patterns"
        print(f"    Query: '{query}'")
        results = await kb.search_async(query, top_k=5, search_mode="advanced")
        print(f"    Results: {len(results)} items")
        if results:
            for i, r in enumerate(results[:3], 1):
                print(f"      {i}. [{r.entry.category}] {r.entry.title} (score: {r.score:.4f})")
        return len(results)

    count = asyncio.run(test_async())

    # 8. Summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    if count > 0:
        print("[SUCCESS] Knowledge retrieval is working!")
        print(f"          Found {count} results for 'buffer overflow checker patterns'")
    else:
        print("[FAILED] Still getting 0 results!")
        print("\nPossible issues:")
        print("1. ChromaDB persist_directory mismatch")
        print("2. Collection name mismatch")
        print("3. No data was imported to the collection")
        print("\nTo check actual ChromaDB data:")
        print(f"   ls -la {kb.vector_db.cache_dir}")

    return count > 0

if __name__ == "__main__":
    import loguru
    success = test_kb_retrieval()
    sys.exit(0 if success else 1)
