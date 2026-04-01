#!/usr/bin/env python3
"""
test_rag.py - 测试 RAG 知识库功能

功能:
1. 测试 ChromaDB 连接
2. 测试嵌入模型加载
3. 测试知识库搜索
4. 添加测试文档

用法:
    python scripts/test_rag.py              # 完整测试
    python scripts/test_rag.py --memory     # 使用内存模式 (不需要 Docker)
    python scripts/test_rag.py --add-docs   # 添加测试文档
"""

import argparse
import sys
import os
from pathlib import Path

# 添加项目根目录到路径
PROJECT_DIR = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_DIR))


def test_chromadb_connection(use_memory: bool = False):
    """测试 ChromaDB 连接"""
    print("\n" + "=" * 50)
    print("测试 1: ChromaDB 连接")
    print("=" * 50)

    try:
        import chromadb
        from chromadb.config import Settings

        if use_memory:
            print("使用内存模式...")
            client = chromadb.Client(Settings(
                chroma_db_impl="duckdb+parquet",
                persist_directory=str(PROJECT_DIR / "data" / "chromadb")
            ))
        else:
            print("连接到 ChromaDB 服务器 (localhost:8001)...")
            client = chromadb.HttpClient(
                host="localhost",
                port=8001
            )

        # 测试心跳
        heartbeat = client.heartbeat()
        print(f"✓ ChromaDB 心跳: {heartbeat}")

        # 列出集合
        collections = client.list_collections()
        print(f"✓ 现有集合数量: {len(collections)}")
        for coll in collections:
            print(f"  - {coll.name}: {coll.count()} 条记录")

        return client

    except ImportError as e:
        print(f"✗ ChromaDB 未安装: {e}")
        print("  运行: pip install chromadb>=0.4.0")
        return None
    except Exception as e:
        print(f"✗ ChromaDB 连接失败: {e}")
        print("  确保 ChromaDB 正在运行: docker-compose up -d")
        return None


def test_embedding_model():
    """测试嵌入模型加载"""
    print("\n" + "=" * 50)
    print("测试 2: 嵌入模型加载")
    print("=" * 50)

    try:
        from llama_index.embeddings.huggingface import HuggingFaceEmbedding

        model_name = "sentence-transformers/all-MiniLM-L6-v2"
        cache_dir = PROJECT_DIR / "pretrained_models"

        print(f"加载模型: {model_name}")
        print(f"缓存目录: {cache_dir}")

        embed_model = HuggingFaceEmbedding(
            model_name=model_name,
            cache_folder=str(cache_dir) if cache_dir.exists() else None
        )

        # 测试嵌入
        test_text = "This is a test sentence for embedding."
        embedding = embed_model.get_text_embedding(test_text)

        print(f"✓ 模型加载成功")
        print(f"  嵌入维度: {len(embedding)}")
        print(f"  嵌入示例: {embedding[:5]}...")

        return embed_model

    except ImportError as e:
        print(f"✗ LlamaIndex 未安装: {e}")
        print("  运行: pip install llama-index-embeddings-huggingface")
        return None
    except Exception as e:
        print(f"✗ 模型加载失败: {e}")
        return None


def test_knowledge_base():
    """测试知识库功能"""
    print("\n" + "=" * 50)
    print("测试 3: 知识库功能")
    print("=" * 50)

    try:
        from src.knowledge.rag import KnowledgeBase, get_knowledge_base

        config = {
            "chromadb": {
                "host": "localhost",
                "port": 8001,
                "collection": "test_knowledge"
            },
            "embedding": {
                "model": "sentence-transformers--all-MiniLM-L6-v2",
                "cache_dir": str(PROJECT_DIR / "pretrained_models")
            },
            "retrieval": {
                "top_k": 3
            }
        }

        print("初始化知识库...")
        kb = KnowledgeBase(config)

        if not kb.initialize():
            print("✗ 知识库初始化失败")
            return None

        print(f"✓ 知识库初始化成功")
        print(f"  集合: {kb.collection.name if kb.collection else 'N/A'}")
        print(f"  文档数: {kb.collection.count() if kb.collection else 0}")

        # 测试搜索
        print("\n测试搜索功能...")
        results = kb.search("null pointer dereference", top_k=2)
        print(f"  搜索结果数: {len(results)}")

        for i, r in enumerate(results):
            print(f"  结果 {i+1}: {r.get('content', '')[:100]}...")

        return kb

    except Exception as e:
        print(f"✗ 知识库测试失败: {e}")
        import traceback
        traceback.print_exc()
        return None


def add_test_documents(kb=None):
    """添加测试文档到知识库"""
    print("\n" + "=" * 50)
    print("添加测试文档")
    print("=" * 50)

    if kb is None:
        from src.knowledge.rag import KnowledgeBase
        config = {
            "chromadb": {
                "host": "localhost",
                "port": 8001,
                "collection": "checker_knowledge"
            }
        }
        kb = KnowledgeBase(config)
        if not kb.initialize():
            print("✗ 知识库初始化失败")
            return False

    # 测试文档
    test_docs = [
        {
            "content": """# Null Pointer Dereference Checker Example

This checker detects null pointer dereferences in C/C++ code.

## Pattern
When a pointer is used without null check before dereferencing.

## Example Bug
```c
void process(User* user) {
    printf("%s\\n", user->name);  // Bug: no null check
}
```

## Fix
```c
void process(User* user) {
    if (user == NULL) return;  // Add null check
    printf("%s\\n", user->name);
}
```""",
            "metadata": {"type": "example", "category": "null_pointer"}
        },
        {
            "content": """# Clang-18 CSA Plugin Structure

## Required Headers
```cpp
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/Basic/Version.h"
```

## Plugin Entry Points
```cpp
// Version string - must be outside namespace
extern "C"
const char clang_analyzerAPIVersionString[] = CLANG_VERSION_STRING;

// Registration function
extern "C"
void clang_registerCheckers(CheckerRegistry &registry) {
    registry.addChecker<MyChecker>("custom.MyChecker", "Description", "");
}
```

## Checker Structure
- Checker class must be in anonymous namespace
- Member functions must be outside anonymous namespace
- Use CLANG_VERSION_STRING (not CLANG_ANALYZER_API_VERSION_STRING)""",
            "metadata": {"type": "api_reference", "category": "clang18"}
        },
        {
            "content": """# Buffer Overflow Detection

Buffer overflow occurs when writing data beyond the allocated buffer size.

## Common Patterns
1. `strcpy` without bounds checking
2. Array access with unchecked index
3. `memcpy` with incorrect size

## Detection Strategy
- Track buffer sizes
- Check bounds before access
- Warn on unsafe functions""",
            "metadata": {"type": "pattern", "category": "buffer_overflow"}
        }
    ]

    print(f"添加 {len(test_docs)} 个测试文档...")
    if kb.add_documents(test_docs):
        print("✓ 文档添加成功")
        print(f"  当前文档数: {kb.collection.count()}")
        return True
    else:
        print("✗ 文档添加失败")
        return False


def main():
    parser = argparse.ArgumentParser(description="测试 RAG 知识库功能")
    parser.add_argument(
        "--memory",
        action="store_true",
        help="使用内存模式 (不需要 Docker)"
    )
    parser.add_argument(
        "--add-docs",
        action="store_true",
        help="添加测试文档"
    )
    args = parser.parse_args()

    print("=" * 50)
    print("RAG 知识库功能测试")
    print("=" * 50)
    print(f"项目目录: {PROJECT_DIR}")
    print(f"模式: {'内存模式' if args.memory else '服务器模式'}")

    # 测试 ChromaDB 连接
    client = test_chromadb_connection(args.memory)
    if client is None and not args.memory:
        print("\n提示: 使用 --memory 参数可以在没有 Docker 的情况下测试")

    # 测试嵌入模型
    embed_model = test_embedding_model()

    # 测试知识库
    kb = test_knowledge_base()

    # 添加测试文档
    if args.add_docs and kb:
        add_test_documents(kb)

    # 总结
    print("\n" + "=" * 50)
    print("测试总结")
    print("=" * 50)
    print(f"ChromaDB 连接: {'✓' if client else '✗'}")
    print(f"嵌入模型加载: {'✓' if embed_model else '✗'}")
    print(f"知识库功能: {'✓' if kb else '✗'}")

    if client and embed_model and kb:
        print("\n✓ 所有测试通过！RAG 功能可用。")
        return 0
    else:
        print("\n✗ 部分测试失败，请检查上述错误信息。")
        return 1


if __name__ == "__main__":
    sys.exit(main())
