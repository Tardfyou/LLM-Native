#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LLM-Native知识库综合测试脚本
集成嵌入模型测试和向量搜索测试功能

功能：
1. 嵌入模型加载和测试（包括交叉编码器）
2. 向量搜索功能测试（多种搜索模式）
3. 知识库状态检查
4. 性能统计和诊断信息

使用方法：
python scripts/test_knowledge_base.py [模式] [参数]

模式：
- embedding    : 测试嵌入模型（默认）
- search       : 测试向量搜索
- full         : 运行所有测试

示例：
python scripts/test_knowledge_base.py embedding
python3 scripts/test_knowledge_base.py search "null ptr dereference" --top-k 2
python scripts/test_knowledge_base.py full
"""

import sys
import os
import argparse
import time
from pathlib import Path
from typing import List, Dict, Any

# 添加项目路径
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root / 'src'))

# 导入知识库相关模块
from knowledge_base.manager import KnowledgeBaseManager
from knowledge_base.vector_db import VectorDatabase

def test_embedding_models():
    """测试嵌入模型加载和功能"""
    print("\033[94m[INFO]\033[0m Testing embedding model loading...")
    print("-" * 50)

    # 检查依赖
    try:
        import sentence_transformers
        SENTENCE_TRANSFORMERS_AVAILABLE = True
    except ImportError:
        SENTENCE_TRANSFORMERS_AVAILABLE = False

    if not SENTENCE_TRANSFORMERS_AVAILABLE:
        print("\033[93m[WARNING]\033[0m sentence-transformers not installed")
        print("   Please run: pip install sentence-transformers")
        print("\033[91m[ERROR]\033[0m Embedding model initialization failed")
        return False

    try:
        # 创建配置
        config = {
            'knowledge_base': {
                'vector_db': {
                    'type': 'chromadb',
                    'collection': 'test_collection'
                }
            },
            'paths': {
                'knowledge_dir': str(project_root / 'data' / 'knowledge'),
                'models_dir': str(project_root / 'pretrained_models')
            }
        }

        vector_db = VectorDatabase(config)

        # 初始化嵌入模型
        success = vector_db.initialize_embedding_model()

        if success:
            print("\033[92m[SUCCESS]\033[0m Embedding model initialization successful")
            print(f"   Available models: {list(vector_db.embedding_models.keys())}")

            # 测试模型选择
            test_texts = [
                "This is a general English text",
                "int main() { return 0; }",
                "这是一个中文的描述文本"
            ]

            print("\n\033[94m[INFO]\033[0m Testing intelligent model selection:")
            for text in test_texts:
                selected_model = vector_db._select_embedding_model(text)
                print(f"   '{text[:30]}...' -> {selected_model}")

            # 测试嵌入生成
            if 'sentence_transformer' in vector_db.embedding_models:
                print("\n\033[94m[INFO]\033[0m Testing embedding generation...")
                model = vector_db.embedding_models['sentence_transformer']
                test_embedding = model.encode(["Hello world"])
                print(f"   Embedding dimensions: {test_embedding.shape[1]}")
                print("\033[92m[SUCCESS]\033[0m Embedding generation successful")

            # 测试交叉编码器
            if vector_db.cross_encoder is not None:
                print("\n\033[94m[INFO]\033[0m Testing cross-encoder...")
                test_query = "What is Python?"
                test_docs = [
                    "Python is a programming language.",
                    "Java is an object-oriented language.",
                    "Python supports multiple programming paradigms."
                ]

                # 准备查询-文档对
                query_doc_pairs = [[test_query, doc] for doc in test_docs]

                # 进行重排序预测
                scores = vector_db.cross_encoder.predict(query_doc_pairs)
                print(f"   Reranking scores: {scores}")

                # 显示重排序结果
                results = list(zip(test_docs, scores))
                results.sort(key=lambda x: x[1], reverse=True)
                print("   Reranked documents:")
                for i, (doc, score) in enumerate(results[:3]):
                    print(f"     {i+1}. (Score: {score:.4f}) {doc}")

                print("\033[92m[SUCCESS]\033[0m Cross-encoder reranking successful")

            elif hasattr(vector_db, 'cross_encoder_name') and vector_db.cross_encoder_name:
                print("\033[93m[WARNING]\033[0m Cross-encoder not loaded")
                print(f"   Configured model: {vector_db.cross_encoder_name}")
            else:
                print("\033[94m[INFO]\033[0m Cross-encoder not configured")

            return True
        else:
            print("\033[91m[ERROR]\033[0m Embedding model initialization failed")
            return False

    except Exception as e:
        print(f"\033[91m[ERROR]\033[0m Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_vector_search(query: str, top_k: int = 3, search_mode: str = "vector"):
    """测试向量搜索功能"""
    print("\033[94m[INFO]\033[0m Testing vector search functionality...")
    print("-" * 50)
    print(f"\033[96m[QUERY]\033[0m Query: '{query}'")
    print(f"\033[96m[PARAM]\033[0m Top-K: {top_k}")
    print(f"\033[96m[PARAM]\033[0m Search mode: {search_mode}")
    print()

    try:
        # 配置
        config = {
            'knowledge_base': {
                'vector_db': {
                    'type': 'chromadb',
                    'collection': 'llm_native_knowledge',
                    'persist_directory': str(project_root / 'data' / 'chromadb')
                }
            },
            'paths': {
                'knowledge_dir': str(project_root / 'data' / 'knowledge'),
                'models_dir': str(project_root / 'pretrained_models')
            }
        }

        print("\033[94m[INFO]\033[0m Initializing knowledge base manager...")
        kb = KnowledgeBaseManager(config)

        # 检查知识库状态
        stats = kb.get_stats()
        if stats:
            print("\033[96m[STATS]\033[0m Knowledge base status:")
            print(f"   Total entries: {stats.total_entries}")
            print(f"   Vector database status: {stats.vector_db_status}")
            print(f"   Entries by category: {stats.entries_by_category}")
            print()

        # 执行搜索
        print("\033[94m[INFO]\033[0m Executing vector search...")
        start_time = time.time()

        results = kb.search(query, top_k=top_k, search_mode=search_mode)

        search_time = time.time() - start_time
        print(f"\033[92m[SUCCESS]\033[0m Search completed in {search_time:.3f} seconds")
        print()

        # 显示搜索参数详情
        print("\033[96m[PARAM]\033[0m Search parameter details:")
        print(f"   Query: '{query}'")
        print(f"   Search mode: {search_mode}")
        print(f"   Requested results: {top_k}")
        print(f"   Actual results: {len(results)}")
        print(f"   Search time: {search_time:.3f} seconds")
        print()

        # 显示详细结果
        if results:
            print("\033[96m[RESULTS]\033[0m Search results details:")
            print("-" * 60)

            for i, result in enumerate(results, 1):
                print(f"\033[92m[RESULT {i}]\033[0m:")
                print(f"   Score: {result.score:.4f}")
                print(f"   Title: {result.entry.title}")
                print(f"   Category: {result.entry.category}")
                print(f"   Framework: {result.entry.framework}")
                print(f"   Language: {result.entry.language}")
                print(f"   ID: {result.entry.id}")

                # 显示元数据
                if result.entry.metadata:
                    print("   Metadata:")
                    for key, value in result.entry.metadata.items():
                        print(f"      {key}: {value}")

                # 显示内容预览（前200字符）
                content_preview = result.entry.content[:200]
                if len(result.entry.content) > 200:
                    content_preview += "..."
                print(f"   Content preview: {content_preview}")
                print()

        else:
            print("\033[91m[ERROR]\033[0m No relevant results found")
            print("\033[93m[SUGGESTIONS]\033[0m Please check:")
            print("   1. Whether knowledge base data has been properly imported")
            print("   2. Whether query is too specific")
            print("   3. Try using more general keywords")

        # 性能统计
        print("\033[96m[PERF]\033[0m Performance statistics:")
        print(f"   Search time: {search_time:.3f} seconds")
        if results:
            qps = 1.0 / search_time if search_time > 0 else float('inf')
            avg_score = sum(r.score for r in results) / len(results)
            print(f"   QPS: {qps:.2f}")
            print(f"   Average score: {avg_score:.4f}")

        return True

    except Exception as e:
        print(f"\033[91m[ERROR]\033[0m Search test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def run_full_test(search_query: str = "buffer overflow detection", top_k: int = 3):
    """运行完整的测试套件"""
    print("\033[94m[INFO]\033[0m Running full test suite")
    print("=" * 60)

    results = {}

    # 1. 测试嵌入模型
    print("\n" + "="*50)
    print("\033[96m[STEP 1]\033[0m Embedding model test")
    results['embedding'] = test_embedding_models()

    # 2. 测试向量搜索
    print("\n" + "="*50)
    print("\033[96m[STEP 2]\033[0m Vector search test")
    results['search'] = test_vector_search(search_query, top_k, "vector")

    # 3. 总结报告
    print("\n" + "="*60)
    print("\033[96m[SUMMARY]\033[0m Test results:")
    embedding_result = "\033[92mPASSED\033[0m" if results['embedding'] else "\033[91mFAILED\033[0m"
    search_result = "\033[92mPASSED\033[0m" if results['search'] else "\033[91mFAILED\033[0m"
    print(f"   Embedding model test: {embedding_result}")
    print(f"   Vector search test: {search_result}")

    all_passed = all(results.values())

    if all_passed:
        print("\n\033[92m[SUCCESS]\033[0m All tests passed!")
        print("\033[92m[SUCCESS]\033[0m Embedding model functionality normal")
        print("\033[92m[SUCCESS]\033[0m Vector search functionality normal")
        print("\033[92m[SUCCESS]\033[0m Knowledge base system running well")
        print("\n\033[94m[READY]\033[0m Knowledge base subsystem is ready!")
    else:
        print("\n\033[93m[WARNING]\033[0m Some tests failed, please check related configuration")

    return all_passed

def main():
    """主函数"""
    parser = argparse.ArgumentParser(
        description='LLM-Native知识库综合测试工具',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  python scripts/test_knowledge_base.py embedding                    # 测试嵌入模型
  python scripts/test_knowledge_base.py search "buffer overflow"     # 测试搜索
  python scripts/test_knowledge_base.py full                         # 运行所有测试

搜索模式选项 (--search-mode):
  vector   - 纯向量相似度搜索
  hybrid   - 向量+关键词混合搜索
  advanced - 混合搜索+重排序
  text     - 纯文本关键词搜索

完整示例:
  python scripts/test_knowledge_base.py search "Clang checker" --top-k 5 --search-mode hybrid
  python scripts/test_knowledge_base.py full --query "memory leak" --top-k 3
        """
    )

    parser.add_argument('mode', choices=['embedding', 'search', 'full'],
                       help='测试模式：embedding（嵌入模型）, search（向量搜索）, full（完整测试）')

    parser.add_argument('query', nargs='?', default='buffer overflow detection',
                       help='搜索查询内容（仅在search和full模式下使用）')

    parser.add_argument('--top-k', type=int, default=3,
                       help='返回结果数量（默认: 3）')

    parser.add_argument('--search-mode', choices=['vector', 'hybrid', 'advanced', 'text'],
                       default='vector', help='搜索模式（默认: vector）')

    args = parser.parse_args()

    print("\033[94m[INFO]\033[0m LLM-Native Knowledge Base Comprehensive Test Tool")
    print("=" * 60)

    success = False

    if args.mode == 'embedding':
        # 仅测试嵌入模型
        success = test_embedding_models()

    elif args.mode == 'search':
        # 仅测试向量搜索
        success = test_vector_search(args.query, args.top_k, args.search_mode)

    elif args.mode == 'full':
        # 运行完整测试
        success = run_full_test(args.query, args.top_k)

    print("\n" + "=" * 60)
    if success:
        print("\033[92m[SUCCESS]\033[0m Test completed")
    else:
        print("\033[91m[ERROR]\033[0m Test failed")

    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())
