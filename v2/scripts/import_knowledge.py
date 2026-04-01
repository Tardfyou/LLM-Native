#!/usr/bin/env python3
"""
import_knowledge.py - 导入知识库数据到 ChromaDB

功能:
1. 清空现有知识库
2. 导入 CSA (Clang Static Analyzer) 知识
   - CWE 漏洞模式
   - Clang API 规则
   - 检测器示例
3. 导入 CodeQL 知识
   - QL 示例
   - QL 模式
4. 导入共享知识
   - 分析器比较
5. 验证导入结果

用法:
    python scripts/import_knowledge.py              # 完整导入
    python scripts/import_knowledge.py --clear-only # 仅清空
    python scripts/import_knowledge.py --validate   # 仅验证
    python scripts/import_knowledge.py --csa-only   # 仅导入CSA
    python scripts/import_knowledge.py --codeql-only # 仅导入CodeQL
"""

import argparse
import json
import sys
from pathlib import Path
from datetime import datetime
from typing import Iterable, Optional, Set

# 添加项目根目录到路径
PROJECT_DIR = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_DIR))

# 知识库目录
KNOWLEDGE_DIR = PROJECT_DIR / "data" / "knowledge"

DOCUMENT_KEYS = {
    "id",
    "title",
    "name",
    "description",
    "category",
    "patterns",
    "vulnerable_code",
    "fixed_code",
    "checker_hints",
    "code",
    "template",
    "pattern_type",
    "applicable_vulnerabilities",
    "wrong_pattern",
    "correct_pattern",
    "notes",
    "tags",
    "pros",
    "cons",
    "use_cases",
}

MANAGED_COLLECTIONS = {
    "checker_cwe_patterns",
    "checker_api_rules",
    "checker_examples",
    "codeql_examples",
    "codeql_patterns",
    "analyzer_comparison",
    "shared_cwe_catalog",
    "checker_knowledge",
}

CSA_MANAGED_COLLECTIONS = {
    "checker_cwe_patterns",
    "checker_api_rules",
    "checker_examples",
}

CODEQL_MANAGED_COLLECTIONS = {
    "codeql_examples",
    "codeql_patterns",
}


def _looks_like_single_document(raw_data) -> bool:
    """判断顶层 dict 是否本身就是一条文档。"""
    return isinstance(raw_data, dict) and any(key in raw_data for key in DOCUMENT_KEYS)


def _coerce_record(item, fallback_id: str):
    """将任意 JSON 项转换为文档记录。"""
    if isinstance(item, dict):
        record = item.copy()
        record.setdefault("id", fallback_id)
        return record

    return {
        "id": fallback_id,
        "name": fallback_id,
        "value": item,
    }


def _normalize_records(raw_data, doc_type: str):
    """把不同结构的 JSON 统一转换为文档记录列表。"""
    if isinstance(raw_data, list):
        return [_coerce_record(item, f"{doc_type}_doc_{i}") for i, item in enumerate(raw_data)]

    if isinstance(raw_data, dict):
        if _looks_like_single_document(raw_data):
            return [_coerce_record(raw_data, raw_data.get("id", f"{doc_type}_doc_0"))]

        records = []
        for key, value in raw_data.items():
            if isinstance(value, dict):
                record = value.copy()
                record.setdefault("id", key)
                record.setdefault("name", record.get("title", key) if isinstance(record.get("title"), str) else key)
            elif isinstance(value, list):
                record = {
                    "id": key,
                    "name": key,
                    "items": value,
                }
            else:
                record = {
                    "id": key,
                    "name": key,
                    "value": value,
                }
            records.append(record)
        return records

    raise TypeError(f"不支持的JSON格式: {type(raw_data)}")


def _render_list_items(items) -> str:
    """将列表转换为 Markdown 列表。"""
    lines = []
    for item in items:
        if isinstance(item, dict):
            label = (
                item.get("dimension")
                or item.get("scenario")
                or item.get("vulnerability")
                or item.get("name")
                or item.get("id")
            )
            if label:
                details = []
                for key, value in item.items():
                    if key in {"dimension", "scenario", "vulnerability", "name", "id"}:
                        continue
                    if value in (None, "", [], {}):
                        continue
                    if isinstance(value, list):
                        rendered = ", ".join(str(v) for v in value)
                    elif isinstance(value, dict):
                        rendered = json.dumps(value, ensure_ascii=False, sort_keys=True)
                    else:
                        rendered = str(value)
                    details.append(f"{key}={rendered}")
                if details:
                    lines.append(f"- {label}: {'; '.join(details)}")
                else:
                    lines.append(f"- {label}")
            else:
                lines.append(f"- {json.dumps(item, ensure_ascii=False, sort_keys=True)}")
        else:
            lines.append(f"- {item}")
    return "\n".join(lines)


def _render_extra_field(field_name: str, value) -> str:
    """把未显式建模的字段也写入文档，避免共享知识被丢失。"""
    if value in (None, "", [], {}):
        return ""

    title = field_name.replace("_", " ").strip().title()
    if isinstance(value, list):
        return f"\n## {title}\n{_render_list_items(value)}"
    if isinstance(value, dict):
        rendered = json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True)
        return f"\n## {title}\n```json\n{rendered}\n```"
    return f"\n## {title}\n{value}"


def _build_document(item, json_path: str, doc_type: str):
    """构建文档内容和元数据。"""
    item_id = item.get("id")
    content_parts = []
    consumed_fields = {
        "id",
        "title",
        "name",
        "description",
        "patterns",
        "vulnerable_code",
        "fixed_code",
        "checker_hints",
        "code",
        "template",
        "pattern_type",
        "applicable_vulnerabilities",
        "wrong_pattern",
        "correct_pattern",
        "notes",
        "tags",
        "pros",
        "cons",
        "use_cases",
        "category",
    }

    if "title" in item:
        content_parts.append(f"# {item['title']}")
    if "name" in item:
        content_parts.append(f"# {item['name']}")
    if "description" in item:
        content_parts.append(f"\n{item['description']}")

    if "patterns" in item:
        content_parts.append(f"\n## 模式\n" + "\n".join(f"- {p}" for p in item["patterns"]))
    if "vulnerable_code" in item:
        content_parts.append(f"\n## 漏洞代码\n```cpp\n{item['vulnerable_code']}\n```")
    if "fixed_code" in item:
        content_parts.append(f"\n## 修复代码\n```cpp\n{item['fixed_code']}\n```")
    if "checker_hints" in item:
        content_parts.append(f"\n## 检测器提示\n" + "\n".join(f"- {h}" for h in item["checker_hints"]))

    if "code" in item:
        lang = "ql" if doc_type == "codeql" else "cpp"
        content_parts.append(f"\n## 代码\n```{lang}\n{item['code']}\n```")
    if "template" in item:
        content_parts.append(f"\n## 模板\n```ql\n{item['template']}\n```")
    if "pattern_type" in item:
        content_parts.append(f"\n## 模式类型: {item['pattern_type']}")
    if "applicable_vulnerabilities" in item:
        content_parts.append(f"\n## 适用漏洞: {', '.join(item['applicable_vulnerabilities'])}")

    if "wrong_pattern" in item:
        content_parts.append(f"\n## 错误写法\n```cpp\n{item['wrong_pattern']}\n```")
    if "correct_pattern" in item:
        content_parts.append(f"\n## 正确写法\n```cpp\n{item['correct_pattern']}\n```")
    if "notes" in item:
        content_parts.append(f"\n## 注意事项\n" + "\n".join(f"- {n}" for n in item["notes"]))

    if "tags" in item:
        content_parts.append(f"\n## 标签\n{', '.join(item['tags'])}")

    if "pros" in item:
        content_parts.append(f"\n## 优点\n" + "\n".join(f"- {p}" for p in item["pros"]))
    if "cons" in item:
        content_parts.append(f"\n## 缺点\n" + "\n".join(f"- {c}" for c in item["cons"]))
    if "use_cases" in item:
        content_parts.append(f"\n## 适用场景\n" + "\n".join(f"- {u}" for u in item["use_cases"]))

    for field_name, value in item.items():
        if field_name in consumed_fields:
            continue
        extra = _render_extra_field(field_name, value)
        if extra:
            content_parts.append(extra)

    document = "\n".join(part for part in content_parts if part)
    metadata = {
        "source": Path(json_path).stem,
        "doc_type": doc_type,
        "imported_at": datetime.now().isoformat()
    }
    if "category" in item:
        metadata["category"] = item["category"]
    if "tags" in item:
        metadata["tags"] = ",".join(item["tags"])
    if "pattern_type" in item:
        metadata["pattern_type"] = item["pattern_type"]

    return item_id, document, metadata


def _normalize_collection_targets(collection_names: Optional[Iterable[str]]) -> Optional[Set[str]]:
    if collection_names is None:
        return None
    if isinstance(collection_names, str):
        names = {collection_names}
    else:
        names = {str(name) for name in collection_names if name}
    return names or None


def _delete_unified_entries_for_collections(client, collection_names: Set[str]) -> None:
    """只删除 unified 集合中属于指定源集合的文档。"""
    try:
        unified = client.get_collection("checker_knowledge")
    except Exception:
        return

    total = unified.count()
    if total == 0:
        return

    try:
        payload = unified.get(limit=total, include=[])
    except Exception as e:
        print(f"  ! 读取 unified 集合失败，跳过定向清理: {e}")
        return

    ids = payload.get("ids", []) if payload else []
    to_delete = [
        doc_id
        for doc_id in ids
        if any(str(doc_id).startswith(f"{name}:") for name in collection_names)
    ]
    if not to_delete:
        return

    unified.delete(ids=to_delete)
    print(f"  删除 unified 条目: checker_knowledge ({len(to_delete)} 条)")


def clear_knowledge_base(collection_names: Optional[Iterable[str]] = None) -> bool:
    """清空知识库"""
    print("\n" + "=" * 50)
    print("清空知识库")
    print("=" * 50)

    try:
        import chromadb
        client = chromadb.HttpClient(host="localhost", port=8001)

        # 获取所有集合
        collections = client.list_collections()
        print(f"现有集合数: {len(collections)}")

        target_names = _normalize_collection_targets(collection_names)

        for coll in collections:
            # 只清空 checker 相关的集合
            if target_names and coll.name not in target_names:
                continue

            if coll.name in MANAGED_COLLECTIONS:
                print(f"  删除集合: {coll.name} ({coll.count()} 条)")
                client.delete_collection(coll.name)
            else:
                print(f"  保留集合: {coll.name}")

        if target_names:
            _delete_unified_entries_for_collections(client, target_names)

        print("✓ 知识库已清空")
        return True

    except Exception as e:
        print(f"✗ 清空失败: {e}")
        return False


def import_json_data(json_path: str, collection_name: str, doc_type: str = "csa") -> int:
    """
    导入 JSON 数据到知识库

    Args:
        json_path: JSON 文件路径
        collection_name: 集合名称
        doc_type: 文档类型 (csa/codeql/shared)

    Returns:
        导入的文档数量
    """
    print(f"\n导入 {Path(json_path).name} -> {collection_name}")

    try:
        import chromadb

        # 读取 JSON 数据
        with open(json_path, 'r', encoding='utf-8') as f:
            raw_data = json.load(f)

        if not raw_data:
            print("  数据为空，跳过")
            return 0

        data = _normalize_records(raw_data, doc_type)

        # 连接 ChromaDB
        client = chromadb.HttpClient(host="localhost", port=8001)

        # 创建或获取集合
        try:
            collection = client.get_collection(collection_name)
            print(f"  使用现有集合: {collection_name} ({collection.count()} 条)")
        except:
            collection = client.create_collection(
                name=collection_name,
                metadata={"hnsw:space": "cosine", "doc_type": doc_type}
            )
            print(f"  创建新集合: {collection_name}")

        # 准备导入数据
        ids = []
        documents = []
        metadatas = []

        for i, item in enumerate(data):
            if "id" not in item:
                item["id"] = f"{doc_type}_doc_{i}"
            item_id, document, metadata = _build_document(item, json_path, doc_type)
            ids.append(item_id)
            documents.append(document)
            metadatas.append(metadata)

        # 导入数据
        collection.add(
            ids=ids,
            documents=documents,
            metadatas=metadatas
        )

        # 同步导入统一集合 checker_knowledge，便于通用检索与状态展示
        try:
            unified = client.get_or_create_collection(
                name="checker_knowledge",
                metadata={"hnsw:space": "cosine", "doc_type": "unified"}
            )
            unified_ids = [f"{collection_name}:{i}" for i in ids]
            unified.add(
                ids=unified_ids,
                documents=documents,
                metadatas=metadatas
            )
        except Exception as e:
            print(f"  ! unified collection 写入失败(不影响主流程): {e}")

        print(f"  ✓ 导入 {len(documents)} 条文档")
        return len(documents)

    except Exception as e:
        print(f"  ✗ 导入失败: {e}")
        import traceback
        traceback.print_exc()
        return 0


def validate_knowledge_base() -> bool:
    """验证知识库数据"""
    print("\n" + "=" * 50)
    print("验证知识库")
    print("=" * 50)

    try:
        import chromadb
        client = chromadb.HttpClient(host="localhost", port=8001)

        collections = client.list_collections()
        print(f"集合总数: {len(collections)}")

        total_docs = 0
        for coll in collections:
            count = coll.count()
            total_docs += count
            doc_type = coll.metadata.get("doc_type", "unknown") if coll.metadata else "unknown"
            print(f"  - {coll.name}: {count} 条 (类型: {doc_type})")

            # 抽样检查
            if count > 0:
                sample = coll.get(limit=1, include=["documents", "metadatas"])
                if sample["documents"]:
                    preview = sample['documents'][0][:100].replace('\n', ' ')
                    print(f"    示例: {preview}...")

        print(f"\n总文档数: {total_docs}")
        return total_docs > 0

    except Exception as e:
        print(f"✗ 验证失败: {e}")
        return False


def import_csa_knowledge(data_dir: Path) -> int:
    """导入 CSA 知识"""
    print("\n" + "-" * 40)
    print("导入 CSA (Clang Static Analyzer) 知识")
    print("-" * 40)

    csa_dir = data_dir / "csa"
    total = 0

    # 导入 CWE 模式
    cwe_path = csa_dir / "cwe_patterns.json"
    if cwe_path.exists():
        count = import_json_data(str(cwe_path), "checker_cwe_patterns", "csa")
        total += count
    else:
        print(f"  文件不存在: {cwe_path}")

    # 导入 API 规则
    api_path = csa_dir / "clang_api_rules.json"
    if api_path.exists():
        count = import_json_data(str(api_path), "checker_api_rules", "csa")
        total += count
    else:
        print(f"  文件不存在: {api_path}")

    # 导入检测器示例
    examples_path = csa_dir / "checker_examples.json"
    if examples_path.exists():
        count = import_json_data(str(examples_path), "checker_examples", "csa")
        total += count
    else:
        print(f"  文件不存在: {examples_path}")

    return total


def import_codeql_knowledge(data_dir: Path) -> int:
    """导入 CodeQL 知识"""
    print("\n" + "-" * 40)
    print("导入 CodeQL 知识")
    print("-" * 40)

    codeql_dir = data_dir / "codeql"
    total = 0

    # 导入 QL 示例
    examples_path = codeql_dir / "ql_examples.json"
    if examples_path.exists():
        count = import_json_data(str(examples_path), "codeql_examples", "codeql")
        total += count
    else:
        print(f"  文件不存在: {examples_path}")

    # 导入 QL 模式
    patterns_path = codeql_dir / "ql_patterns.json"
    if patterns_path.exists():
        count = import_json_data(str(patterns_path), "codeql_patterns", "codeql")
        total += count
    else:
        print(f"  文件不存在: {patterns_path}")

    return total


def import_shared_knowledge(data_dir: Path) -> int:
    """导入共享知识"""
    print("\n" + "-" * 40)
    print("导入共享知识")
    print("-" * 40)

    shared_dir = data_dir / "shared"
    total = 0

    # 导入分析器比较
    comparison_path = shared_dir / "analyzer_comparison.json"
    if comparison_path.exists():
        count = import_json_data(str(comparison_path), "analyzer_comparison", "shared")
        total += count
    else:
        print(f"  文件不存在: {comparison_path}")

    # 导入统一 CWE 目录
    cwe_catalog_path = shared_dir / "cwe_catalog.json"
    if cwe_catalog_path.exists():
        count = import_json_data(str(cwe_catalog_path), "shared_cwe_catalog", "shared")
        total += count
    else:
        print(f"  文件不存在: {cwe_catalog_path}")

    return total


def main():
    parser = argparse.ArgumentParser(description="导入知识库数据")
    parser.add_argument(
        "--clear-only",
        action="store_true",
        help="仅清空知识库"
    )
    parser.add_argument(
        "--validate",
        action="store_true",
        help="仅验证知识库"
    )
    parser.add_argument(
        "--collection",
        default=None,
        help="指定要清空的集合名称"
    )
    parser.add_argument(
        "--csa-only",
        action="store_true",
        help="仅导入CSA知识"
    )
    parser.add_argument(
        "--codeql-only",
        action="store_true",
        help="仅导入CodeQL知识"
    )
    args = parser.parse_args()

    print("=" * 50)
    print("知识库数据导入工具 v2.0")
    print("=" * 50)
    print(f"项目目录: {PROJECT_DIR}")
    print(f"知识目录: {KNOWLEDGE_DIR}")

    # 仅验证模式
    if args.validate:
        success = validate_knowledge_base()
        return 0 if success else 1

    clear_targets: Optional[Set[str]] = None
    if args.collection:
        clear_targets = {args.collection}
    elif args.csa_only:
        clear_targets = set(CSA_MANAGED_COLLECTIONS)
    elif args.codeql_only:
        clear_targets = set(CODEQL_MANAGED_COLLECTIONS)

    # 清空知识库
    if not clear_knowledge_base(clear_targets):
        return 1

    # 仅清空模式
    if args.clear_only:
        return 0

    # 导入数据
    print("\n" + "=" * 50)
    print("导入数据")
    print("=" * 50)

    total_imported = 0

    # 根据参数选择导入内容
    if args.csa_only:
        total_imported += import_csa_knowledge(KNOWLEDGE_DIR)
    elif args.codeql_only:
        total_imported += import_codeql_knowledge(KNOWLEDGE_DIR)
    else:
        # 默认导入所有
        total_imported += import_csa_knowledge(KNOWLEDGE_DIR)
        total_imported += import_codeql_knowledge(KNOWLEDGE_DIR)
        total_imported += import_shared_knowledge(KNOWLEDGE_DIR)

    print(f"\n{'=' * 50}")
    print(f"✓ 共导入 {total_imported} 条文档")
    print("=" * 50)

    # 验证
    validate_knowledge_base()

    return 0


if __name__ == "__main__":
    sys.exit(main())
