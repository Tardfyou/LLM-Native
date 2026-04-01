#!/usr/bin/env python3
"""
迁移知识库到新结构

将现有的知识库文件整理到正确的目录
"""

import json
import shutil
from pathlib import Path
from loguru import logger
from typing import List, Dict


def migrate_knowledge():
    """执行迁移"""
    base_dir = Path(__file__).parent.parent
    old_kb_dir = base_dir / "data" / "knowledge"
    new_kb_dir = base_dir / "data" + "knowledge_new"

    # 文件迁移映射
    migrations = [
        # CSA 相关文件
        ("checker_examples.json", "csa/checker_examples.json"),
        ("clang_api_rules.json", "csa/clang_api_rules.json"),
        ("cwe_patterns.json", "csa/cwe_patterns.json"),

        # CodeQL 相关文件
        ("codeql_examples.json", "codeql/codeql_examples.json"),
        ("ql_patterns.json", "codeql/ql_patterns.json"),

        # 共享文件
        ("analyzer_comparison.json", "shared/analyzer_comparison.json"),
    ]

    migrated = 0
    errors = []

    for src_name, dst_name in migrations:
        src_file = old_kb_dir / src_name
        dst_file = new_kb_dir / dst_name

        if not src_file.exists():
            logger.warning(f"源文件不存在: {src_file}")
            continue
        # 创建目标目录
        dst_file.parent.mkdir(parents=True, exist_ok=True)
        # 移动文件
        try:
            shutil.move(str(src_file), str(dst_file))
            migrated += 1
            logger.info(f"已迁移: {src_file} -> {dst_file}")
        except Exception as e:
            error = f"迁移失败 {src_file}: {e}"
            errors.append(error)
            logger.error(f"迁移失败 {src_file}: {e}")
    # 打印总结
    print("\n" + "=" * 60)
    print("知识库迁移完成")
    print("=" * 60)
    print(f"成功迁移: {migrated} 个文件")
    print(f"失败: {len(errors)} 个文件")
    if errors:
        print("\n错误详情:")
        for error in errors:
            print(f"  - {error}")
    print("\n新的知识库结构:")
    print("data/knowledge/")
    print("├── csa/")
    print("│   ├── checker_examples.json")
    print("│   ├── clang_api_rules.json")
    print("│   └── cwe_patterns.json")
    print("├── codeql/")
    print("│   ├── codeql_examples.json")
    print("│   └── ql_patterns.json")
    print("└── shared/")
    print("    └── analyzer_comparison.json")


if __name__ == "__main__":
    migrate_knowledge()
