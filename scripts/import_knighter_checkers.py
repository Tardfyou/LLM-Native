#!/usr/bin/env python3
"""
Import Knighter checker_database into LLM-Native knowledge base.

This script reads checker implementations from Knighter's checker_database
directory and imports them as knowledge entries for RAG-based retrieval.

Usage:
    python scripts/import_knighter_checkers.py
"""

import sys
import os
from pathlib import Path
from typing import List, Dict, Any
import hashlib
import re

# Add project path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root / 'src'))

from knowledge_base.manager import KnowledgeBaseManager
from knowledge_base.models import KnowledgeEntry


def extract_checker_info(checker_dir: Path) -> Dict[str, Any]:
    """Extract information from a Knighter checker directory."""
    checker_name = checker_dir.name

    # Read checker.cpp if exists
    checker_file = checker_dir / "checker.cpp"
    checker_code = ""
    if checker_file.exists():
        with open(checker_file, 'r', encoding='utf-8', errors='ignore') as f:
            checker_code = f.read()

    # Read pattern.md if exists
    pattern_file = checker_dir / "pattern.md"
    pattern_desc = ""
    if pattern_file.exists():
        with open(pattern_file, 'r', encoding='utf-8', errors='ignore') as f:
            pattern_desc = f.read()

    # Read plan.md if exists
    plan_file = checker_dir / "plan.md"
    plan_desc = ""
    if plan_file.exists():
        with open(plan_file, 'r', encoding='utf-8', errors='ignore') as f:
            plan_desc = f.read()

    # Read patch.md if exists
    patch_file = checker_dir / "patch.md"
    patch_desc = ""
    if patch_file.exists():
        with open(patch_file, 'r', encoding='utf-8', errors='ignore') as f:
            patch_desc = f.read()

    return {
        'checker_name': checker_name,
        'checker_code': checker_code,
        'pattern': pattern_desc,
        'plan': plan_desc,
        'patch': patch_desc
    }


def create_knowledge_entries(checker_info: Dict[str, Any]) -> List[KnowledgeEntry]:
    """Create knowledge entries from checker information."""
    entries = []
    checker_name = checker_info['checker_name']

    # 1. Create checker code entry
    if checker_info['checker_code']:
        # Extract checker class name
        class_match = re.search(r'class\s+(\w+)\s*:', checker_info['checker_code'])
        class_name = class_match.group(1) if class_match else checker_name

        # Extract brief description from comment
        desc_match = re.search(r'//\s*(.*?checker.*?[\.。])', checker_info['checker_code'], re.IGNORECASE)
        description = desc_match.group(1) if desc_match else f"Clang Static Analyzer checker for {checker_name}"

        # Determine callback types used
        callbacks = []
        for callback in ['check::Location', 'check::PreCall', 'check::PostCall',
                        'check::Bind', 'check::BranchCondition', 'check::PreStmt',
                        'check::PostStmt', 'check::BeginFunction', 'check::EndFunction',
                        'check::ASTCodeBody']:
            if callback in checker_info['checker_code']:
                callbacks.append(callback)

        code_entry = KnowledgeEntry(
            id=f"knighter_code_{checker_name}",
            content=checker_info['checker_code'],
            title=f"{class_name} - Knighter Checker Implementation",
            category="code_examples",
            framework="clang",
            language="cpp",
            metadata={
                "source": "knighter_checker_database",
                "checker_name": checker_name,
                "class_name": class_name,
                "description": description,
                "callbacks": callbacks,
                "file_type": "checker_implementation",
                "code_only": True
            }
        )
        entries.append(code_entry)

    # 2. Create pattern entry if available
    if checker_info['pattern']:
        pattern_entry = KnowledgeEntry(
            id=f"knighter_pattern_{checker_name}",
            content=checker_info['pattern'],
            title=f"{checker_name} - Vulnerability Pattern",
            category="cwe_patterns",
            framework="clang",
            language="cpp",
            metadata={
                "source": "knighter_checker_database",
                "checker_name": checker_name,
                "file_type": "pattern_description"
            }
        )
        entries.append(pattern_entry)

    # 3. Create plan entry if available
    if checker_info['plan']:
        plan_entry = KnowledgeEntry(
            id=f"knighter_plan_{checker_name}",
            content=checker_info['plan'],
            title=f"{checker_name} - Implementation Plan",
            category="expert_knowledge",
            framework="clang",
            language="cpp",
            metadata={
                "source": "knighter_checker_database",
                "checker_name": checker_name,
                "file_type": "implementation_plan"
            }
        )
        entries.append(plan_entry)

    # 4. Create combined entry for complete context
    combined_content = f"""## Checker: {checker_name}

### Pattern Description
{checker_info['pattern'] or 'No pattern description available.'}

### Implementation Plan
{checker_info['plan'] or 'No implementation plan available.'}

### Reference Patch
{checker_info['patch'] or 'No patch available.'}

### Checker Implementation
```cpp
{checker_info['checker_code'] or 'No code available.'}
```
"""

    combined_entry = KnowledgeEntry(
        id=f"knighter_complete_{checker_name}",
        content=combined_content,
        title=f"{checker_name} - Complete Knighter Example",
        category="code_examples",
        framework="clang",
        language="cpp",
        metadata={
            "source": "knighter_checker_database",
            "checker_name": checker_name,
            "file_type": "complete_example",
            "example_type": "complete_vulnerability_analysis",
            "includes": ["pattern", "plan", "patch", "checker"]
        }
    )
    entries.append(combined_entry)

    return entries


def import_knighter_checkers(knighter_path: Path, kb_manager: KnowledgeBaseManager) -> Dict[str, int]:
    """Import all checkers from Knighter database."""
    checker_db_path = knighter_path / "checker_database"

    if not checker_db_path.exists():
        print(f"Error: Knighter checker_database not found at {checker_db_path}")
        return {"success": 0, "failed": 0, "skipped": 0}

    print(f"Scanning Knighter checker_database at: {checker_db_path}")

    all_entries = []
    skipped = 0
    processed = 0

    # Iterate through all checker directories
    for checker_dir in sorted(checker_db_path.iterdir()):
        if not checker_dir.is_dir():
            continue

        checker_info = extract_checker_info(checker_dir)

        # Skip if no checker code
        if not checker_info['checker_code']:
            skipped += 1
            continue

        entries = create_knowledge_entries(checker_info)
        all_entries.extend(entries)
        processed += 1

        if processed % 10 == 0:
            print(f"  Processed {processed} checkers...")

    print(f"Found {processed} checkers with code, skipped {skipped} without code")
    print(f"Generated {len(all_entries)} knowledge entries")

    # Bulk import
    if all_entries:
        result = kb_manager.bulk_add_entries(all_entries)
        print(f"Import result: {result['success']} successful, {result['failed']} failed")

        return {
            "success": result['success'],
            "failed": result['failed'],
            "skipped": skipped,
            "total_checkers": processed
        }

    return {"success": 0, "failed": 0, "skipped": skipped}


def main():
    """Main function."""
    # Knighter path - check multiple locations
    possible_paths = [
        Path("/app/KNighter"),      # Container mount point
        Path("/home/spa/KNighter"), # Host path
        Path("../../../KNighter"),  # Relative path
        Path("../KNighter"),        # Another relative option
    ]

    knighter_path = None
    for p in possible_paths:
        if p.exists():
            knighter_path = p.resolve()  # Get absolute path
            break

    if not knighter_path:
        print(f"Error: Knighter directory not found!")
        print(f"Checked paths:")
        for p in possible_paths:
            print(f"  - {p.resolve()}")
        print()
        print("Please ensure Knighter is accessible or update the knighter_path in the script.")
        return 1

    # Initialize knowledge base
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

    kb = KnowledgeBaseManager(config)

    print("=" * 60)
    print("Importing Knighter Checker Database")
    print("=" * 60)
    print(f"Knighter path: {knighter_path}")
    print(f"Knowledge base: {len(kb.entries)} existing entries")
    print()

    # Import checkers
    result = import_knighter_checkers(knighter_path, kb)

    print()
    print("=" * 60)
    print("Import Summary")
    print("=" * 60)
    print(f"Total checkers processed: {result.get('total_checkers', 0)}")
    print(f"Successful entries: {result['success']}")
    print(f"Failed entries: {result['failed']}")
    print(f"Skipped checkers: {result['skipped']}")

    # Show updated stats
    stats = kb.get_stats()
    print()
    print("Updated Knowledge Base Stats:")
    print(f"  Total entries: {stats.total_entries}")
    print(f"  By category: {stats.entries_by_category}")
    print(f"  By framework: {stats.entries_by_framework}")

    print()
    print("✅ Knighter import complete!")

    return 0


if __name__ == "__main__":
    sys.exit(main())
