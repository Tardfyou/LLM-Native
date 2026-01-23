"""
Knowledge Base Data Sources
知识库数据源处理器

负责从各种来源收集和处理知识库数据：
1. 框架API文档 (Clang/LLVM, CodeQL)
2. 代码示例和查询模板
3. CWE漏洞模式描述
4. 专家知识和最佳实践
"""

from typing import Dict, Any, List, Optional, Tuple
from pathlib import Path
from dataclasses import dataclass
import json
import re
from urllib.request import urlopen
from urllib.error import URLError
import logging

import logging
logger = logging.getLogger(__name__)
from bs4 import BeautifulSoup

from .models import KnowledgeEntry, DataSourceConfig


class DataSourceProcessor:
    """数据源处理器"""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.data_sources = self._initialize_data_sources()

    def _initialize_data_sources(self) -> List[DataSourceConfig]:
        """初始化数据源配置"""
        sources = []

        # Clang/LLVM API文档
        sources.append(DataSourceConfig(
            name="clang_api_docs",
            type="api_docs",
            framework="clang",
            language="cpp",
            source_url="https://clang.llvm.org/docs/",
            local_path=Path("data/knowledge/clang")
        ))

        # CodeQL API文档和示例
        sources.append(DataSourceConfig(
            name="codeql_api_docs",
            type="api_docs",
            framework="codeql",
            language="cpp",
            source_url="https://codeql.github.com/docs/",
            local_path=Path("data/knowledge/codeql")
        ))

        # CWE漏洞模式库
        sources.append(DataSourceConfig(
            name="cwe_patterns",
            type="cwe_patterns",
            framework="general",
            language="general",
            source_url="https://cwe.mitre.org/data/definitions/",
            local_path=Path("data/knowledge/cwe")
        ))

        # 专家知识和最佳实践
        sources.append(DataSourceConfig(
            name="expert_knowledge",
            type="expert_knowledge",
            framework="general",
            language="general",
            local_path=Path("data/knowledge/expert")
        ))

        return sources

    def collect_all_sources(self) -> List[KnowledgeEntry]:
        """
        从所有数据源收集知识条目

        Returns:
            知识条目列表
        """
        all_entries = []

        for source in self.data_sources:
            if source.enabled:
                try:
                    logger.info(f"Collecting from data source: {source.name}")
                    entries = self._collect_from_source(source)
                    all_entries.extend(entries)
                    logger.info(f"Collected {len(entries)} entries from {source.name}")
                except Exception as e:
                    logger.error(f"Failed to collect from {source.name}: {e}")

        return all_entries

    def _collect_from_source(self, source: DataSourceConfig) -> List[KnowledgeEntry]:
        """从特定数据源收集知识"""
        if source.type == "api_docs":
            return self._collect_api_docs(source)
        elif source.type == "code_examples":
            return self._collect_code_examples(source)
        elif source.type == "cwe_patterns":
            return self._collect_cwe_patterns(source)
        elif source.type == "expert_knowledge":
            return self._collect_expert_knowledge(source)
        else:
            logger.warning(f"Unknown data source type: {source.type}")
            return []

    def _collect_api_docs(self, source: DataSourceConfig) -> List[KnowledgeEntry]:
        """收集API文档"""
        entries = []

        try:
            # 尝试从本地文件收集
            if source.local_path and source.local_path.exists():
                entries.extend(self._parse_local_api_docs(source))

            # 尝试从网络收集（如果配置了URL）
            if source.source_url:
                entries.extend(self._scrape_api_docs(source))

        except Exception as e:
            logger.error(f"Failed to collect API docs from {source.name}: {e}")

        return entries

    def _parse_local_api_docs(self, source: DataSourceConfig) -> List[KnowledgeEntry]:
        """解析本地API文档"""
        entries = []

        if not source.local_path.exists():
            return entries

        # 递归查找文档文件
        for file_path in source.local_path.rglob("*.md"):
            try:
                content = file_path.read_text(encoding='utf-8')
                title = self._extract_title_from_content(content)

                entry = KnowledgeEntry(
                    id="",
                    content=content,
                    title=title,
                    category="framework_docs",
                    framework=source.framework,
                    language=source.language,
                    metadata={
                        "file_path": str(file_path),
                        "source_type": "local_file",
                        "tags": self._extract_tags_from_content(content)
                    }
                )
                entries.append(entry)

            except Exception as e:
                logger.warning(f"Failed to parse {file_path}: {e}")

        return entries

    def _scrape_api_docs(self, source: DataSourceConfig) -> List[KnowledgeEntry]:
        """从网络抓取API文档"""
        entries = []

        try:
            if not source.source_url:
                return entries

            # 这里应该实现网页抓取逻辑
            # 由于网络限制，这里只返回示例
            logger.info(f"Web scraping not implemented for {source.name}")
            # TODO: 实现网页抓取和解析

        except Exception as e:
            logger.error(f"Failed to scrape API docs from {source.source_url}: {e}")

        return entries

    def _collect_code_examples(self, source: DataSourceConfig) -> List[KnowledgeEntry]:
        """收集代码示例"""
        entries = []

        try:
            if not source.local_path or not source.local_path.exists():
                return entries

            # 查找代码文件
            for file_path in source.local_path.rglob("*"):
                if file_path.suffix in ['.cpp', '.java', '.py', '.ql']:
                    try:
                        content = file_path.read_text(encoding='utf-8')

                        # 提取代码块和注释
                        code_blocks = self._extract_code_blocks(content)
                        comments = self._extract_comments(content, file_path.suffix)

                        for i, (code_block, comment) in enumerate(zip(code_blocks, comments)):
                            entry = KnowledgeEntry(
                                id="",
                                content=f"{comment}\n\n``` {file_path.suffix[1:]}\n{code_block}\n```",
                                title=f"Code Example: {file_path.stem} ({i+1})",
                                category="code_examples",
                                framework=source.framework,
                                language=source.language,
                                metadata={
                                    "file_path": str(file_path),
                                    "code_type": file_path.suffix[1:],
                                    "source_type": "code_example",
                                    "tags": ["example", "code"]
                                }
                            )
                            entries.append(entry)

                    except Exception as e:
                        logger.warning(f"Failed to parse code file {file_path}: {e}")

        except Exception as e:
            logger.error(f"Failed to collect code examples from {source.name}: {e}")

        return entries

    def _collect_cwe_patterns(self, source: DataSourceConfig) -> List[KnowledgeEntry]:
        """收集CWE漏洞模式"""
        entries = []

        try:
            # 从MITRE CWE数据库收集
            cwe_data = self._fetch_cwe_data()

            for cwe_id, cwe_info in cwe_data.items():
                entry = KnowledgeEntry(
                    id="",
                    content=f"CWE-{cwe_id}: {cwe_info.get('name', '')}\n\nDescription: {cwe_info.get('description', '')}\n\nExtended Description: {cwe_info.get('extended_description', '')}",
                    title=f"CWE-{cwe_id}: {cwe_info.get('name', '')}",
                    category="cwe_patterns",
                    framework="general",
                    language="general",
                    metadata={
                        "cwe_id": cwe_id,
                        "severity": cwe_info.get('severity', 'Unknown'),
                        "source_type": "cwe_database",
                        "tags": ["vulnerability", "cwe", cwe_info.get('weakness_type', '')]
                    }
                )
                entries.append(entry)

        except Exception as e:
            logger.error(f"Failed to collect CWE patterns: {e}")

        return entries

    def _collect_expert_knowledge(self, source: DataSourceConfig) -> List[KnowledgeEntry]:
        """收集专家知识"""
        entries = []

        try:
            if not source.local_path or not source.local_path.exists():
                return entries

            # 读取专家知识文件
            for file_path in source.local_path.rglob("*.md"):
                try:
                    content = file_path.read_text(encoding='utf-8')
                    title = self._extract_title_from_content(content)

                    entry = KnowledgeEntry(
                        id="",
                        content=content,
                        title=title,
                        category="expert_knowledge",
                        framework="general",
                        language="general",
                        metadata={
                            "file_path": str(file_path),
                            "source_type": "expert_knowledge",
                            "tags": self._extract_tags_from_content(content) + ["expert", "best_practice"]
                        }
                    )
                    entries.append(entry)

                except Exception as e:
                    logger.warning(f"Failed to parse expert knowledge file {file_path}: {e}")

        except Exception as e:
            logger.error(f"Failed to collect expert knowledge: {e}")

        return entries

    def _fetch_cwe_data(self) -> Dict[str, Dict[str, Any]]:
        """获取CWE数据"""
        # 这里应该实现从MITRE CWE API或本地缓存获取数据
        # 为了演示，返回一些示例数据
        return {
            "119": {
                "name": "Improper Restriction of Operations within the Bounds of a Memory Buffer",
                "description": "The software performs operations on a memory buffer, but it can read from or write to a memory location that is outside of the intended boundary of the buffer.",
                "severity": "High",
                "weakness_type": "buffer_overflow"
            },
            "125": {
                "name": "Out-of-bounds Read",
                "description": "The software reads data past the end, or before the beginning, of the intended buffer.",
                "severity": "High",
                "weakness_type": "buffer_overflow"
            },
            "416": {
                "name": "Use After Free",
                "description": "Referencing memory after it has been freed can cause a program to crash or lead to exploitation.",
                "severity": "High",
                "weakness_type": "memory_management"
            }
        }

    def _extract_title_from_content(self, content: str) -> str:
        """从内容中提取标题"""
        lines = content.strip().split('\n')
        for line in lines[:5]:  # 检查前5行
            line = line.strip()
            if line.startswith('# '):
                return line[2:].strip()
        return "Untitled Document"

    def _extract_tags_from_content(self, content: str) -> List[str]:
        """从内容中提取标签"""
        tags = []
        # 查找常见的标签模式
        tag_patterns = [
            r'#(\w+)',
            r'@(\w+)',
            r'标签[:\s]*([^\n\r]+)',
            r'tags[:\s]*([^\n\r]+)'
        ]

        for pattern in tag_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            tags.extend([match.strip() for match in matches])

        return list(set(tags))  # 去重

    def _extract_code_blocks(self, content: str) -> List[str]:
        """提取代码块"""
        # 简单的代码块提取（可以根据需要改进）
        code_blocks = []
        lines = content.split('\n')
        in_code_block = False
        current_block = []

        for line in lines:
            if line.strip().startswith('```'):
                if in_code_block:
                    code_blocks.append('\n'.join(current_block))
                    current_block = []
                in_code_block = not in_code_block
            elif in_code_block:
                current_block.append(line)

        return code_blocks

    def _extract_comments(self, content: str, file_extension: str) -> List[str]:
        """提取注释"""
        comments = []

        if file_extension in ['.cpp', '.java']:
            # C/C++/Java风格注释
            comment_pattern = r'/\*.*?\*/|//.*?$'
            matches = re.findall(comment_pattern, content, re.MULTILINE | re.DOTALL)
            comments.extend([match.strip() for match in matches])
        elif file_extension == '.py':
            # Python风格注释
            comment_pattern = r'#.*?$'
            matches = re.findall(comment_pattern, content, re.MULTILINE)
            comments.extend([match.strip() for match in matches])
        elif file_extension == '.ql':
            # CodeQL风格注释
            comment_pattern = r'/\*.*?\*/|//.*?$'
            matches = re.findall(comment_pattern, content, re.MULTILINE | re.DOTALL)
            comments.extend([match.strip() for match in matches])

        return comments

    def create_initial_knowledge_base(self) -> List[KnowledgeEntry]:
        """
        创建初始知识库

        Returns:
            初始知识条目列表
        """
        logger.info("Creating initial knowledge base...")

        # 收集所有数据源
        entries = self.collect_all_sources()

        # 如果没有收集到数据，创建一些基础示例
        if not entries:
            entries = self._create_sample_entries()

        logger.info(f"Created initial knowledge base with {len(entries)} entries")
        return entries

    def _create_sample_entries(self) -> List[KnowledgeEntry]:
        """创建示例知识条目"""
        entries = []

        # Clang Static Analyzer示例
        clang_checker_example = KnowledgeEntry(
            id="clang_checker_example_001",
            content="""
# Clang Static Analyzer Checker Example

This example shows how to create a basic checker for detecting null pointer dereferences.

## Key Components:

1. **Checker Class**: Inherits from `Checker<check::PreStmt<UnaryOperator>>`
2. **checkPreStmt Method**: Called before each unary operator statement
3. **Bug Reporting**: Uses `BugReporter` to report issues

## Code Example:

```cpp
class MyChecker : public Checker<check::PreStmt<UnaryOperator>> {
private:
  const BugType BT{this, "Null pointer dereference"};

public:
  void checkPreStmt(const UnaryOperator *UO, CheckerContext &C) const {
    // Implementation here
  }
};
```

## Registration:

```cpp
void ento::registerMyChecker(CheckerManager &mgr) {
  mgr.registerChecker<MyChecker>();
}
```
            """,
            title="Clang Static Analyzer Checker Development Guide",
            category="framework_docs",
            framework="clang",
            language="cpp",
            metadata={
                "difficulty": "intermediate",
                "tags": ["clang", "static_analysis", "checker", "tutorial"],
                "source_type": "documentation"
            }
        )
        entries.append(clang_checker_example)

        # CodeQL示例
        codeql_query_example = KnowledgeEntry(
            id="codeql_query_example_001",
            content="""
# CodeQL Query Example: Buffer Overflow Detection

This query detects potential buffer overflow vulnerabilities in C/C++ code.

## Query Structure:

```ql
/**
 * @name Buffer overflow
 * @description Buffer write operations that may overflow
 * @kind path-problem
 */

import cpp
import semmle.code.cpp.dataflow.DataFlow
import semmle.code.cpp.commons.Buffer

// Define sources: functions that return potentially unsafe data
predicate isSource(DataFlow::Node source) {
  exists(FunctionCall fc |
    fc.getTarget().getName() = "gets" or
    fc.getTarget().getName() = "strcpy"
    // Add more sources...
  )
}

// Define sinks: buffer operations that may overflow
predicate isSink(DataFlow::Node sink) {
  exists(FunctionCall fc, string name |
    name = fc.getTarget().getName() and
    (name = "memcpy" or name = "strncpy" or name = "sprintf") and
    sink.asExpr() = fc.getArgument(0)
  )
}

// Define sanitizers: bounds checking operations
predicate isSanitizer(DataFlow::Node node) {
  // Implementation for bounds checking
  none() // Placeholder
}

module BufferOverflowConfig implements DataFlow::ConfigSig {
  predicate isSource = isSource/1;
  predicate isSink = isSink/1;
  predicate isBarrier = isSanitizer/1;
}

module BufferOverflowFlow = DataFlow::Global<BufferOverflowConfig>;

from BufferOverflowFlow::PathNode source, BufferOverflowFlow::PathNode sink
where BufferOverflowFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Buffer overflow due to flow from $@ to $@", source, "source", sink, "sink"
```
            """,
            title="CodeQL Buffer Overflow Detection Query",
            category="code_examples",
            framework="codeql",
            language="cpp",
            metadata={
                "cwe_id": "119",
                "tags": ["codeql", "buffer_overflow", "dataflow", "security"],
                "source_type": "example"
            }
        )
        entries.append(codeql_query_example)

        return entries
