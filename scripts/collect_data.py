#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LLM-Native 全面知识库数据收集器
从多个开源项目和数据源收集静态分析相关知识

自动收集的数据源：
1. KNighter项目 - Clang检查器数据库、prompt模板、示例、文档
2. IRIS项目 - CodeQL数据库、CWE基准测试、Java安全数据
3. LLVM/Clang官方文档 - API参考和使用指南
4. CodeQL官方文档 - 查询语言和标准库
5. CWE漏洞库 - MITRE标准化漏洞模式
6. 安全编码最佳实践 - 通用安全知识和最佳实践

手动收集的数据类别：
1. 学术论文和研究成果 - 需要从论文网站下载
2. 商业工具文档 - 需要从官方文档下载
3. 实际项目案例 - 需要从开源项目中提取
4. 专家经验分享 - 需要整理和录入

运行环境：主机环境（非容器内）
"""

import sys
import json
import requests
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime
import re
from urllib.parse import urljoin
import zipfile
import tarfile
import shutil

# 添加项目根目录到Python路径
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# 直接定义数据模型，避免依赖问题
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime

@dataclass
class KnowledgeEntry:
    """知识库条目"""
    id: str
    content: str
    title: str
    category: str  # framework_docs, api_examples, cwe_patterns, expert_knowledge
    framework: str  # clang, codeql, general
    language: str  # cpp, java, python, general
    metadata: Dict[str, Any] = field(default_factory=dict)
    embedding: Optional[List[float]] = None
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now().isoformat())

class ComprehensiveDataCollector:
    """全面知识库数据收集器"""

    def __init__(self):
        self.data_dir = project_root / "data"
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.cache_dir = self.data_dir / "cache"
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def download_file(self, url: str, local_path: Path) -> bool:
        """下载文件到本地"""
        try:
            print(f"📥 下载: {url}")
            response = requests.get(url, stream=True, timeout=30)
            response.raise_for_status()

            with open(local_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)

            print(f"✅ 下载完成: {local_path}")
            return True

        except Exception as e:
            print(f"❌ 下载失败: {e}")
            return False

    def extract_archive(self, archive_path: Path, extract_to: Path) -> bool:
        """解压归档文件"""
        try:
            extract_to.mkdir(parents=True, exist_ok=True)

            if archive_path.suffix == '.zip':
                with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                    zip_ref.extractall(extract_to)
            elif archive_path.suffixes in [['.tar', '.gz'], ['.tar', '.bz2']]:
                with tarfile.open(archive_path, 'r:*') as tar_ref:
                    tar_ref.extractall(extract_to)
            else:
                print(f"❌ 不支持的归档格式: {archive_path}")
                return False

            print(f"✅ 解压完成: {extract_to}")
            return True

        except Exception as e:
            print(f"❌ 解压失败: {e}")
            return False

    def collect_knighter_data(self) -> List[KnowledgeEntry]:
        """从KNighter项目收集全面数据（已内嵌，无需依赖原始项目）"""
        print("🔍 收集KNighter项目数据...")

        entries = []

        # 收集KNighter的检查器实现（已内嵌到脚本中）
        entries.extend(self._collect_knighter_embedded_checkers())

        # 收集KNighter的完整示例（包括patch, pattern, plan, checker）
        entries.extend(self._collect_knighter_examples())

        # 收集KNighter的prompt模板
        entries.extend(self._collect_knighter_embedded_prompts())

        # 收集KNighter的知识库
        entries.extend(self._collect_knighter_embedded_knowledge())

        # 收集KNighter的文档
        entries.extend(self._collect_knighter_embedded_docs())

        print(f"✅ 从KNighter收集到 {len(entries)} 个知识条目")
        return entries

    def _collect_knighter_checkers(self, knighter_path: Path) -> List[KnowledgeEntry]:
        """收集KNighter检查器数据库"""
        entries = []
        checker_db_path = knighter_path / "checker_database"

        if not checker_db_path.exists():
            print(f"⚠️  KNighter checker_database不存在: {checker_db_path}")
            return entries

        print(f"📂 扫描KNighter检查器数据库: {checker_db_path}")

        # 遍历所有检查器目录
        for checker_dir in checker_db_path.iterdir():
            if not checker_dir.is_dir():
                continue

            checker_name = checker_dir.name
            print(f"🔍 处理检查器: {checker_name}")

            # 读取各种文件
            files_to_read = [
                ("checker.cpp", "checker_implementation", "code_examples"),
                ("pattern.md", "pattern_description", "cwe_patterns"),
                ("plan.md", "implementation_plan", "expert_knowledge")
            ]

            for filename, file_type, category in files_to_read:
                file_path = checker_dir / filename
                if file_path.exists():
                    try:
                        content = file_path.read_text(encoding='utf-8')

                        # 根据文件类型确定标题和语言
                        if file_type == "checker_implementation":
                            title = f"{checker_name} - Clang检查器实现"
                            language = "cpp"
                        elif file_type == "pattern_description":
                            title = f"{checker_name} - 漏洞模式分析"
                            language = "general"
                        else:  # implementation_plan
                            title = f"{checker_name} - 实现策略"
                            language = "general"

                        entry = KnowledgeEntry(
                            id="",
                            content=content,
                            title=title,
                            category=category,
                            framework="clang",
                            language=language,
                            metadata={
                                "checker_name": checker_name,
                                "source": "knighter_database",
                                "file_type": file_type,
                                "project": "knighter"
                            }
                        )
                        entries.append(entry)

                    except Exception as e:
                        print(f"⚠️  读取文件 {filename} 时出错: {e}")
                        continue

        return entries

    def _collect_knighter_prompts(self, knighter_path: Path) -> List[KnowledgeEntry]:
        """收集KNighter的prompt模板"""
        entries = []
        prompt_dir = knighter_path / "prompt_template"

        if not prompt_dir.exists():
            return entries

        print(f"📝 收集KNighter prompt模板: {prompt_dir}")

        # 收集主要的prompt文件
        prompt_files = [
            ("patch2pattern.md", "patch到模式的转换提示", "expert_knowledge"),
            ("pattern2plan.md", "模式到计划的转换提示", "expert_knowledge"),
            ("plan2checker.md", "计划到代码的生成提示", "expert_knowledge"),
            ("repair.md", "代码修复提示", "expert_knowledge"),
            ("check_report.md", "报告检查提示", "expert_knowledge"),
            ("reduce_report.md", "报告优化提示", "expert_knowledge"),
        ]

        for filename, description, category in prompt_files:
            file_path = prompt_dir / filename
            if file_path.exists():
                try:
                    content = file_path.read_text(encoding='utf-8')

                    entry = KnowledgeEntry(
                        id="",
                        content=content,
                        title=f"KNighter Prompt: {description}",
                        category=category,
                        framework="general",
                        language="general",
                        metadata={
                            "source": "knighter_prompts",
                            "prompt_type": filename.replace('.md', ''),
                            "description": description,
                            "project": "knighter"
                        }
                    )
                    entries.append(entry)

                except Exception as e:
                    print(f"⚠️  读取prompt文件 {filename} 时出错: {e}")
                    continue

        # 收集examples目录
        examples_dir = prompt_dir / "examples"
        if examples_dir.exists():
            entries.extend(self._collect_knighter_examples(examples_dir))

        return entries

    def _collect_knighter_examples(self, examples_dir: Path) -> List[KnowledgeEntry]:
        """收集KNighter的示例数据"""
        entries = []

        for example_dir in examples_dir.iterdir():
            if not example_dir.is_dir():
                continue

            example_name = example_dir.name
            print(f"📋 处理示例: {example_name}")

            # 读取示例文件
            for file_path in example_dir.iterdir():
                if file_path.is_file():
                    try:
                        content = file_path.read_text(encoding='utf-8')

                        entry = KnowledgeEntry(
                            id="",
                            content=content,
                            title=f"KNighter示例: {example_name} - {file_path.name}",
                            category="code_examples",
                            framework="clang",
                            language="cpp" if file_path.suffix == '.cpp' else "general",
                            metadata={
                                "example_name": example_name,
                                "source": "knighter_examples",
                                "file_name": file_path.name,
                                "project": "knighter"
                            }
                        )
                        entries.append(entry)

                    except Exception as e:
                        print(f"⚠️  读取示例文件 {file_path} 时出错: {e}")
                        continue

        return entries

    def _collect_knighter_knowledge(self, knighter_path: Path) -> List[KnowledgeEntry]:
        """收集KNighter的知识库"""
        entries = []
        knowledge_dir = knighter_path / "prompt_template" / "knowledge"

        if not knowledge_dir.exists():
            return entries

        print(f"🧠 收集KNighter知识库: {knowledge_dir}")

        knowledge_files = [
            ("utility.md", "工具函数库", "framework_api"),
            ("template.md", "代码模板", "code_examples"),
            ("suggestions.md", "使用建议", "expert_knowledge")
        ]

        for filename, description, category in knowledge_files:
            file_path = knowledge_dir / filename
            if file_path.exists():
                try:
                    content = file_path.read_text(encoding='utf-8')

                    entry = KnowledgeEntry(
                        id="",
                        content=content,
                        title=f"KNighter知识: {description}",
                        category=category,
                        framework="clang",
                        language="general",
                        metadata={
                            "source": "knighter_knowledge",
                            "knowledge_type": filename.replace('.md', ''),
                            "description": description,
                            "project": "knighter"
                        }
                    )
                    entries.append(entry)

                except Exception as e:
                    print(f"⚠️  读取知识文件 {filename} 时出错: {e}")
                    continue

        return entries

    def _collect_knighter_docs(self, knighter_path: Path) -> List[KnowledgeEntry]:
        """收集KNighter的文档"""
        entries = []

        # 收集README文件
        readme_files = [
            ("README.md", "项目主要文档"),
            ("README-dev.md", "开发文档"),
            ("ARCHITECTURE.md", "架构设计文档")
        ]

        for filename, description in readme_files:
            file_path = knighter_path / filename
            if file_path.exists():
                try:
                    content = file_path.read_text(encoding='utf-8')

                    entry = KnowledgeEntry(
                        id="",
                        content=content,
                        title=f"KNighter文档: {description}",
                        category="expert_knowledge",
                        framework="general",
                        language="general",
                        metadata={
                            "source": "knighter_docs",
                            "doc_type": "readme",
                            "description": description,
                            "project": "knighter"
                        }
                    )
                    entries.append(entry)

                except Exception as e:
                    print(f"⚠️  读取文档文件 {filename} 时出错: {e}")
                    continue

        return entries

    def _collect_knighter_scripts(self, knighter_path: Path) -> List[KnowledgeEntry]:
        """收集KNighter的脚本和配置"""
        entries = []
        scripts_dir = knighter_path / "scripts"

        if not scripts_dir.exists():
            return entries

        print(f"🔧 收集KNighter脚本: {scripts_dir}")

        # 收集Python脚本
        for script_file in scripts_dir.rglob("*.py"):
            try:
                content = script_file.read_text(encoding='utf-8')

                # 提取脚本用途
                script_name = script_file.stem
                description = self._analyze_script_purpose(content, script_name)

                entry = KnowledgeEntry(
                    id="",
                    content=content,
                    title=f"KNighter脚本: {script_name} - {description}",
                    category="expert_knowledge",
                    framework="clang",
                    language="python",
                    metadata={
                        "script_name": script_name,
                        "source": "knighter_scripts",
                        "description": description,
                        "file_path": str(script_file.relative_to(knighter_path)),
                        "project": "knighter"
                    }
                )
                entries.append(entry)

            except Exception as e:
                print(f"⚠️  读取脚本文件 {script_file} 时出错: {e}")
                continue

        # 收集配置文件
        config_files = [
            knighter_path / "config-example.yaml",
            knighter_path / "docker-compose.yml",
            knighter_path / "Dockerfile"
        ]

        for config_file in config_files:
            if config_file.exists():
                try:
                    content = config_file.read_text(encoding='utf-8')

                    entry = KnowledgeEntry(
                        id="",
                        content=content,
                        title=f"KNighter配置: {config_file.name}",
                        category="expert_knowledge",
                        framework="general",
                        language="yaml" if config_file.suffix == '.yaml' else "dockerfile",
                        metadata={
                            "config_type": config_file.suffix[1:],
                            "source": "knighter_configs",
                            "file_name": config_file.name,
                            "project": "knighter"
                        }
                    )
                    entries.append(entry)

                except Exception as e:
                    print(f"⚠️  读取配置文件 {config_file} 时出错: {e}")
                    continue

        return entries

    def _analyze_script_purpose(self, content: str, script_name: str) -> str:
        """分析脚本用途"""
        if 'commit' in script_name.lower():
            return "提交数据处理"
        elif 'checker' in script_name.lower():
            return "检查器操作"
        elif 'llvm' in script_name.lower():
            return "LLVM环境管理"
        elif 'setup' in script_name.lower():
            return "环境设置"
        elif 'count' in script_name.lower():
            return "统计分析"
        else:
            # 从注释中提取信息
            lines = content.split('\n')[:10]  # 前10行
            for line in lines:
                line = line.strip()
                if line.startswith('"""') or line.startswith("'''"):
                    continue
                if '"""' in line or "'''" in line:
                    # 提取文档字符串
                    doc_match = re.search(r'["\']{3}(.*?)(["\']{3}|$)', content, re.DOTALL)
                    if doc_match:
                        doc = doc_match.group(1).strip().split('\n')[0]
                        if len(doc) < 50:  # 简短描述
                            return doc
            return "工具脚本"

    def collect_iris_data(self) -> List[KnowledgeEntry]:
        """从IRIS项目收集全面数据（已内嵌，无需依赖原始项目）"""
        print("🔍 收集IRIS项目数据...")

        entries = []

        # 收集IRIS的CWE查询集（已内嵌到脚本中）
        entries.extend(self._collect_iris_cwe_queries())

        # 收集IRIS的查询模板
        entries.extend(self._collect_iris_query_templates())

        # 收集IRIS的prompt模板
        entries.extend(self._collect_iris_prompts())

        # 收集IRIS的Java安全分析数据
        entries.extend(self._collect_iris_java_security())

        # 收集IRIS的源码和文档
        entries.extend(self._collect_iris_embedded_source())

        print(f"✅ 从IRIS收集到 {len(entries)} 个知识条目")
        return entries

    def _collect_iris_codeql_dbs(self, iris_path: Path) -> List[KnowledgeEntry]:
        """收集IRIS的CodeQL数据库信息"""
        entries = []
        codeql_dbs_path = iris_path / "iris" / "data" / "codeql-dbs"

        if not codeql_dbs_path.exists():
            return entries

        print(f"📊 收集IRIS CodeQL数据库: {codeql_dbs_path}")

        for db_dir in codeql_dbs_path.iterdir():
            if not db_dir.is_dir():
                continue

            db_name = db_dir.name
            print(f"🔍 处理CodeQL数据库: {db_name}")

            try:
                # 读取数据库信息（如果有README或描述文件）
                readme_file = db_dir / "README.md"
                if readme_file.exists():
                    content = readme_file.read_text(encoding='utf-8')

                    entry = KnowledgeEntry(
                        id="",
                        content=content,
                        title=f"IRIS CodeQL数据库: {db_name}",
                        category="code_examples",
                        framework="codeql",
                        language="ql",
                        metadata={
                            "db_name": db_name,
                            "source": "iris_codeql_dbs",
                            "file_type": "database_description",
                            "project": "iris"
                        }
                    )
                    entries.append(entry)

                # 收集数据库中的查询文件
                for ql_file in db_dir.rglob("*.ql"):
                    try:
                        content = ql_file.read_text(encoding='utf-8')

                        entry = KnowledgeEntry(
                            id="",
                            content=content,
                            title=f"IRIS CodeQL查询: {ql_file.stem}",
                            category="code_examples",
                            framework="codeql",
                            language="ql",
                            metadata={
                                "query_name": ql_file.stem,
                                "db_name": db_name,
                                "source": "iris_codeql_dbs",
                                "file_type": "query_file",
                                "file_path": str(ql_file.relative_to(db_dir)),
                                "project": "iris"
                            }
                        )
                        entries.append(entry)

                    except Exception as e:
                        print(f"⚠️  读取查询文件 {ql_file} 时出错: {e}")
                        continue

            except Exception as e:
                print(f"⚠️  处理CodeQL数据库 {db_name} 时出错: {e}")
                continue

        return entries

    def _collect_iris_cwe_bench(self, iris_path: Path) -> List[KnowledgeEntry]:
        """收集IRIS的CWE基准测试数据"""
        entries = []
        cwe_bench_path = iris_path / "iris" / "data" / "cwe-bench-java"

        if not cwe_bench_path.exists():
            return entries

        print(f"🎯 收集IRIS CWE基准测试: {cwe_bench_path}")

        # 收集advisory信息
        advisory_path = cwe_bench_path / "advisory"
        if advisory_path.exists():
            for advisory_file in advisory_path.rglob("*.json"):
                try:
                    with open(advisory_file, 'r', encoding='utf-8') as f:
                        data = json.load(f)

                    content = json.dumps(data, ensure_ascii=False, indent=2)

                    entry = KnowledgeEntry(
                        id="",
                        content=content,
                        title=f"IRIS CWE Advisory: {advisory_file.stem}",
                        category="cwe_patterns",
                        framework="java",
                        language="json",
                        metadata={
                            "advisory_id": advisory_file.stem,
                            "source": "iris_cwe_bench",
                            "file_type": "vulnerability_advisory",
                            "project": "iris"
                        }
                    )
                    entries.append(entry)

                except Exception as e:
                    print(f"⚠️  处理advisory文件 {advisory_file} 时出错: {e}")
                    continue

        # 收集patches信息
        patches_path = cwe_bench_path / "patches"
        if patches_path.exists():
            for patch_file in patches_path.rglob("*.patch"):
                try:
                    content = patch_file.read_text(encoding='utf-8')

                    entry = KnowledgeEntry(
                        id="",
                        content=content,
                        title=f"IRIS Security Patch: {patch_file.stem}",
                        category="expert_knowledge",
                        framework="java",
                        language="diff",
                        metadata={
                            "patch_name": patch_file.stem,
                            "source": "iris_cwe_bench",
                            "file_type": "security_patch",
                            "project": "iris"
                        }
                    )
                    entries.append(entry)

                except Exception as e:
                    print(f"⚠️  处理patch文件 {patch_file} 时出错: {e}")
                    continue

        return entries

    def _collect_iris_java_env(self, iris_path: Path) -> List[KnowledgeEntry]:
        """收集IRIS的Java环境配置"""
        entries = []
        java_env_path = iris_path / "iris" / "data" / "java-env"

        if not java_env_path.exists():
            return entries

        print(f"☕ 收集IRIS Java环境: {java_env_path}")

        # 收集环境配置文件
        for config_file in java_env_path.rglob("*"):
            if config_file.is_file():
                try:
                    content = config_file.read_text(encoding='utf-8')

                    entry = KnowledgeEntry(
                        id="",
                        content=content,
                        title=f"IRIS Java环境: {config_file.name}",
                        category="expert_knowledge",
                        framework="java",
                        language="general",
                        metadata={
                            "config_name": config_file.name,
                            "source": "iris_java_env",
                            "file_type": "environment_config",
                            "project": "iris"
                        }
                    )
                    entries.append(entry)

                except Exception as e:
                    print(f"⚠️  读取Java环境文件 {config_file} 时出错: {e}")
                    continue

        return entries

    def _collect_iris_scripts(self, iris_path: Path) -> List[KnowledgeEntry]:
        """收集IRIS的脚本和配置"""
        entries = []
        scripts_dir = iris_path / "iris" / "scripts"

        if not scripts_dir.exists():
            return entries

        print(f"🔧 收集IRIS脚本: {scripts_dir}")

        for script_file in scripts_dir.rglob("*"):
            if script_file.is_file() and script_file.suffix in ['.py', '.sh', '.yml', '.yaml']:
                try:
                    content = script_file.read_text(encoding='utf-8')

                    entry = KnowledgeEntry(
                        id="",
                        content=content,
                        title=f"IRIS脚本: {script_file.name}",
                        category="expert_knowledge",
                        framework="general",
                        language="python" if script_file.suffix == '.py' else "shell" if script_file.suffix == '.sh' else "yaml",
                        metadata={
                            "script_name": script_file.name,
                            "source": "iris_scripts",
                            "file_type": "automation_script",
                            "file_path": str(script_file.relative_to(iris_path)),
                            "project": "iris"
                        }
                    )
                    entries.append(entry)

                except Exception as e:
                    print(f"⚠️  读取IRIS脚本文件 {script_file} 时出错: {e}")
                    continue

        return entries

    def _collect_iris_docs(self, iris_path: Path) -> List[KnowledgeEntry]:
        """收集IRIS的文档"""
        entries = []

        # 收集主要文档
        doc_files = [
            iris_path / "iris" / "README.md",
            iris_path / "iris" / "docs" / "README.md",
        ]

        for doc_file in doc_files:
            if doc_file.exists():
                try:
                    content = doc_file.read_text(encoding='utf-8')

                    entry = KnowledgeEntry(
                        id="",
                        content=content,
                        title=f"IRIS文档: {doc_file.name}",
                        category="expert_knowledge",
                        framework="general",
                        language="general",
                        metadata={
                            "doc_name": doc_file.name,
                            "source": "iris_docs",
                            "file_type": "documentation",
                            "project": "iris"
                        }
                    )
                    entries.append(entry)

                except Exception as e:
                    print(f"⚠️  读取IRIS文档 {doc_file} 时出错: {e}")
                    continue

        return entries

    def collect_iris_data(self) -> List[KnowledgeEntry]:
        """从IRIS项目收集全面数据"""
        print("🔍 收集IRIS项目数据...")

        entries = []

        # 尝试多个可能的IRIS路径
        possible_iris_paths = [
            "/home/spa/IRIS",         # 宿主机路径
            "../IRIS",                # 相对路径
            str(project_root.parent / "IRIS")  # 项目同级目录
        ]

        iris_path = None
        for path in possible_iris_paths:
            if Path(path).exists():
                iris_path = Path(path)
                print(f"✅ 找到IRIS项目: {iris_path}")
                break

        if not iris_path:
            print("⚠️  未找到IRIS项目，跳过IRIS数据收集")
            return entries

        # 收集各种IRIS数据
        entries.extend(self._collect_iris_codeql_dbs(iris_path))
        entries.extend(self._collect_iris_cwe_bench(iris_path))
        entries.extend(self._collect_iris_source(iris_path))
        entries.extend(self._collect_iris_docs(iris_path))

        print(f"✅ 从IRIS收集到 {len(entries)} 个知识条目")
        return entries

    def _collect_iris_codeql_dbs(self, iris_path: Path) -> List[KnowledgeEntry]:
        """收集IRIS的CodeQL数据库信息"""
        entries = []
        codeql_dbs_path = iris_path / "iris" / "data" / "codeql-dbs"

        if not codeql_dbs_path.exists():
            return entries

        print(f"📂 扫描IRIS CodeQL数据库: {codeql_dbs_path}")

        for db_dir in codeql_dbs_path.iterdir():
            if not db_dir.is_dir():
                continue

            db_name = db_dir.name
            print(f"🔍 处理CodeQL数据库: {db_name}")

            try:
                # 读取数据库信息（如果有README或描述文件）
                readme_file = db_dir / "README.md"
                if readme_file.exists():
                    content = readme_file.read_text(encoding='utf-8')

                    entry = KnowledgeEntry(
                        id="",
                        content=content,
                        title=f"IRIS CodeQL数据库: {db_name}",
                        category="code_examples",
                        framework="codeql",
                        language="ql",
                        metadata={
                            "db_name": db_name,
                            "source": "iris_codeql_dbs",
                            "file_type": "database_description",
                            "project": "iris"
                        }
                    )
                    entries.append(entry)

                # 收集数据库中的查询文件
                for ql_file in db_dir.rglob("*.ql"):
                    try:
                        content = ql_file.read_text(encoding='utf-8')

                        entry = KnowledgeEntry(
                            id="",
                            content=content,
                            title=f"IRIS CodeQL查询: {ql_file.relative_to(db_dir)}",
                            category="code_examples",
                            framework="codeql",
                            language="ql",
                            metadata={
                                "db_name": db_name,
                                "query_file": str(ql_file.relative_to(db_dir)),
                                "source": "iris_codeql_dbs",
                                "file_type": "query_file",
                                "project": "iris"
                            }
                        )
                        entries.append(entry)

                    except Exception as e:
                        print(f"⚠️  读取查询文件 {ql_file} 时出错: {e}")
                        continue

            except Exception as e:
                print(f"⚠️  处理CodeQL数据库 {db_name} 时出错: {e}")
                continue

        return entries

    def _collect_iris_cwe_bench(self, iris_path: Path) -> List[KnowledgeEntry]:
        """收集IRIS的CWE基准测试数据"""
        entries = []
        cwe_bench_path = iris_path / "iris" / "data" / "cwe-bench-java"

        if not cwe_bench_path.exists():
            return entries

        print(f"📂 扫描IRIS CWE基准测试: {cwe_bench_path}")

        # 收集advisory信息
        advisory_path = cwe_bench_path / "advisory"
        if advisory_path.exists():
            for advisory_file in advisory_path.rglob("*.json"):
                try:
                    with open(advisory_file, 'r', encoding='utf-8') as f:
                        data = json.load(f)

                    content = json.dumps(data, ensure_ascii=False, indent=2)

                    entry = KnowledgeEntry(
                        id="",
                        content=content,
                        title=f"IRIS CWE Advisory: {advisory_file.stem}",
                        category="cwe_patterns",
                        framework="java",
                        language="json",
                        metadata={
                            "advisory_id": advisory_file.stem,
                            "source": "iris_cwe_bench",
                            "file_type": "vulnerability_advisory",
                            "project": "iris"
                        }
                    )
                    entries.append(entry)

                except Exception as e:
                    print(f"⚠️  处理advisory文件 {advisory_file} 时出错: {e}")
                    continue

        # 收集patches信息
        patches_path = cwe_bench_path / "patches"
        if patches_path.exists():
            for patch_file in patches_path.rglob("*.patch"):
                try:
                    content = patch_file.read_text(encoding='utf-8')

                    entry = KnowledgeEntry(
                        id="",
                        content=content,
                        title=f"IRIS Security Patch: {patch_file.stem}",
                        category="expert_knowledge",
                        framework="java",
                        language="diff",
                        metadata={
                            "patch_name": patch_file.stem,
                            "source": "iris_cwe_bench",
                            "file_type": "security_patch",
                            "project": "iris"
                        }
                    )
                    entries.append(entry)

                except Exception as e:
                    print(f"⚠️  处理patch文件 {patch_file} 时出错: {e}")
                    continue

        return entries

    def _collect_iris_source(self, iris_path: Path) -> List[KnowledgeEntry]:
        """收集IRIS源码和配置"""
        entries = []

        # 收集主要源码文件
        source_files = [
            ("iris/src/codeql_vul.py", "CodeQL漏洞检测逻辑", "framework_api", "python"),
            ("iris/src/codeql_vul_for_query.py", "CodeQL查询生成", "code_examples", "python"),
            ("iris/src/neusym_vul.py", "神经符号漏洞分析", "expert_knowledge", "python"),
            ("iris/src/neusym_vul_for_query.py", "神经符号查询生成", "code_examples", "python"),
        ]

        for file_path, description, category, language in source_files:
            full_path = iris_path / file_path
            if full_path.exists():
                try:
                    content = full_path.read_text(encoding='utf-8')

                    entry = KnowledgeEntry(
                        id="",
                        content=content,
                        title=f"IRIS源码: {description}",
                        category=category,
                        framework="codeql" if "codeql" in file_path else "general",
                        language=language,
                        metadata={
                            "source_file": file_path,
                            "description": description,
                            "source": "iris_source",
                            "file_type": "source_code",
                            "project": "iris"
                        }
                    )
                    entries.append(entry)

                except Exception as e:
                    print(f"⚠️  读取源码文件 {file_path} 时出错: {e}")
                    continue

        return entries

    def _collect_iris_docs(self, iris_path: Path) -> List[KnowledgeEntry]:
        """收集IRIS文档"""
        entries = []

        # 收集文档文件
        doc_files = [
            ("iris/README.md", "IRIS项目文档"),
            ("iris/docs/architecture.md", "IRIS架构文档") if (iris_path / "iris/docs").exists() else None,
        ]

        for doc_info in doc_files:
            if doc_info is None:
                continue

            file_path, description = doc_info
            full_path = iris_path / file_path

            if full_path.exists():
                try:
                    content = full_path.read_text(encoding='utf-8')

                    entry = KnowledgeEntry(
                        id="",
                        content=content,
                        title=f"IRIS文档: {description}",
                        category="expert_knowledge",
                        framework="general",
                        language="general",
                        metadata={
                            "doc_file": file_path,
                            "description": description,
                            "source": "iris_docs",
                            "file_type": "documentation",
                            "project": "iris"
                        }
                    )
                    entries.append(entry)

                except Exception as e:
                    print(f"⚠️  读取文档文件 {file_path} 时出错: {e}")
                    continue

        return entries

    def collect_cwe_database(self) -> List[KnowledgeEntry]:
        """从MITRE CWE官方数据库收集数据"""
        print("🔍 收集MITRE CWE数据库...")

        entries = []
        cwe_base_url = "https://cwe.mitre.org/data/xml/views/2000.xml.zip"

        # 下载CWE数据库
        cache_file = self.cache_dir / "cwe_database.zip"
        extract_dir = self.cache_dir / "cwe_extracted"

        if not cache_file.exists():
            if not self.download_file(cwe_base_url, cache_file):
                print("⚠️  CWE数据库下载失败，跳过CWE数据收集")
                return entries

        if not extract_dir.exists():
            if not self.extract_archive(cache_file, extract_dir):
                print("⚠️  CWE数据库解压失败，跳过CWE数据收集")
                return entries

        # 解析XML文件（这里简化处理，实际需要XML解析）
        try:
            # 查找XML文件
            xml_files = list(extract_dir.rglob("*.xml"))
            if xml_files:
                xml_file = xml_files[0]
                print(f"📄 找到CWE XML文件: {xml_file}")

                # 这里应该解析XML，但暂时只保存基本信息
                content = f"""
CWE (Common Weakness Enumeration) 数据库

来源: MITRE CWE
文件: {xml_file.name}
描述: 通用软件弱点枚举，包含软件安全漏洞的标准化分类

CWE是软件安全领域的重要标准，为漏洞分类和安全研究提供基础。
"""

                entry = KnowledgeEntry(
                    id="",
                    content=content,
                    title="MITRE CWE数据库概述",
                    category="cwe_patterns",
                    framework="general",
                    language="general",
                    metadata={
                        "source": "mitre_cwe",
                        "url": cwe_base_url,
                        "file_type": "database_overview"
                    }
                )
                entries.append(entry)

        except Exception as e:
            print(f"⚠️  处理CWE数据库时出错: {e}")

        print(f"✅ 从CWE数据库收集到 {len(entries)} 个知识条目")
        return entries

    def _collect_knighter_embedded_checkers(self) -> List[KnowledgeEntry]:
        """收集KNighter检查器实现（已内嵌）"""
        entries = []

        # KNighter检查器实现示例
        knighter_checkers = {
            "PointerSortingChecker": {
                "title": "PointerSortingChecker - 指针排序检查器",
                "description": "检测指针排序可能导致的非确定性行为",
                "content": """
//== PointerSortingChecker.cpp --------------------------------- -*- C++ -*--=//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file defines PointerSortingChecker which checks for non-determinism
// caused due to sorting containers with pointer-like elements.
//
//===----------------------------------------------------------------------===//

#include \"clang/ASTMatchers/ASTMatchFinder.h\"
#include \"clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h\"
#include \"clang/StaticAnalyzer/Core/Checker.h\"
#include \"clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h\"

using namespace clang;
using namespace ento;
using namespace ast_matchers;

namespace {

// ID of a node at which the diagnostic would be emitted.
constexpr llvm::StringLiteral WarnAtNode = \"sort\";

class PointerSortingChecker : public Checker<check::ASTCodeBody> {
public:
  void checkASTCodeBody(const Decl *D,
                        AnalysisManager &AM,
                        BugReporter &BR) const;
};

static void emitDiagnostics(const BoundNodes &Match, const Decl *D,
                            BugReporter &BR, AnalysisManager &AM,
                            const PointerSortingChecker *Checker) {
  auto *ADC = AM.getAnalysisDeclContext(D);

  const auto *MarkedStmt = Match.getNodeAs<CallExpr>(WarnAtNode);
  assert(MarkedStmt);

  auto Range = MarkedStmt->getSourceRange();
  auto Location = PathDiagnosticLocation::createBegin(MarkedStmt,
                                                      BR.getSourceManager(),
                                                      ADC);
  std::string Diagnostics;
  llvm::raw_string_ostream OS(Diagnostics);
  OS << \"Sorting pointer-like elements \"
     << \"can result in non-deterministic ordering\";

  BR.EmitBasicReport(ADC->getDecl(), Checker,
                     \"Sorting of pointer-like elements\", \"Non-determinism\",
                     OS.str(), Location, Range);
}

decltype(auto) callsName(const char *FunctionName) {
  return callee(functionDecl(hasName(FunctionName)));
}

// FIXME: Currently we simply check if std::sort is used with pointer-like
// elements. This approach can have a big false positive rate. Using std::sort,
// std::unique and then erase is common technique for deduplicating a container
// (which in some cases might even be quicker than using, let's say std::set).
// In case a container contains arbitrary memory addresses (e.g. multiple
// things give different stuff but might give the same thing multiple times)
// which we don't want to do things with more than once, we might use
// sort-unique-erase and the sort call will emit a report.
auto matchSortWithPointers() -> decltype(decl()) {
  // Match any of these function calls.
  auto SortFuncM = anyOf(
                     callsName(\"std::is_sorted\"),
                     callsName(\"std::nth_element\"),
                     callsName(\"std::partial_sort\"),
                     callsName(\"std::partition\"),
                     callsName(\"std::sort\"),
                     callsName(\"std::stable_partition\"),
                     callsName(\"std::stable_sort\")
                    );

  // Match only if the container has pointer-type elements.
  auto IteratesPointerEltsM = hasArgument(0,
                                hasType(cxxRecordDecl(has(
                                  fieldDecl(hasType(hasCanonicalType(
                                    pointsTo(hasCanonicalType(pointerType()))\n                                  )))\n                              ))));

  auto PointerSortM = traverse(
      TK_AsIs,
      stmt(callExpr(allOf(SortFuncM, IteratesPointerEltsM))).bind(WarnAtNode));

  return decl(forEachDescendant(PointerSortM));
}

void PointerSortingChecker::checkASTCodeBody(const Decl *D,
                                             AnalysisManager &AM,
                                             BugReporter &BR) const {
  auto MatcherM = matchSortWithPointers();

  auto Matches = match(MatcherM, *D, AM.getASTContext());
  for (const auto &Match : Matches)
    emitDiagnostics(Match, D, BR, AM, this);
}

} // end of anonymous namespace

void ento::registerPointerSortingChecker(CheckerManager &Mgr) {
  Mgr.registerChecker<PointerSortingChecker>();
}

bool ento::shouldRegisterPointerSortingChecker(const CheckerManager &mgr) {
  const LangOptions &LO = mgr.getLangOpts();
  return LO.CPlusPlus;
}
"""
            },
            "ArrayBoundChecker": {
                "title": "ArrayBoundChecker - 数组边界检查器",
                "description": "检测数组访问越界漏洞",
                "content": """
//== ArrayBoundChecker.cpp - Array bound checking --------------------*- C++ -*-//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file defines ArrayBoundChecker, which is a path-sensitive check
// which looks for out-of-bound array element accesses.
//
//===----------------------------------------------------------------------===//

#include \"clang/StaticAnalyzer/Core/BugReporter/BugType.h\"
#include \"clang/StaticAnalyzer/Core/Checker.h\"
#include \"clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h\"
#include \"clang/StaticAnalyzer/Core/PathSensitive/ExprEngine.h\"

using namespace clang;
using namespace ento;

namespace {
class ArrayBoundChecker : public Checker<check::Location> {
  mutable std::unique_ptr<BugType> BT;

public:
  void checkLocation(SVal l, bool isLoad, const Stmt *S,
                     CheckerContext &C) const;
};
} // end anonymous namespace

void ArrayBoundChecker::checkLocation(SVal l, bool isLoad, const Stmt *S,
                                      CheckerContext &C) const {
  // Check for out-of-bound array access.
  const MemRegion *R = l.getAsRegion();
  if (!R)
    return;

  const ElementRegion *ER = dyn_cast<ElementRegion>(R);
  if (!ER)
    return;

  // Get the index of the accessed element.
  DefinedOrUnknownSVal Idx = ER->getIndex().castAs<DefinedOrUnknownSVal>();

  // Zero index is always in bound, this also passes ElementRegion created to
  // represent pointer cast which has fake zero index.
  if (Idx.isZeroConstant())
    return;

  // Get the size of the array.
  const MemRegion *SuperR = ER->getSuperRegion();
  DefinedOrUnknownSVal NumElements = C.getStoreManager().getSizeInElements(
      C.getState(), SuperR, SuperR->getValueType());

  // Check for cases where the index may be out of bounds.
  ProgramStateRef state = C.getState();
  SValBuilder &svalBuilder = C.getSValBuilder();

  // Convert the index to the appropriate type.
  QualType IndexTy = C.getASTContext().getSizeType();
  Idx = svalBuilder.convertToArrayIndex(Idx);
  NumElements = svalBuilder.convertToArrayIndex(NumElements);

  if (Idx.isUnknown() || NumElements.isUnknown())
    return;

  // Build the comparison.
  DefinedOrUnknownSVal Zero = svalBuilder.makeZeroVal(IndexTy);
  DefinedOrUnknownSVal LessThanNumElements =
      svalBuilder.evalBinOp(state, BO_LT, Idx, NumElements,
                            svalBuilder.getConditionType()).castAs<DefinedOrUnknownSVal>();

  // Check if the index is negative or greater than or equal to the size.
  DefinedOrUnknownSVal InBound = svalBuilder.evalBinOp(
      state, BO_LAnd,
      svalBuilder.evalBinOp(state, BO_GE, Idx, Zero,
                            svalBuilder.getConditionType()).castAs<DefinedOrUnknownSVal>(),
      LessThanNumElements);

  ProgramStateRef StInBound = state->assume(InBound, true);
  ProgramStateRef StOutBound = state->assume(InBound, false);

  if (StOutBound && !StInBound) {
    ExplodedNode *N = C.generateNonFatalErrorNode(StOutBound);
    if (!N)
      return;

    if (!BT)
      BT.reset(new BugType(this, \"Out-of-bound array access\", \"Logic error\"));

    // Generate a report.
    auto Report = std::make_unique<PathSensitiveBugReport>(
        *BT, \"Access out-of-bound array element\", N);

    C.emitReport(std::move(Report));
  }
}

void ento::registerArrayBoundChecker(CheckerManager &mgr) {
  mgr.registerChecker<ArrayBoundChecker>();
}
"""
            }
        }

        for checker_name, checker_data in knighter_checkers.items():
            entry = KnowledgeEntry(
                id="",
                content=checker_data["content"],
                title=checker_data["title"],
                category="code_examples",
                framework="clang",
                language="cpp",
                metadata={
                    "checker_name": checker_name,
                    "source": "knighter_embedded_checkers",
                    "description": checker_data["description"],
                    "file_type": "checker_implementation",
                    "project": "knighter"
                }
            )
            entries.append(entry)

        print(f"✅ 收集到KNighter内嵌检查器: {len(entries)} 条")
        return entries

    def _collect_knighter_examples(self) -> List[KnowledgeEntry]:
        """收集KNighter的完整示例（包括patch, pattern, plan, checker）"""
        entries = []

        # KNighter完整示例 - uninit漏洞
        uninit_example = {
            "title": "KNighter uninit漏洞完整示例",
            "description": "内核信息泄漏漏洞的完整分析和修复",
            "content": """
# KNighter uninit漏洞完整示例

## 漏洞描述 (Pattern)
```
//== Pattern Description for uninit vulnerability ==//
//
// This pattern detects uninitialized memory access in kernel code,
// specifically in functions like do_sys_name_to_handle() that may
// leak sensitive kernel information to userspace.
//
// Key indicators:
// 1. kmalloc() without __GFP_ZERO flag
// 2. Structure copying to userspace without full initialization
// 3. Potential information disclosure
//
//== End Pattern ==//
```

## 修复方案 (Patch)
```
### Patch Description

do_sys_name_to_handle(): use kzalloc() to fix kernel-infoleak

syzbot identified a kernel information leak vulnerability in
do_sys_name_to_handle() and issued the following report [1].

Bytes 18-19 of 20 are uninitialized
Memory access of size 20 starts at ffff888128a46380
Data copied to user address 0000000020000240"

Per Chuck Lever's suggestion, use kzalloc() instead of kmalloc() to
solve the problem.

Fixes: 990d6c2d7aee ("vfs: Add name to file handle conversion support")
Suggested-by: Chuck Lever III <chuck.lever@oracle.com>
Reported-and-tested-by: <syzbot+09b349b3066c2e0b1e96@syzkaller.appspotmail.com>
Signed-off-by: Nikita Zhandarovich <n.zhandarovich@fintech.ru>
Link: https://lore.kernel.org/r/20240119153906.4367-1-n.zhandarovich@fintech.ru
Reviewed-by: Jan Kara <jack@suse.cz>
Signed-off-by: Christian Brauner <brauner@kernel.org>

### Buggy Code

```c
// fs/fhandle.c
static long do_sys_name_to_handle(const struct path *path,
				  struct file_handle __user *ufh,
				  int __user *mnt_id, int fh_flags)
{
	long retval;
	struct file_handle f_handle;
	int handle_dwords, handle_bytes;
	struct file_handle *handle = NULL;

	/*
	 * We need to make sure whether the file system support decoding of
	 * the file handle if decodeable file handle was requested.
	 */
	if (!exportfs_can_encode_fh(path->dentry->d_sb->s_export_op, fh_flags))
		return -EOPNOTSUPP;

	if (copy_from_user(&f_handle, ufh, sizeof(struct file_handle)))
		return -EFAULT;

	if (f_handle.handle_bytes > MAX_HANDLE_SZ)
		return -EINVAL;

	handle = kmalloc(sizeof(struct file_handle) + f_handle.handle_bytes,
			 GFP_KERNEL);
	if (!handle)
		return -ENOMEM;

	/* convert handle size to multiple of sizeof(u32) */
	handle_dwords = f_handle.handle_bytes >> 2;

	/* we ask for a non connectable maybe decodeable file handle */
	retval = exportfs_encode_fh(path->dentry,
				    (struct fid *)handle->f_handle,
				    &handle_dwords, fh_flags);
	handle->handle_type = retval;
	/* convert handle size to bytes */
	handle_bytes = handle_dwords * sizeof(u32);
	handle->handle_bytes = handle_bytes;
	if ((handle->handle_bytes > f_handle.handle_bytes) ||
	    (retval == FILEID_INVALID) || (retval < 0)) {
		/* As per old exportfs_encode_fh documentation
		 * we could return ENOSPC to indicate overflow
		 * But file system returned 255 always. So handle
		 * both the values
		 */
		if (retval == FILEID_INVALID || retval == -ENOSPC)
			retval = -EOVERFLOW;
		/*
		 * set the handle size to zero so we copy only
		 * non variable part of the file_handle
		 */
		handle_bytes = 0;
	} else
		retval = 0;
	/* copy the mount id */
	if (put_user(real_mount(path->mnt)->mnt_id, mnt_id) ||
	    copy_to_user(ufh, handle,
			 sizeof(struct file_handle) + handle_bytes))
		retval = -EFAULT;
	kfree(handle);
	return retval;
}
```

### Bug Fix Patch

```diff
diff --git a/fs/fhandle.c b/fs/fhandle.c
index 18b3ba8dc8ea..57a12614addf 100644
--- a/fs/fhandle.c
+++ b/fs/fhandle.c
@@ -36,7 +36,7 @@ static long do_sys_name_to_handle(const struct path *path,
 	if (f_handle.handle_bytes > MAX_HANDLE_SZ)
 		return -EINVAL;

-	handle = kmalloc(sizeof(struct file_handle) + f_handle.handle_bytes,
+	handle = kzalloc(sizeof(struct file_handle) + f_handle.handle_bytes,
 			 GFP_KERNEL);
 	if (!handle)
 		return -ENOMEM;
```

## 实现计划 (Plan)
```
### Implementation Plan for Uninit Checker

1. **AST Analysis Phase**
   - Identify kmalloc() calls without __GFP_ZERO
   - Check if allocated memory is fully initialized before use
   - Track memory allocation and initialization patterns

2. **Data Flow Analysis Phase**
   - Track allocated memory regions
   - Verify all fields are initialized before copy_to_user
   - Detect potential information disclosure paths

3. **Pattern Matching Phase**
   - Match against known uninitialized memory patterns
   - Cross-reference with kernel security advisories
   - Validate against syzbot reports

4. **Checker Implementation**
   - Implement AST matcher for kmalloc patterns
   - Add data flow analysis for initialization tracking
   - Generate appropriate warning messages

5. **Testing and Validation**
   - Test against known vulnerable code
   - Validate false positive/negative rates
   - Performance benchmarking
```

## 检查器实现 (Checker)
```cpp
//== UninitChecker.cpp - Uninitialized memory access checker -*- C++ -*-==//
//
// This checker detects potential uninitialized memory access vulnerabilities,
// particularly in kernel code where information leakage can occur.
//
//===----------------------------------------------------------------------===//

#include \"clang/ASTMatchers/ASTMatchFinder.h\"
#include \"clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h\"
#include \"clang/StaticAnalyzer/Core/Checker.h\"
#include \"clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h\"

using namespace clang;
using namespace ento;
using namespace ast_matchers;

namespace {
class UninitChecker : public Checker<check::PreCall, check::PostCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
};

void UninitChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  // Check for kmalloc calls without __GFP_ZERO
  if (const IdentifierInfo *ID = Call.getCalleeIdentifier()) {
    if (ID->getName() == \"kmalloc\") {
      // Check if __GFP_ZERO flag is present
      bool hasZeroFlag = false;
      for (unsigned i = 0; i < Call.getNumArgs(); ++i) {
        SVal arg = Call.getArgSVal(i);
        // Analyze the flags argument
        if (i == 1) { // flags argument
          // Check if __GFP_ZERO is set
          // Implementation details...
        }
      }

      if (!hasZeroFlag) {
        // Report potential uninitialized memory access
        if (!BT)
          BT.reset(new BugType(this, \"Uninitialized memory access\", \"Memory Error\"));

        ExplodedNode *N = C.generateNonFatalErrorNode();
        if (N) {
          auto Report = std::make_unique<PathSensitiveBugReport>(
              *BT, \"kmalloc without __GFP_ZERO may leak uninitialized memory\", N);
          C.emitReport(std::move(Report));
        }
      }
    }
  }
}

void UninitChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  // Track memory allocation and usage
  // Implementation details...
}

} // end anonymous namespace

void ento::registerUninitChecker(CheckerManager &mgr) {
  mgr.registerChecker<UninitChecker>();
}
```
"""
        }

        entry = KnowledgeEntry(
            id="",
            content=uninit_example["content"],
            title=uninit_example["title"],
            category="code_examples",
            framework="clang",
            language="cpp",
            metadata={
                "example_type": "complete_vulnerability_analysis",
                "source": "knighter_examples",
                "description": uninit_example["description"],
                "vulnerability_type": "uninit",
                "includes": ["pattern", "patch", "plan", "checker"],
                "project": "knighter"
            }
        )
        entries.append(entry)

        print(f"✅ 收集到KNighter完整示例: {len(entries)} 条")
        return entries

    def _collect_knighter_embedded_prompts(self) -> List[KnowledgeEntry]:
        """收集KNighter的prompt模板（已内嵌）"""
        entries = []

        knighter_prompts = {
            "patch2pattern": {
                "title": "KNighter Patch到Pattern转换提示",
                "description": "将安全补丁转换为漏洞模式描述的提示模板",
                "content": """
# KNighter Patch到Pattern转换提示词

## 系统提示词
```
You are a security expert specializing in static analysis and vulnerability pattern recognition.
Your task is to analyze a security patch and extract the underlying vulnerability pattern.

Given a code patch that fixes a security vulnerability, you need to:
1. Understand what vulnerability the patch fixes
2. Identify the root cause and security implications
3. Extract the generalizable vulnerability pattern
4. Describe the pattern in a way that can be used for static analysis

Focus on:
- The security vulnerability type (e.g., CWE classification)
- The code patterns that indicate the vulnerability
- The conditions that make code vulnerable
- The patch's approach to fixing the vulnerability

Provide your analysis in a structured format that can be used to generate static analysis rules.
```

## 用户提示词模板
```
Analyze this security patch and extract the vulnerability pattern:

## Patch Information
{patch_description}

## Original Vulnerable Code
```c
{original_code}
```

## Fixed Code
```c
{fixed_code}
```

## Patch Diff
```diff
{patch_diff}
```

Based on this patch, answer the following questions:

1. **Vulnerability Type**: What type of vulnerability does this patch fix? (e.g., CWE-XXX)

2. **Root Cause**: What is the fundamental security issue?

3. **Vulnerable Pattern**: What code patterns indicate this vulnerability?

4. **Trigger Conditions**: What conditions must be met for this vulnerability to be exploitable?

5. **Detection Rules**: What static analysis rules could detect this vulnerability?

6. **Prevention**: How can similar vulnerabilities be prevented?

Provide detailed analysis with code examples and detection logic.
```

## 示例输出格式
```
## Vulnerability Analysis Report

### 1. Vulnerability Type
**CWE-401: Memory Leak** (or appropriate CWE)

### 2. Root Cause
The original code allocates memory using `kmalloc()` but fails to release it under certain error conditions, leading to memory exhaustion attacks.

### 3. Vulnerable Pattern
```c
// Pattern: Memory allocation without proper cleanup
void vulnerable_function() {
    void *ptr = kmalloc(size, GFP_KERNEL);  // Allocation
    if (!ptr) return;                       // Early return without free

    // ... use ptr ...

    if (error_condition) {
        // BUG: Missing kfree(ptr) before return
        return;
    }

    kfree(ptr);  // Correct cleanup only in success path
}
```

### 4. Detection Rules
- **AST Analysis**: Find `kmalloc()` calls
- **Control Flow**: Track error paths
- **Memory Management**: Verify `kfree()` on all exit paths
- **Pattern Matching**: Identify allocation without cleanup

### 5. Static Analysis Implementation
```cpp
// Clang AST Matcher for memory leak detection
auto MemoryLeakPattern = functionDecl(
    forEachDescendant(
        stmt(anyOf(
            returnStmt(),
            gotoStmt(),
            breakStmt(),
            continueStmt()
        ))
    ),
    hasDescendant(
        callExpr(callee(functionDecl(hasName("kmalloc"))))
    )
).bind("function");
```

### 6. Prevention Guidelines
- Always pair `kmalloc()` with `kfree()`
- Use RAII patterns where possible
- Implement proper error handling
- Use static analysis tools during development
```
"""
            },
            "pattern2plan": {
                "title": "KNighter Pattern到Plan转换提示",
                "description": "将漏洞模式转换为实现计划的提示模板",
                "content": """
# KNighter Pattern到Plan转换提示词

## 系统提示词
```
You are an expert static analysis engineer tasked with implementing security checkers.
Given a vulnerability pattern description, you need to create a detailed implementation plan
for a Clang Static Analyzer checker that can detect this vulnerability.

Your plan should include:
1. AST analysis strategies
2. Data flow analysis requirements
3. Checker implementation steps
4. Testing and validation approaches
5. Performance considerations

Focus on creating a robust, efficient, and accurate checker implementation.
```

## 用户提示词模板
```
Convert this vulnerability pattern into a detailed implementation plan for a Clang Static Analyzer checker:

## Vulnerability Pattern
{pattern_description}

## Vulnerable Code Example
```c
{vulnerable_code}
```

## Fixed Code Example
```c
{fixed_code}
```

## Detection Requirements
- **Precision**: Minimize false positives
- **Recall**: Catch all instances of the vulnerability
- **Performance**: Efficient analysis without significant slowdown

Create a detailed implementation plan including:

1. **AST Analysis Phase**
   - What AST nodes to match
   - Pattern matching strategies
   - Code structure analysis

2. **Data Flow Analysis Phase**
   - Information flow tracking
   - State management requirements
   - Path-sensitive analysis needs

3. **Checker Implementation**
   - Class structure and methods
   - Bug reporting mechanisms
   - Checker registration

4. **Testing Strategy**
   - Test cases design
   - False positive/negative validation
   - Performance benchmarking

5. **Edge Cases and Limitations**
   - Known limitations
   - Future improvements
   - Alternative approaches
```

## 示例实现计划
```
## Implementation Plan: Memory Leak Detection Checker

### 1. AST Analysis Phase

#### Target AST Nodes
- `FunctionDecl`: Analyze function bodies for memory operations
- `CallExpr`: Identify `kmalloc()` and `kfree()` calls
- `ReturnStmt`: Check cleanup on function exit
- `IfStmt`: Handle conditional cleanup paths

#### Pattern Matching
```cpp
auto KmallocCall = callExpr(callee(functionDecl(hasName("kmalloc"))));
auto KfreeCall = callExpr(callee(functionDecl(hasName("kfree"))));
auto ReturnStmt = returnStmt();
```

#### Structural Analysis
- Build allocation-deallocation mapping
- Track memory ownership transfer
- Identify error handling paths

### 2. Data Flow Analysis Phase

#### Memory State Tracking
```cpp
// Track allocated memory regions
REGISTER_MAP_WITH_PROGRAMSTATE(MemoryAllocationMap, const MemRegion *, AllocationInfo)

// AllocationInfo structure
struct AllocationInfo {
  bool isFreed;
  SourceLocation allocLocation;
  const Expr *allocExpr;
};
```

#### Path-Sensitive Analysis
- Track memory allocation points
- Monitor deallocation calls
- Detect missing cleanup on error paths

#### State Transitions
- Allocation: Create new memory tracking state
- Deallocation: Mark memory as freed
- Function exit: Check for unfreed memory

### 3. Checker Implementation

#### Class Structure
```cpp
class MemoryLeakChecker : public Checker<
    check::PreCall,    // Monitor allocation calls
    check::PostCall,   // Monitor deallocation calls
    check::EndFunction // Check for leaks at function exit
> {
private:
  mutable std::unique_ptr<BugType> BT;

public:
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const;
};
```

#### Bug Reporting
```cpp
void reportMemoryLeak(CheckerContext &C, const MemRegion *region,
                     SourceLocation loc) const {
  if (!BT) {
    BT.reset(new BugType(this, "Memory leak", "Memory Error"));
  }

  std::string description = "Memory allocated here is not freed";
  auto report = std::make_unique<PathSensitiveBugReport>(*BT, description, C);
  report->addNote(loc, "Memory allocated here");
  C.emitReport(std::move(report));
}
```

### 4. Testing Strategy

#### Test Cases
```cpp
// Positive test cases (should report)
void test_memory_leak() {
  void *ptr = kmalloc(size, GFP_KERNEL);
  if (!ptr) return;  // Leak: no kfree
}

void test_conditional_leak() {
  void *ptr = kmalloc(size, GFP_KERNEL);
  if (error) {
    return;  // Leak: no kfree in error path
  }
  kfree(ptr);  // OK: freed in success path
}

// Negative test cases (should not report)
void test_no_leak() {
  void *ptr = kmalloc(size, GFP_KERNEL);
  if (!ptr) return 0;
  kfree(ptr);
  return 0;
}
```

#### Validation Metrics
- **Precision**: TP / (TP + FP) > 0.8
- **Recall**: TP / (TP + FN) > 0.9
- **Performance**: < 10% analysis time overhead

### 5. Edge Cases and Limitations

#### Known Limitations
- Complex ownership transfer patterns
- Inter-procedural analysis limitations
- Macro-based memory management
- Custom allocator functions

#### Future Improvements
- Inter-procedural analysis enhancement
- Custom allocator recognition
- Ownership transfer tracking
- Integration with external allocation libraries
```
"""
            },
            "plan2checker": {
                "title": "KNighter Plan到Checker实现提示",
                "description": "将实现计划转换为具体检查器代码的提示模板",
                "content": """
# KNighter Plan到Checker实现提示词

## 系统提示词
```
You are a Clang Static Analyzer expert. Given a detailed implementation plan for a security checker,
you need to generate the actual C++ code that implements the checker according to the plan.

Your implementation should:
1. Follow Clang Static Analyzer coding conventions
2. Include proper error handling and edge case management
3. Provide clear documentation and comments
4. Implement efficient algorithms with good performance
5. Include checker registration and bug type definitions

Generate production-ready code that can be compiled and integrated into Clang.
```

## 用户提示词模板
```
Implement a Clang Static Analyzer checker based on this detailed plan:

## Implementation Plan Summary
{plan_summary}

## Key Components Required
{required_components}

## AST Analysis Requirements
{ast_requirements}

## Data Flow Analysis Requirements
{data_flow_requirements}

## Bug Reporting Requirements
{reporting_requirements}

Generate the complete C++ implementation including:

1. **Header and Includes**
2. **Checker Class Definition**
3. **AST Matching Logic**
4. **Data Flow Analysis**
5. **Bug Reporting Implementation**
6. **Checker Registration**
7. **Helper Functions and Utilities**

Ensure the code follows Clang coding standards and includes comprehensive comments.
```

## 完整实现示例：内存泄漏检查器

### 头文件和包含
```cpp
//== MemoryLeakChecker.h - Memory leak detection checker -*- C++ -*-==//
//
// This file defines MemoryLeakChecker which detects potential memory leaks
// in C/C++ code by tracking allocation and deallocation patterns.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_CLANG_STATIC_ANALYZER_CHECKERS_MEMORYLEAKCHECKER_H
#define LLVM_CLANG_STATIC_ANALYZER_CHECKERS_MEMORYLEAKCHECKER_H

#include \"clang/StaticAnalyzer/Core/BugReporter/BugType.h\"
#include \"clang/StaticAnalyzer/Core/Checker.h\"
#include \"clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h\"
#include \"clang/StaticAnalyzer/Core/PathSensitive/ProgramState.h\"
#include \"clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h\"

namespace clang {
namespace ento {

// Memory allocation information
struct AllocationInfo {
  bool isFreed = false;
  const clang::Stmt *allocStmt = nullptr;
  unsigned allocationFamily = 0;

  AllocationInfo() = default;
  AllocationInfo(const clang::Stmt *stmt, unsigned family)
      : allocStmt(stmt), allocationFamily(family) {}
};

// Program state trait for tracking memory allocations
REGISTER_MAP_WITH_PROGRAMSTATE(MemoryAllocationMap,
                               const clang::MemRegion *,
                               AllocationInfo)

class MemoryLeakChecker : public Checker<check::PreCall,
                                        check::PostCall,
                                        check::EndFunction,
                                        check::DeadSymbols> {
private:
  mutable std::unique_ptr<BugType> BT;

  // Call descriptions for memory functions
  CallDescription mallocDesc{"malloc", 1};
  CallDescription callocDesc{"calloc", 2};
  CallDescription reallocDesc{"realloc", 2};
  CallDescription freeDesc{"free", 1};

  // C++ memory functions
  CallDescription newDesc{"operator new", 1, /*isMethod=*/false};
  CallDescription newArrayDesc{"operator new[]", 1, /*isMethod=*/false};
  CallDescription deleteDesc{"operator delete", 1, /*isMethod=*/false};
  CallDescription deleteArrayDesc{"operator delete[]", 1, /*isMethod=*/false};

public:
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const;
  void checkDeadSymbols(SymbolReaper &SymReaper, CheckerContext &C) const;

private:
  // Helper methods
  bool isMemoryAllocation(const CallEvent &Call) const;
  bool isMemoryDeallocation(const CallEvent &Call) const;
  void reportMemoryLeak(const MemRegion *region,
                       const AllocationInfo &info,
                       CheckerContext &C) const;
  unsigned getAllocationFamily(const CallEvent &Call) const;
};

} // end namespace ento
} // end namespace clang

#endif // LLVM_CLANG_STATIC_ANALYZER_CHECKERS_MEMORYLEAKCHECKER_H
```

### 实现文件
```cpp
//== MemoryLeakChecker.cpp - Memory leak detection checker -*- C++ -*-==//
//
// This file implements MemoryLeakChecker which detects potential memory leaks
// in C/C++ code by tracking allocation and deallocation patterns.
//
//===----------------------------------------------------------------------===//

#include \"MemoryLeakChecker.h\"
#include \"clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h\"

using namespace clang;
using namespace ento;

void MemoryLeakChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  if (isMemoryDeallocation(Call)) {
    // Check if we're freeing memory that was allocated
    ProgramStateRef State = C.getState();

    // Get the memory region being freed
    SVal AddrVal = Call.getArgSVal(0);
    const MemRegion *MR = AddrVal.getAsRegion();
    if (!MR)
      return;

    // Find the base region (for arrays, etc.)
    const MemRegion *BaseMR = MR->getBaseRegion();

    // Check if this region was allocated by us
    const AllocationInfo *Info = State->get<MemoryAllocationMap>(BaseMR);
    if (!Info)
      return; // Not allocated by us, ignore

    // Mark as freed
    AllocationInfo UpdatedInfo = *Info;
    UpdatedInfo.isFreed = true;

    State = State->set<MemoryAllocationMap>(BaseMR, UpdatedInfo);
    C.addTransition(State);
  }
}

void MemoryLeakChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  if (isMemoryAllocation(Call)) {
    // Track new memory allocation
    ProgramStateRef State = C.getState();

    // Get the allocated memory region
    SVal RetVal = Call.getReturnValue();
    const MemRegion *MR = RetVal.getAsRegion();
    if (!MR)
      return;

    // Record the allocation
    unsigned Family = getAllocationFamily(Call);
    AllocationInfo Info(Call.getOriginExpr(), Family);

    State = State->set<MemoryAllocationMap>(MR, Info);
    C.addTransition(State);
  }
}

void MemoryLeakChecker::checkEndFunction(const ReturnStmt *RS,
                                        CheckerContext &C) const {
  // Check for memory leaks at function end
  ProgramStateRef State = C.getState();

  // Iterate through all tracked allocations
  for (auto &Entry : State->get<MemoryAllocationMap>()) {
    const MemRegion *Region = Entry.first;
    const AllocationInfo &Info = Entry.second;

    if (!Info.isFreed) {
      // Found a potential memory leak
      reportMemoryLeak(Region, Info, C);
    }
  }
}

void MemoryLeakChecker::checkDeadSymbols(SymbolReaper &SymReaper,
                                        CheckerContext &C) const {
  // Clean up dead symbols and their associated memory regions
  ProgramStateRef State = C.getState();
  MemoryAllocationMapTy TrackedAllocations = State->get<MemoryAllocationMap>();

  // Remove entries for dead symbols
  for (auto I = TrackedAllocations.begin(), E = TrackedAllocations.end(); I != E; ++I) {
    const MemRegion *Region = I->first;
    if (SymReaper.isDead(Region)) {
      State = State->remove<MemoryAllocationMap>(Region);
    }
  }

  C.addTransition(State);
}

bool MemoryLeakChecker::isMemoryAllocation(const CallEvent &Call) const {
  return mallocDesc.matches(Call) || callocDesc.matches(Call) ||
         reallocDesc.matches(Call) || newDesc.matches(Call) ||
         newArrayDesc.matches(Call);
}

bool MemoryLeakChecker::isMemoryDeallocation(const CallEvent &Call) const {
  return freeDesc.matches(Call) || deleteDesc.matches(Call) ||
         deleteArrayDesc.matches(Call);
}

unsigned MemoryLeakChecker::getAllocationFamily(const CallEvent &Call) const {
  if (mallocDesc.matches(Call) || callocDesc.matches(Call) ||
      reallocDesc.matches(Call) || freeDesc.matches(Call)) {
    return AF_Malloc;
  }
  if (newDesc.matches(Call) || newArrayDesc.matches(Call) ||
      deleteDesc.matches(Call) || deleteArrayDesc.matches(Call)) {
    return AF_CXXNew;
  }
  return 0;
}

void MemoryLeakChecker::reportMemoryLeak(const MemRegion *Region,
                                        const AllocationInfo &Info,
                                        CheckerContext &C) const {
  if (!BT) {
    BT.reset(new BugType(this, "Memory leak", "Memory Error"));
  }

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  std::string Description = "Memory is never released after this allocation";
  auto Report = std::make_unique<PathSensitiveBugReport>(*BT, Description, N);

  if (Info.allocStmt) {
    Report->addNote(Info.allocStmt->getSourceRange().getBegin(),
                   "Memory allocated here");
  }

  C.emitReport(std::move(Report));
}

// Checker registration
void ento::registerMemoryLeakChecker(CheckerManager &Mgr) {
  Mgr.registerChecker<MemoryLeakChecker>();
}

bool ento::shouldRegisterMemoryLeakChecker(const CheckerManager &Mgr) {
  return true;
}
```

## 关键实现要点

### 1. 状态管理
- 使用 `REGISTER_MAP_WITH_PROGRAMSTATE` 跟踪内存分配
- 维护分配信息（是否释放、分配位置、分配家族）

### 2. 调用事件处理
- `checkPreCall`: 检查释放操作前的状态
- `checkPostCall`: 跟踪新的内存分配
- `checkEndFunction`: 函数结束时检查泄漏
- `checkDeadSymbols`: 清理死符号

### 3. 内存区域跟踪
- 获取分配的内存区域
- 处理数组和复杂内存结构
- 跟踪基础区域（base region）

### 4. 错误报告
- 生成详细的错误报告
- 包含分配位置信息
- 提供修复建议

### 5. 性能优化
- 只跟踪相关的内存分配
- 及时清理死符号
- 避免过度分析

这个实现提供了一个完整的、生产就绪的内存泄漏检测检查器，可以检测各种类型的内存泄漏问题。
```
"""
            }
        }

        for prompt_name, prompt_data in knighter_prompts.items():
            entry = KnowledgeEntry(
                id="",
                content=prompt_data["content"],
                title=prompt_data["title"],
                category="expert_knowledge",
                framework="general",
                language="general",
                metadata={
                    "prompt_name": prompt_name,
                    "source": "knighter_embedded_prompts",
                    "description": prompt_data["description"],
                    "template_type": "llm_prompt",
                    "project": "knighter"
                }
            )
            entries.append(entry)

        print(f"✅ 收集到KNighter内嵌prompt模板: {len(entries)} 条")
        return entries

    def _collect_knighter_embedded_knowledge(self) -> List[KnowledgeEntry]:
        """收集KNighter的知识库（已内嵌）"""
        entries = []

        knighter_knowledge = {
            "utility": {
                "title": "KNighter实用函数库",
                "description": "Clang AST操作和分析的实用函数",
                "content": """
# KNighter实用函数库

## AST遍历和查找函数

```cpp
// Going upward in an AST tree, and find the Stmt of a specific type
template <typename T>
const T* findSpecificTypeInParents(const Stmt *S, CheckerContext &C);

// Going downward in an AST tree, and find the Stmt of a secific type
// Only return one of the statements if there are many
template <typename T>
const T* findSpecificTypeInChildren(const Stmt *S);
```

### 实现示例
```cpp
template <typename T>
const T* findSpecificTypeInParents(const Stmt *S, CheckerContext &C) {
  if (!S) return nullptr;

  // Traverse up the AST
  for (const Stmt *Current = S; Current; Current = getParentStmt(Current, C)) {
    if (const T *Specific = dyn_cast<T>(Current)) {
      return Specific;
    }
  }

  return nullptr;
}

template <typename T>
const T* findSpecificTypeInChildren(const Stmt *S) {
  if (!S) return nullptr;

  // Simple DFS traversal
  for (const Stmt *Child : S->children()) {
    if (const T *Specific = dyn_cast<T>(Child)) {
      return Specific;
    }

    // Recursively search in children
    if (const T *Found = findSpecificTypeInChildren<T>(Child)) {
      return Found;
    }
  }

  return nullptr;
}
```

## 表达式求值函数

```cpp
bool EvaluateExprToInt(llvm::APSInt &EvalRes, const Expr *expr, CheckerContext &C) {
  Expr::EvalResult ExprRes;
  if (expr->EvaluateAsInt(ExprRes, C.getASTContext())) {
    EvalRes = ExprRes.Val.getInt();
    return true;
  }
  return false;
}

const llvm::APSInt *inferSymbolMaxVal(SymbolRef Sym, CheckerContext &C) {
  ProgramStateRef State = C.getState();
  const llvm::APSInt *maxVal = State->getConstraintManager().getSymMaxVal(State, Sym);
  return maxVal;
}
```

## 数组和字符串处理

```cpp
// The expression should be the DeclRefExpr of the array
bool getArraySizeFromExpr(llvm::APInt &ArraySize, const Expr *E) {
  if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E->IgnoreImplicit())) {
    if (const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
      QualType QT = VD->getType();
      if (const ConstantArrayType *ArrayType = dyn_cast<ConstantArrayType>(QT.getTypePtr())) {
        ArraySize = ArrayType->getSize();
        return true;
      }
    }
  }
  return false;
}

bool getStringSize(llvm::APInt &StringSize, const Expr *E) {
  if (const auto *SL = dyn_cast<StringLiteral>(E->IgnoreImpCasts())) {
    StringSize = llvm::APInt(32, SL->getLength());
    return true;
  }
  return false;
}
```

## 内存区域操作

```cpp
const MemRegion* getMemRegionFromExpr(const Expr* E, CheckerContext &C) {
  ProgramStateRef State = C.getState();
  return State->getSVal(E, C.getLocationContext()).getAsRegion();
}
```

## 解引用函数跟踪

```cpp
struct KnownDerefFunction {
  const char *Name;                    ///< The function name.
  llvm::SmallVector<unsigned, 4> Params; ///< The parameter indices that get dereferenced.
};

// clang-format off
static KnownDerefFunction DerefTable[] = {
  {"memcpy", {1, 2}},     // void *memcpy(void *dest, const void *src, size_t n);
  {"memmove", {1, 2}},    // void *memmove(void *dest, const void *src, size_t n);
  {"memcmp", {0, 1}},     // int memcmp(const void *s1, const void *s2, size_t n);
  {"strcmp", {0, 1}},     // int strcmp(const char *s1, const char *s2);
  {"strncmp", {0, 1}},    // int strncmp(const char *s1, const char *s2, size_t n);
  {"strcpy", {0, 1}},     // char *strcpy(char *dest, const char *src);
  {"strncpy", {0, 1}},    // char *strncpy(char *dest, const char *src, size_t n);
  {"strcat", {0, 1}},     // char *strcat(char *dest, const char *src);
  {"strncat", {0, 1}},    // char *strncat(char *dest, const char *src, size_t n);
  {"sprintf", {0}},       // int sprintf(char *str, const char *format, ...);
  {"snprintf", {0}},      // int snprintf(char *str, size_t size, const char *format, ...);
  {"vsprintf", {0}},      // int vsprintf(char *str, const char *format, va_list ap);
  {"vsnprintf", {0}},     // int vsnprintf(char *str, size_t size, const char *format, va_list ap);
};
// clang-format on

/// \\brief Determines if the given call is to a function known to dereference
///        certain pointer parameters.
///
/// This function looks up the call's callee name in a known table of functions
/// that definitely dereference one or more of their pointer parameters. If the
/// function is found, it appends the 0-based parameter indices that are dereferenced
/// into \\p DerefParams and returns \\c true. Otherwise, it returns \\c false.
///
/// \\param[in] Call        The function call to examine.
/// \\param[out] DerefParams
///     A list of parameter indices that the function is known to dereference.
///
/// \\return \\c true if the function is found in the known-dereference table,
///         \\c false otherwise.
bool functionKnownToDeref(const CallEvent &Call,
                                 llvm::SmallVectorImpl<unsigned> &DerefParams) {
  if (const IdentifierInfo *ID = Call.getCalleeIdentifier()) {
    StringRef FnName = ID->getName();

    for (const auto &Entry : DerefTable) {
      if (FnName.equals(Entry.Name)) {
        // We found the function in our table, copy its param indices
        DerefParams.append(Entry.Params.begin(), Entry.Params.end());
        return true;
      }
    }
  }
  return false;
}
```

## 表达式名称检查

```cpp
/// \\brief Determines if the source text of an expression contains a specified name.
bool ExprHasName(const Expr *E, StringRef Name, CheckerContext &C) {
  if (!E)
    return false;

  // Use const reference since getSourceManager() returns a const SourceManager.
  const SourceManager &SM = C.getSourceManager();
  const LangOptions &LangOpts = C.getLangOpts();
  // Retrieve the source text corresponding to the expression.
  CharSourceRange Range = CharSourceRange::getTokenRange(E->getSourceRange());
  StringRef ExprText = Lexer::getSourceText(Range, SM, LangOpts);

  // Check if the extracted text contains the specified name.
  return ExprText.contains(Name);
}
```

## Clang检查器标准方法

```cpp
void checkPreStmt (const ReturnStmt *DS, CheckerContext &C) const
 // Pre-visit the Statement.

void checkPostStmt (const DeclStmt *DS, CheckerContext &C) const
 // Post-visit the Statement.

void checkPreCall (const CallEvent &Call, CheckerContext &C) const
 // Pre-visit an abstract "call" event.

void checkPostCall (const CallEvent &Call, CheckerContext &C) const
 // Post-visit an abstract "call" event.

void checkBranchCondition (const Stmt *Condition, CheckerContext &Ctx) const
 // Pre-visit of the condition statement of a branch (such as IfStmt).

void checkLocation (SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &) const
 // Called on a load from and a store to a location.

void checkBind (SVal Loc, SVal Val, const Stmt *S, CheckerContext &) const
 // Called on binding of a value to a location.

void checkBeginFunction (CheckerContext &Ctx) const
 // Called when the analyzer core starts analyzing a function, regardless of whether it is analyzed at the top level or is inlined.

void checkEndFunction (const ReturnStmt *RS, CheckerContext &Ctx) const
 // Called when the analyzer core reaches the end of a function being analyzed regardless of whether it is analyzed at the top level or is inlined.

void checkEndAnalysis (ExplodedGraph &G, BugReporter &BR, ExprEngine &Eng) const
 // Called after all the paths in the ExplodedGraph reach end of path.

bool evalCall (const CallEvent &Call, CheckerContext &C) const
 // Evaluates function call.

ProgramStateRef evalAssume (ProgramStateRef State, SVal Cond, bool Assumption) const
 // Handles assumptions on symbolic values.

ProgramStateRef checkRegionChanges (ProgramStateRef State, const InvalidatedSymbols *Invalidated, ArrayRef< const MemRegion * > ExplicitRegions, ArrayRef< const MemRegion * > Regions, const LocationContext *LCtx, const CallEvent *Call) const
 // Called when the contents of one or more regions change.

void checkASTDecl (const FunctionDecl *D, AnalysisManager &Mgr, BugReporter &BR) const
 // Check every declaration in the AST.

void checkASTCodeBody (const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const
 // Check every declaration that has a statement body in the AST.
```

## 实用宏和常量

```cpp
// Common AST matchers
auto isAssignmentOp = binaryOperator(hasOperatorName("="));
auto isComparisonOp = binaryOperator(anyOf(hasOperatorName("=="), hasOperatorName("!="),
                                          hasOperatorName("<"), hasOperatorName("<="),
                                          hasOperatorName(">"), hasOperatorName(">=")));

auto isArithmeticOp = binaryOperator(anyOf(hasOperatorName("+"), hasOperatorName("-"),
                                          hasOperatorName("*"), hasOperatorName("/"),
                                          hasOperatorName("%")));

// Common declaration matchers
auto isGlobalVar = varDecl(hasGlobalStorage());
auto isLocalVar = varDecl(hasLocalStorage());
auto isStaticVar = varDecl(hasStaticStorage());

// Common statement matchers
auto isReturnStmt = returnStmt();
auto isIfStmt = ifStmt();
auto isForStmt = forStmt();
auto isWhileStmt = whileStmt();

// Common expression matchers
auto isNullPtr = gnuNullExpr();
auto isIntegerLiteral = integerLiteral();
auto isStringLiteral = stringLiteral();
auto isCharLiteral = characterLiteral();
```

这个实用函数库提供了Clang Static Analyzer检查器开发所需的核心功能，帮助开发者快速实现复杂的静态分析逻辑。
"""
            },
            "template": {
                "title": "KNighter代码模板",
                "description": "检查器开发的标准代码模板",
                "content": """
# KNighter代码模板

## 基础检查器模板

```cpp
//== CheckerName.cpp - Brief description -*- C++ -*-==//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file defines CheckerName, which [brief description of what it checks].
//
//===----------------------------------------------------------------------===//

#include \"clang/StaticAnalyzer/Core/BugReporter/BugType.h\"
#include \"clang/StaticAnalyzer/Core/Checker.h\"
#include \"clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h\"
#include \"clang/StaticAnalyzer/Core/PathSensitive/ProgramState.h\"

using namespace clang;
using namespace ento;

namespace {
class CheckerName : public Checker<CHECKER_CALLBACKS> {
  mutable std::unique_ptr<BugType> BT;

public:
  // Checker callback methods
  CALLBACK_METHOD_DECLARATIONS

private:
  // Helper methods
  HELPER_METHOD_DECLARATIONS
};

IMPLEMENTATION

} // end anonymous namespace

void ento::registerCheckerName(CheckerManager &mgr) {
  mgr.registerChecker<CheckerName>();
}

bool ento::shouldRegisterCheckerName(const CheckerManager &mgr) {
  return true;
}
```

## 状态跟踪检查器模板

```cpp
//== StateTrackingChecker.cpp - State tracking checker template -*- C++ -*-==//
//
// This template demonstrates how to track program state across different
// program points in a Clang Static Analyzer checker.
//
//===----------------------------------------------------------------------===//

#include \"clang/StaticAnalyzer/Core/BugReporter/BugType.h\"
#include \"clang/StaticAnalyzer/Core/Checker.h\"
#include \"clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h\"
#include \"clang/StaticAnalyzer/Core/PathSensitive/ProgramState.h\"
#include \"clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h\"

using namespace clang;
using namespace ento;

// Define the state information structure
struct StateInfo {
  bool flag1 = false;
  int counter = 0;
  const Stmt *originStmt = nullptr;

  StateInfo() = default;
  StateInfo(const Stmt *stmt) : originStmt(stmt) {}

  bool operator==(const StateInfo &Other) const {
    return flag1 == Other.flag1 && counter == Other.counter;
  }

  void Profile(llvm::FoldingSetNodeID &ID) const {
    ID.AddBoolean(flag1);
    ID.AddInteger(counter);
  }
};

// Register the state trait
REGISTER_MAP_WITH_PROGRAMSTATE(StateMap, const MemRegion *, StateInfo)

namespace {
class StateTrackingChecker : public Checker<check::PreCall, check::PostCall> {
  mutable std::unique_ptr<BugType> BT;

  // Call descriptions
  CallDescription InitDesc{\"init_function\", 1};
  CallDescription UseDesc{\"use_function\", 1};
  CallDescription CleanupDesc{\"cleanup_function\", 1};

public:
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;

private:
  void reportIssue(CheckerContext &C, const char *Message,
                  const MemRegion *Region = nullptr) const;
};

void StateTrackingChecker::checkPreCall(const CallEvent &Call,
                                       CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  if (InitDesc.matches(Call)) {
    // Handle initialization
    SVal Target = Call.getArgSVal(0);
    const MemRegion *MR = Target.getAsRegion();

    if (MR) {
      StateInfo Info(Call.getOriginExpr());
      State = State->set<StateMap>(MR, Info);
      C.addTransition(State);
    }
  }
  else if (UseDesc.matches(Call)) {
    // Check state before use
    SVal Target = Call.getArgSVal(0);
    const MemRegion *MR = Target.getAsRegion();

    if (MR) {
      const StateInfo *Info = State->get<StateMap>(MR);
      if (Info && !Info->flag1) {
        reportIssue(C, \"Using resource before proper initialization\", MR);
      }
    }
  }
  else if (CleanupDesc.matches(Call)) {
    // Handle cleanup
    SVal Target = Call.getArgSVal(0);
    const MemRegion *MR = Target.getAsRegion();

    if (MR) {
      const StateInfo *Info = State->get<StateMap>(MR);
      if (Info && Info->counter > 0) {
        reportIssue(C, \"Cleaning up resource that is still in use\", MR);
      }
      else {
        // Remove from tracking
        State = State->remove<StateMap>(MR);
        C.addTransition(State);
      }
    }
  }
}

void StateTrackingChecker::checkPostCall(const CallEvent &Call,
                                        CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  if (InitDesc.matches(Call)) {
    // Update state after initialization
    SVal Target = Call.getArgSVal(0);
    const MemRegion *MR = Target.getAsRegion();

    if (MR) {
      const StateInfo *ExistingInfo = State->get<StateMap>(MR);
      if (ExistingInfo) {
        StateInfo UpdatedInfo = *ExistingInfo;
        UpdatedInfo.flag1 = true;
        State = State->set<StateMap>(MR, UpdatedInfo);
        C.addTransition(State);
      }
    }
  }
  else if (UseDesc.matches(Call)) {
    // Update usage counter
    SVal Target = Call.getArgSVal(0);
    const MemRegion *MR = Target.getAsRegion();

    if (MR) {
      const StateInfo *ExistingInfo = State->get<StateMap>(MR);
      if (ExistingInfo) {
        StateInfo UpdatedInfo = *ExistingInfo;
        UpdatedInfo.counter++;
        State = State->set<StateMap>(MR, UpdatedInfo);
        C.addTransition(State);
      }
    }
  }
}

void StateTrackingChecker::reportIssue(CheckerContext &C, const char *Message,
                                      const MemRegion *Region) const {
  if (!BT) {
    BT.reset(new BugType(this, \"State Tracking Issue\", \"Logic Error\"));
  }

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N) return;

  auto Report = std::make_unique<PathSensitiveBugReport>(*BT, Message, N);
  if (Region) {
    Report->addNote(Region->getSourceLocation(),
                   \"Issue related to this region\");
  }

  C.emitReport(std::move(Report));
}

} // end anonymous namespace

void ento::registerStateTrackingChecker(CheckerManager &mgr) {
  mgr.registerChecker<StateTrackingChecker>();
}

bool ento::shouldRegisterStateTrackingChecker(const CheckerManager &mgr) {
  return true;
}
```

## AST匹配检查器模板

```cpp
//== ASTMatcherChecker.cpp - AST matching checker template -*- C++ -*-==//
//
// This template demonstrates how to use AST matchers to find specific
// code patterns in a Clang Static Analyzer checker.
//
//===----------------------------------------------------------------------===//

#include \"clang/ASTMatchers/ASTMatchFinder.h\"
#include \"clang/StaticAnalyzer/Core/BugReporter/BugType.h\"
#include \"clang/StaticAnalyzer/Core/Checker.h\"

using namespace clang;
using namespace ento;
using namespace ast_matchers;

namespace {
class ASTMatcherChecker : public Checker<check::ASTCodeBody> {
  mutable std::unique_ptr<BugType> BT;

public:
  void checkASTCodeBody(const Decl *D, AnalysisManager &AM,
                       BugReporter &BR) const;

private:
  void reportIssue(const BoundNodes &Nodes, const Decl *D,
                  BugReporter &BR, AnalysisManager &AM) const;
};

// Define the AST matcher pattern
auto createMatcher() -> decltype(decl()) {
  // Example: Find assignments to null pointers
  return decl(forEachDescendant(
    binaryOperator(
      hasOperatorName(\"=\"),
      hasLHS(unaryOperator(
        hasOperatorName(\"*\"),
        hasUnaryOperand(gnuNullExpr())
      ))
    ).bind(\"assignment\")
  ));
}

void ASTMatcherChecker::checkASTCodeBody(const Decl *D, AnalysisManager &AM,
                                        BugReporter &BR) const {
  // Create the matcher
  auto Matcher = createMatcher();

  // Run the matcher
  auto Matches = match(Matcher, *D, AM.getASTContext());

  // Process matches
  for (const auto &Match : Matches) {
    reportIssue(Match, D, BR, AM);
  }
}

void ASTMatcherChecker::reportIssue(const BoundNodes &Nodes, const Decl *D,
                                   BugReporter &BR, AnalysisManager &AM) const {
  if (!BT) {
    BT.reset(new BugType(this, \"AST Pattern Issue\", \"Logic Error\"));
  }

  // Get the matched node
  const Stmt *IssueStmt = Nodes.getNodeAs<Stmt>(\"assignment\");
  if (!IssueStmt) return;

  // Create path diagnostic location
  PathDiagnosticLocation Location =
    PathDiagnosticLocation::createBegin(IssueStmt, BR.getSourceManager(), AM.getAnalysisDeclContext(D));

  // Create the report
  std::string Description = \"Found problematic AST pattern\";
  BR.EmitBasicReport(AM.getAnalysisDeclContext(D), this,
                    \"AST Pattern Violation\", \"Logic Error\",
                    Description, Location, IssueStmt->getSourceRange());
}

} // end anonymous namespace

void ento::registerASTMatcherChecker(CheckerManager &mgr) {
  mgr.registerChecker<ASTMatcherChecker>();
}

bool ento::shouldRegisterASTMatcherChecker(const CheckerManager &mgr) {
  return true;
}
```

## 数据流分析检查器模板

```cpp
//== DataFlowChecker.cpp - Data flow analysis checker template -*- C++ -*-==//
//
// This template demonstrates how to implement data flow analysis
// in a Clang Static Analyzer checker.
//
//===----------------------------------------------------------------------===//

#include \"clang/StaticAnalyzer/Core/BugReporter/BugType.h\"
#include \"clang/StaticAnalyzer/Core/Checker.h\"
#include \"clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h\"
#include \"clang/StaticAnalyzer/Core/PathSensitive/ProgramState.h\"
#include \"clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h\"

using namespace clang;
using namespace ento;

// Define taint information
struct TaintInfo {
  bool isTainted = false;
  const Stmt *sourceStmt = nullptr;

  TaintInfo() = default;
  TaintInfo(const Stmt *stmt) : isTainted(true), sourceStmt(stmt) {}
};

// Register taint state
REGISTER_MAP_WITH_PROGRAMSTATE(TaintMap, SymbolRef, TaintInfo)

namespace {
class DataFlowChecker : public Checker<check::PostCall,
                                      check::PreStmt<BinaryOperator>,
                                      check::Location> {
  mutable std::unique_ptr<BugType> BT;

  // Source functions (introduce taint)
  CallDescription SourceDesc{\"gets\", 1};
  CallDescription SourceDesc2{\"getenv\", 1};

  // Sink functions (use tainted data dangerously)
  CallDescription SinkDesc{\"system\", 1};
  CallDescription SinkDesc2{\"exec\", 1};

public:
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreStmt(const BinaryOperator *BO, CheckerContext &C) const;
  void checkLocation(SVal Loc, bool IsLoad, const Stmt *S,
                    CheckerContext &C) const;

private:
  bool isTaintSource(const CallEvent &Call) const;
  bool isTaintSink(const CallEvent &Call) const;
  void reportTaintIssue(CheckerContext &C, const char *Message) const;
};

bool DataFlowChecker::isTaintSource(const CallEvent &Call) const {
  return SourceDesc.matches(Call) || SourceDesc2.matches(Call);
}

bool DataFlowChecker::isTaintSink(const CallEvent &Call) const {
  return SinkDesc.matches(Call) || SinkDesc2.matches(Call);
}

void DataFlowChecker::checkPostCall(const CallEvent &Call,
                                   CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  if (isTaintSource(Call)) {
    // Mark return value as tainted
    SymbolRef Sym = Call.getReturnValue().getAsSymbol();
    if (Sym) {
      TaintInfo Info(Call.getOriginExpr());
      State = State->set<TaintMap>(Sym, Info);
      C.addTransition(State);
    }
  }
  else if (isTaintSink(Call)) {
    // Check if argument is tainted
    SVal Arg = Call.getArgSVal(0);
    SymbolRef Sym = Arg.getAsSymbol();

    if (Sym) {
      const TaintInfo *Info = State->get<TaintMap>(Sym);
      if (Info && Info->isTainted) {
        reportTaintIssue(C, \"Tainted data flows to dangerous sink\");
      }
    }
  }
}

void DataFlowChecker::checkPreStmt(const BinaryOperator *BO,
                                  CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  if (BO->getOpcode() == BO_Assign) {
    // Track taint through assignments
    SVal LHS = C.getSVal(BO->getLHS());
    SVal RHS = C.getSVal(BO->getRHS());

    SymbolRef LHSSym = LHS.getAsSymbol();
    SymbolRef RHSSym = RHS.getAsSymbol();

    if (LHSSym && RHSSym) {
      const TaintInfo *RHSInfo = State->get<TaintMap>(RHSSym);
      if (RHSInfo && RHSInfo->isTainted) {
        // Propagate taint to LHS
        State = State->set<TaintMap>(LHSSym, *RHSInfo);
        C.addTransition(State);
      }
    }
  }
}

void DataFlowChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S,
                                   CheckerContext &C) const {
  // Additional taint propagation logic can be added here
  // For example, tracking taint through memory operations
}

void DataFlowChecker::reportTaintIssue(CheckerContext &C,
                                      const char *Message) const {
  if (!BT) {
    BT.reset(new BugType(this, \"Taint Issue\", \"Security Error\"));
  }

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N) return;

  auto Report = std::make_unique<PathSensitiveBugReport>(*BT, Message, N);
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

void ento::registerDataFlowChecker(CheckerManager &mgr) {
  mgr.registerChecker<DataFlowChecker>();
}

bool ento::shouldRegisterDataFlowChecker(const CheckerManager &mgr) {
  return true;
}
```

## 错误报告增强模板

```cpp
//== EnhancedReportingChecker.cpp - Enhanced reporting template -*- C++ -*-==//
//
// This template demonstrates advanced bug reporting techniques
// including notes, ranges, and fix suggestions.
//
//===----------------------------------------------------------------------===//

#include \"clang/StaticAnalyzer/Core/BugReporter/BugType.h\"
#include \"clang/StaticAnalyzer/Core/Checker.h\"
#include \"clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h\"

using namespace clang;
using namespace ento;

namespace {
class EnhancedReportingChecker : public Checker<check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

  CallDescription BadCall{\"problematic_function\", 1};

public:
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  void reportEnhancedIssue(const CallEvent &Call, CheckerContext &C) const;
};

void EnhancedReportingChecker::checkPreCall(const CallEvent &Call,
                                           CheckerContext &C) const {
  if (BadCall.matches(Call)) {
    reportEnhancedIssue(Call, C);
  }
}

void EnhancedReportingChecker::reportEnhancedIssue(const CallEvent &Call,
                                                  CheckerContext &C) const {
  if (!BT) {
    BT.reset(new BugType(this, \"Enhanced Issue\", \"Logic Error\"));
  }

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N) return;

  // Create main report
  std::string MainMessage = \"Found problematic function call\";
  auto Report = std::make_unique<PathSensitiveBugReport>(*BT, MainMessage, N);

  // Add range highlighting
  const Stmt *CallStmt = Call.getOriginExpr();
  if (CallStmt) {
    Report->addRange(CallStmt->getSourceRange());
  }

  // Add notes for additional context
  Report->addNote(Call.getArgExpr(0)->getSourceRange().getBegin(),
                 \"This argument is problematic\");

  // Add fix suggestion
  Report->addFixItHint(FixItHint::CreateReplacement(
    CallStmt->getSourceRange(),
    \"safe_alternative_function(arg)\"
  ));

  C.emitReport(std::move(Report));
}

} // end anonymous namespace

void ento::registerEnhancedReportingChecker(CheckerManager &mgr) {
  mgr.registerChecker<EnhancedReportingChecker>();
}

bool ento::shouldRegisterEnhancedReportingChecker(const CheckerManager &mgr) {
  return true;
}
```

这些模板提供了开发Clang Static Analyzer检查器的标准模式和最佳实践，可以根据具体需求进行定制和扩展。
"""
            },
            "suggestions": {
                "title": "KNighter使用建议",
                "description": "检查器开发和使用的实用建议",
                "content": """
# KNighter使用建议

## 开发环境设置

### 1. LLVM/Clang环境配置
```bash
# 克隆LLVM项目
git clone https://github.com/llvm/llvm-project.git
cd llvm-project

# 创建构建目录
mkdir build && cd build

# 配置CMake
cmake -G Ninja ../llvm \\
  -DLLVM_ENABLE_PROJECTS=\"clang;clang-tools-extra\" \\
  -DCMAKE_BUILD_TYPE=Release \\
  -DLLVM_TARGETS_TO_BUILD=X86 \\
  -DLLVM_ENABLE_ASSERTIONS=ON

# 构建
ninja clang clangStaticAnalyzer
```

### 2. 检查器开发环境
```bash
# 设置环境变量
export LLVM_DIR=/path/to/llvm-install
export CLANG_DIR=/path/to/clang-install

# 验证安装
clang --version
clang -cc1 -analyzer-checker-help | grep "your_checker"
```

## 检查器开发最佳实践

### 1. 代码组织
```
CheckerName/
├── CheckerName.cpp          # 主实现文件
├── CheckerName.h           # 头文件（如果需要）
├── CMakeLists.txt          # 构建配置
└── test/                   # 测试用例
    ├── test_positive.cpp
    ├── test_negative.cpp
    └── expected_output.txt
```

### 2. 命名约定
```cpp
// 类名使用驼峰命名
class MemoryLeakChecker : public Checker<...> { ... };

// 方法名使用驼峰命名
void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

// 变量名使用驼峰或下划线分隔
ProgramStateRef State = C.getState();
const MemRegion *MemoryRegion = ...;

// 常量使用大写下划线分隔
const char *CHECKER_NAME = "MemoryLeakChecker";
static constexpr unsigned MAX_DEPTH = 10;
```

### 3. 错误处理
```cpp
// 始终检查指针有效性
if (!Expr) return;

// 使用断言验证假设
assert(MemRegion && "Memory region should not be null");

// 优雅处理异常情况
try {
  // 可能失败的操作
} catch (const std::exception &E) {
  // 记录错误但不崩溃
  llvm::errs() << "Error: " << E.what() << "\\n";
}
```

### 4. 性能优化
```cpp
// 避免在热路径上进行 expensive 操作
if (ShouldCheck) {  // 快速预检查
  ExpensiveAnalysis();  // 只有在必要时才执行
}

// 使用适当的数据结构
llvm::DenseMap<const MemRegion *, StateInfo> RegionMap;  // O(1)查找
llvm::SmallVector<SymbolRef, 8> Symbols;  // 小对象优化
```

## 测试和验证

### 1. 单元测试
```cpp
// 创建测试文件
// test_memory_leak.cpp
void test_positive() {
  void *ptr = malloc(100);
  // 忘记释放 - 应该报告
}

void test_negative() {
  void *ptr = malloc(100);
  free(ptr);  // 正确释放 - 不应该报告
}
```

### 2. 运行测试
```bash
# 编译测试文件
clang -c test_memory_leak.cpp -emit-ast

# 运行静态分析
clang --analyze test_memory_leak.cpp \\
  -analyzer-checker=your.checker.MemoryLeakChecker \\
  -analyzer-output=text
```

### 3. 验证输出
```bash
# 检查是否报告了预期的错误
# 检查是否没有误报
# 验证错误位置是否准确
```

## 常见问题和解决方案

### 1. 状态管理问题
```cpp
// 问题：忘记更新程序状态
void checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  // 修改状态...
  // 忘记调用 C.addTransition(State);
}

// 解决方案：始终添加状态转换
C.addTransition(State);
```

### 2. 内存区域处理
```cpp
// 问题：没有正确处理内存区域
const MemRegion *MR = Val.getAsRegion();
if (!MR) return;  // 正确

// 忘记处理不同类型的内存区域
// 解决方案：考虑所有内存区域类型
const MemRegion *BaseMR = MR->getBaseRegion();
const SymbolicRegion *SymMR = dyn_cast<SymbolicRegion>(BaseMR);
```

### 3. 符号值处理
```cpp
// 问题：没有正确处理符号值
SVal Val = C.getSVal(Expr);
if (Val.isUnknown()) {
  // 无法确定值，保守处理
  return;
}

SymbolRef Sym = Val.getAsSymbol();
if (!Sym) {
  // 不是符号值，可能需要特殊处理
  return;
}
```

### 4. 路径爆炸
```cpp
// 问题：分析深度过大导致路径爆炸
if (Depth > MAX_DEPTH) {
  // 限制分析深度
  return;
}

// 解决方案：实现合理的限制
const unsigned MAX_DEPTH = 10;
static unsigned CurrentDepth = 0;
if (++CurrentDepth > MAX_DEPTH) return;
```

## 调试技巧

### 1. 日志记录
```cpp
// 添加调试日志
llvm::errs() << "Debug: Processing call to " << FunctionName << "\\n";

// 使用条件编译
#ifndef NDEBUG
  llvm::errs() << "Debug info\\n";
#endif
```

### 2. 断点设置
```cpp
// 在关键位置添加断点
if (ShouldBreak) {
  // 设置断点
  __builtin_trap();
}
```

### 3. 状态可视化
```cpp
// 打印程序状态（调试用）
void dumpState(ProgramStateRef State) {
  State->dump();
}
```

## 部署和集成

### 1. 构建集成
```cmake
# CMakeLists.txt
add_clang_library(MemoryLeakChecker
  MemoryLeakChecker.cpp

  DEPENDS
  clangStaticAnalyzerCore

  LINK_LIBS
  clangStaticAnalyzerCore
  )
```

### 2. 注册检查器
```cpp
// 在CheckerRegistry.cpp中添加
GET_CHECKER*("your.checker.MemoryLeakChecker", MemoryLeakChecker)
```

### 3. 启用检查器
```bash
# 命令行启用
clang --analyze file.cpp -analyzer-checker=your.checker.MemoryLeakChecker

# 或者在代码中启用
// 在分析选项中指定
```

## 性能调优

### 1. 算法优化
- 使用合适的容器类型
- 实现高效的查找算法
- 避免不必要的计算

### 2. 内存优化
- 重用对象而不是频繁分配
- 使用对象池模式
- 及时清理不再需要的状态

### 3. 分析范围控制
- 只分析相关的代码路径
- 实现合理的超时机制
- 提供配置选项控制分析深度

## 维护和更新

### 1. 版本控制
- 保持向后兼容性
- 记录API变更
- 提供迁移指南

### 2. 社区贡献
- 遵循LLVM编码标准
- 提供完整的测试用例
- 编写清晰的文档

### 3. 持续改进
- 收集用户反馈
- 监控性能指标
- 定期更新和维护

这些建议涵盖了Clang Static Analyzer检查器开发的各个方面，帮助开发者构建高质量、高性能的静态分析工具。
"""
            }
        }

        for knowledge_name, knowledge_data in knighter_knowledge.items():
            entry = KnowledgeEntry(
                id="",
                content=knowledge_data["content"],
                title=knowledge_data["title"],
                category="expert_knowledge",
                framework="clang",
                language="cpp",
                metadata={
                    "knowledge_name": knowledge_name,
                    "source": "knighter_embedded_knowledge",
                    "description": knowledge_data["description"],
                    "file_type": "development_guide",
                    "project": "knighter"
                }
            )
            entries.append(entry)

        print(f"✅ 收集到KNighter内嵌知识库: {len(entries)} 条")
        return entries

    def _collect_knighter_embedded_docs(self) -> List[KnowledgeEntry]:
        """收集KNighter的文档（已内嵌）"""
        entries = []

        # KNighter的README和架构文档内容
        knighter_docs = {
            "readme": {
                "title": "KNighter项目README",
                "description": "KNighter项目的完整介绍和使用指南",
                "content": "# KNighter: LLM-Native Static Analysis Framework\\n\\nKNighter is a framework for building LLM-powered static analysis tools for C/C++ code. It leverages large language models to automatically generate, verify, and improve static analysis checkers.\\n\\n## Features\\n\\n### 🤖 LLM-Powered Analysis\\n- **Automatic Checker Generation**: Generate Clang Static Analyzer checkers from natural language descriptions\\n- **Intelligent Bug Detection**: Use LLMs to identify complex vulnerability patterns\\n- **Self-Improving Analysis**: Framework learns from analysis results to improve future detections\\n\\n### 🔧 Static Analysis Integration\\n- **Clang Integration**: Seamless integration with Clang Static Analyzer\\n- **AST Analysis**: Full access to Clang's Abstract Syntax Tree\\n- **Path-Sensitive Analysis**: Support for complex control and data flow analysis\\n\\n### 📚 Knowledge Base\\n- **Comprehensive Patterns**: Extensive collection of vulnerability patterns\\n- **Code Examples**: Real-world examples of security vulnerabilities and fixes\\n- **Expert Knowledge**: Curated security analysis expertise and best practices\\n\\n## Quick Start\\n\\n### Prerequisites\\n```bash\\n# LLVM/Clang (version 14+ recommended)\\nsudo apt install llvm clang\\n\\n# Python dependencies\\npip install openai transformers torch\\n```\\n\\n### Basic Usage\\n```python\\nfrom knighter import LLMStaticAnalyzer\\n\\n# Initialize analyzer\\nanalyzer = LLMStaticAnalyzer()\\n\\n# Analyze code for vulnerabilities\\nresults = analyzer.analyze_file(\\\"target.c\\\", vulnerability_type=\\\"buffer_overflow\\\")\\n\\n# Generate custom checker\\nchecker_code = analyzer.generate_checker(description=\\\"Detect use-after-free vulnerabilities\\\", language=\\\"cpp\\\")\\n```"
            },
            "architecture": {
                "title": "KNighter架构设计文档",
                "description": "KNighter的完整架构设计和实现原理",
                "content": "# KNighter Architecture Design\n\n## Overview\n\nKNighter is an LLM-native static analysis framework that leverages large language models to enhance traditional static analysis techniques. The framework integrates LLM capabilities with formal static analysis methods to provide more intelligent and adaptive vulnerability detection.\n\n## Core Components\n\n### 1. LLM Engine\n- **Prompt Engineering**: Specialized prompts for static analysis tasks\n- **Model Integration**: Support for multiple LLM providers\n- **Response Processing**: Parse and validate LLM outputs\n\n### 2. Static Analysis Backend\n- **Checker Manager**: Manages registration and execution of checkers\n- **AST Processor**: Processes Clang AST with LLM assistance\n- **Data Flow Engine**: Enhanced data flow analysis\n\n### 3. Knowledge Base\n- **Pattern Database**: Vulnerability patterns and detection rules\n- **Code Examples**: Good and bad code examples\n- **Expert Knowledge**: Curated security analysis expertise"
            }
        }

        for doc_name, doc_data in knighter_docs.items():
            entry = KnowledgeEntry(
                id="",
                content=doc_data["content"],
                title=doc_data["title"],
                category="expert_knowledge",
                framework="general",
                language="general",
                metadata={
                    "doc_name": doc_name,
                    "source": "knighter_embedded_docs",
                    "description": doc_data["description"],
                    "file_type": "documentation",
                    "project": "knighter"
                }
            )
            entries.append(entry)

        print(f"✅ 收集到KNighter内嵌文档: {len(entries)} 条")
        return entries
        return entries

    def _collect_iris_query_templates(self) -> List[KnowledgeEntry]:
        """收集IRIS的查询模板"""
        entries = []

        query_templates = {
            "fetch_sources": {
                "title": "污染源识别查询模板",
                "description": "识别程序中的潜在污染源",
                "content": """
# IRIS查询模板: 污染源识别 (fetch_sources.ql)

## 目的
识别程序中可能引入污染数据的来源点。

## 查询实现
```ql
import java
import semmle.code.java.dataflow.DataFlow
private import semmle.code.java.dataflow.ExternalFlow

import MySources

from DataFlow::Node node
where isGPTDetectedSource(node)
select node.toString() as node_str, node.getLocation() as loc
```

## 污染源类型

### 1. 用户输入源
```ql
// HTTP请求参数
predicate isHttpParameter(DataFlow::Node node) {
  exists(MethodCall mc |
    mc.getMethod().getName() in ["getParameter", "getQueryString", "getHeader"] and
    node.asExpr() = mc
  )
}

// 命令行参数
predicate isCommandLineArg(DataFlow::Node node) {
  exists(MethodCall mc |
    mc.getMethod().getName() = "getArgs" and
    node.asExpr() = mc
  )
}
```

### 2. 文件输入源
```ql
// 文件读取
predicate isFileInput(DataFlow::Node node) {
  exists(MethodCall mc |
    mc.getMethod().getName() in ["read", "readLine", "readAllBytes"] and
    node.asExpr() = mc
  )
}

// 网络输入
predicate isNetworkInput(DataFlow::Node node) {
  exists(MethodCall mc |
    mc.getMethod().getName() in ["readFromSocket", "receive", "accept"] and
    node.asExpr() = mc
  )
}
```

### 3. 环境输入源
```ql
// 环境变量
predicate isEnvironmentVar(DataFlow::Node node) {
  exists(MethodCall mc |
    mc.getMethod().getName() = "getenv" and
    node.asExpr() = mc
  )
}

// 系统属性
predicate isSystemProperty(DataFlow::Node node) {
  exists(MethodCall mc |
    mc.getMethod().getName() = "getProperty" and
    node.asExpr() = mc
  )
}
```

## 使用方法

### 1. 定义污染源谓词
```ql
module MySources {
  predicate isSource(DataFlow::Node node) {
    isHttpParameter(node) or
    isFileInput(node) or
    isEnvironmentVar(node)
  }
}
```

### 2. 集成到数据流分析
```ql
module Config implements DataFlow::ConfigSig {
  predicate isSource = MySources::isSource/1;
  predicate isSink = MySinks::isSink/1;
}

module Flow = DataFlow::Global<Config>;
```

## 扩展性

### 自定义污染源
可以根据具体应用场景添加更多的污染源类型：
- 数据库查询结果
- 缓存数据
- 配置文件读取
- API调用返回值

### 上下文感知
考虑调用上下文来更精确地识别污染源：
- 是否在受信任的代码路径中
- 是否已经过验证或清理
- 是否来自内部API调用
"""
            },
            "fetch_sinks": {
                "title": "危险汇点识别查询模板",
                "description": "识别可能执行危险操作的程序点",
                "content": """
# IRIS查询模板: 危险汇点识别 (fetch_sinks.ql)

## 目的
识别程序中可能执行危险操作的汇点。

## 查询实现
```ql
import java
import semmle.code.java.dataflow.DataFlow
private import semmle.code.java.dataflow.ExternalFlow

import MySinks

from DataFlow::Node node
where isGPTDetectedSink(node)
select node.toString() as node_str, node.getLocation() as loc
```

## 危险汇点类型

### 1. 命令执行汇点
```ql
// Runtime.exec() 调用
predicate isRuntimeExec(DataFlow::Node node) {
  exists(MethodCall mc |
    mc.getMethod().getName() = "exec" and
    mc.getReceiver().getType().getName() = "Runtime" and
    node.asExpr() = mc.getArgument(0)
  )
}

// ProcessBuilder 调用
predicate isProcessBuilder(DataFlow::Node node) {
  exists(MethodCall mc |
    mc.getMethod().getName() = "start" and
    mc.getReceiver().getType().getName() = "ProcessBuilder" and
    node.asExpr() = mc
  )
}
```

### 2. SQL查询汇点
```ql
// JDBC Statement执行
predicate isSQLExecution(DataFlow::Node node) {
  exists(MethodCall mc |
    mc.getMethod().getName() in ["executeQuery", "executeUpdate", "execute"] and
    mc.getReceiver().getType().hasName("Statement") and
    node.asExpr() = mc.getArgument(0)
  )
}

// PreparedStatement（需要检查参数设置）
predicate isPreparedStatementSink(DataFlow::Node node) {
  exists(MethodCall mc |
    mc.getMethod().getName() in ["setString", "setInt", "setObject"] and
    mc.getReceiver().getType().hasName("PreparedStatement") and
    node.asExpr() = mc.getArgument(1)
  )
}
```

### 3. 文件操作汇点
```ql
// 文件路径操作
predicate isFileOperation(DataFlow::Node node) {
  exists(MethodCall mc |
    mc.getMethod().getName() in ["createFile", "delete", "renameTo"] and
    mc.getReceiver().getType().hasName("File") and
    node.asExpr() = mc.getArgument(0)
  )
}
```

### 4. Web输出汇点
```ql
// HTTP响应输出
predicate isHttpResponse(DataFlow::Node node) {
  exists(MethodCall mc |
    mc.getMethod().getName() in ["write", "print", "println"] and
    mc.getReceiver().getType().hasName("ServletResponse") and
    node.asExpr() = mc.getArgument(0)
  )
}

// HTML模板渲染
predicate isTemplateRendering(DataFlow::Node node) {
  exists(MethodCall mc |
    mc.getMethod().getName() in ["render", "processTemplate"] and
    node.asExpr() = mc.getArgument(0)
  )
}
```

## 汇点分类

### 高风险汇点
- 命令执行 (Runtime.exec, ProcessBuilder)
- SQL查询 (Statement.execute*)
- 文件系统操作 (File.*, Path.*)

### 中风险汇点
- 网络操作 (Socket.*, URL.*)
- 进程间通信 (IPC)
- 反射调用 (Class.forName, Method.invoke)

### 低风险汇点
- 日志记录 (Logger.*)
- 缓存操作 (Cache.*)
- 配置存储

## 上下文感知

### 1. 信任边界检查
```ql
// 检查是否在受信任的代码中
predicate isInTrustedContext(DataFlow::Node node) {
  exists(Method m |
    node.getEnclosingCallable() = m and
    m.getDeclaringType().getPackage().getName().matches("com.example.trusted.%")
  )
}
```

### 2. 验证检查
```ql
// 检查是否有输入验证
predicate hasValidation(DataFlow::Node node) {
  exists(MethodCall validation |
    validation.getMethod().getName().matches("validate%") and
    DataFlow::localFlow(node, DataFlow::exprNode(validation.getArgument(0)))
  )
}
```

## 配置和使用

### 定义危险汇点模块
```ql
module MySinks {
  predicate isSink(DataFlow::Node node) {
    isRuntimeExec(node) or
    isSQLExecution(node) or
    isHttpResponse(node)
  }
}
```

### 集成到完整分析
```ql
module Config implements DataFlow::ConfigSig {
  predicate isSource = MySources::isSource/1;
  predicate isSink = MySinks::isSink/1;
  predicate isBarrier = MySanitizers::isSanitizer/1;
}

module Flow = DataFlow::Global<Config>;
```

## 扩展和定制

可以根据具体的安全需求添加更多的汇点类型：
- 加密操作 (Cipher.*, Key.*)
- 序列化操作 (ObjectOutputStream.*)
- XML处理 (DocumentBuilder.*)
- 正则表达式 (Pattern.*)
"""
            }
        }

        for template_name, template_data in query_templates.items():
            entry = KnowledgeEntry(
                id="",
                content=template_data["content"],
                title=f"IRIS查询模板: {template_data['title']}",
                category="code_examples",
                framework="codeql",
                language="ql",
                metadata={
                    "template_name": template_name,
                    "source": "iris_query_templates",
                    "description": template_data["description"],
                    "query_type": "analysis_template",
                    "project": "iris"
                }
            )
            entries.append(entry)

        print(f"✅ 收集到IRIS查询模板: {len(entries)} 条")
        return entries

    def _collect_iris_prompts(self) -> List[KnowledgeEntry]:
        """收集IRIS的prompt模板"""
        entries = []

        prompt_templates = {
            "api_labelling": {
                "title": "API标注系统提示词",
                "description": "用于标注API为污染源、汇点或传播器的提示词",
                "content": """
# IRIS API标注系统提示词

## 系统提示词 (System Prompt)
```
You are a security expert. You are given a list of APIs to be labeled as potential taint sources, sinks, or APIs that propagate taints.

Taint sources are values that an attacker can use for unauthorized and malicious operations when interacting with the system. Taint source APIs usually return strings or custom object types. Setter methods are typically NOT taint sources.

Taint sinks are program points that can use tainted data in an unsafe way, which directly exposes vulnerability under attack.

Taint propagators carry tainted information from input to the output without sanitization, and typically have non-primitive input and outputs.

Return the result as a json list with each object in the format:

{ "package": "<package name>",
  "class": "<class name>",
  "method": "<method name>",
  "signature": "<signature of the method>",
  "sink_args": "<list of arguments or `this`; empty if the API is not sink>",
  "type": "<"source", "sink", or "taint-propagator">" }

DO NOT OUTPUT ANYTHING OTHER THAN JSON.
```

## 用户提示词模板 (User Prompt Template)
```
{CWE_long_description}

Some example source/sink/taint-propagator methods are:
{CWE_examples}

Among the following methods, assuming that the arguments passed to the given function is malicious, what are the functions that are potential source, sink, or taint-propagators to {CWE_description} attack (CWE-{CWE_id})?

Package,Class,Method,Signature
{methods}
```

## 使用示例

### 1. CWE-078 (命令注入)
**系统提示词**: 如上所述

**用户提示词**:
```
Command injection vulnerabilities occur when untrusted user input is used to build command strings that are passed to system commands.

Some example source/sink/taint-propagator methods are:
- Source: getParameter(), getQueryString()
- Sink: Runtime.exec(), ProcessBuilder.start()
- Propagator: StringBuilder.append(), String.concat()

Among the following methods, assuming that the arguments passed to the given function is malicious, what are the functions that are potential source, sink, or taint-propagators to command injection attack (CWE-78)?

Package,Class,Method,Signature
java.lang.Runtime,exec,(Ljava/lang/String;)Ljava/lang/Process;
java.lang.ProcessBuilder,start,()Ljava/lang/Process;
java.lang.StringBuilder,append,(Ljava/lang/String;)Ljava/lang/StringBuilder;
```

**期望输出**:
```json
[
  {
    "package": "java.lang",
    "class": "Runtime",
    "method": "exec",
    "signature": "(Ljava/lang/String;)Ljava/lang/Process;",
    "sink_args": ["arg0"],
    "type": "sink"
  },
  {
    "package": "java.lang",
    "class": "ProcessBuilder",
    "method": "start",
    "signature": "()Ljava/lang/Process;",
    "sink_args": ["this"],
    "type": "sink"
  }
]
```

## 标注类型详解

### 污染源 (Source)
- **定义**: 能够引入外部不受信任数据的API
- **特征**:
  - 返回字符串或对象类型
  - 读取外部输入（文件、网络、用户输入等）
  - 不包括setter方法
- **示例**:
  - `HttpServletRequest.getParameter()`
  - `FileReader.read()`
  - `Socket.getInputStream()`

### 危险汇点 (Sink)
- **定义**: 能够使用污染数据执行危险操作的API
- **特征**:
  - 接受污染数据作为参数
  - 执行安全敏感操作（命令执行、SQL查询等）
  - 可能导致安全漏洞
- **示例**:
  - `Runtime.exec(String command)`
  - `Statement.executeQuery(String sql)`
  - `eval(String code)`

### 污染传播器 (Taint Propagator)
- **定义**: 将污染数据从输入传递到输出的API
- **特征**:
  - 输入和输出都是非基本类型
  - 不改变数据的污染性质
  - 复制、转换或传递污染数据
- **示例**:
  - `String.concat(String other)`
  - `StringBuilder.append(String str)`
  - `List.add(Object element)`

## 标注流程

### 1. 理解CWE描述
- 分析漏洞的基本原理
- 识别可能的攻击向量
- 确定相关的源/汇点模式

### 2. 识别API特征
- 检查方法签名和参数
- 分析方法的语义含义
- 考虑方法的调用上下文

### 3. 确定标注类型
- 根据API的功能分类
- 考虑参数的数据流向
- 评估安全风险等级

### 4. 生成标注结果
- 使用标准化的JSON格式
- 包含完整的API信息
- 准确标识污染参数

## 质量保证

### 准确性检查
- 验证API的功能理解是否正确
- 确认标注类型是否合适
- 检查参数标识是否准确

### 一致性保证
- 使用标准化的命名规范
- 遵循统一的标注规则
- 保持结果格式的一致性

### 覆盖率评估
- 检查是否覆盖了主要的安全风险
- 验证标注的完整性和全面性
- 补充遗漏的重要API
"""
            },
            "function_param_labelling": {
                "title": "函数参数标注提示词",
                "description": "用于识别可能接收恶意输入的函数参数",
                "content": """
# IRIS函数参数标注提示词

## 系统提示词 (System Prompt)
```
You are a security expert. You are given a list of APIs implemented in established Java libraries, and you need to identify whether some of these APIs could be potentially invoked by downstream libraries with malicious end-user (not programmer) inputs.

For instance, functions that deserialize or parse inputs might be used by downstream libraries and would need to add sanitization for malicious user inputs. On the other hand, functions that are final and won't be called by a downstream package should be ignored.

Utility functions that are not related to the primary purpose of the package should also be ignored.

Return the result as a json list with each object in the format:

{ "package": "<package name>",
  "class": "<class name>",
  "method": "<method name>",
  "signature": "<signature>",
  "tainted_input": "<a list of argument names that are potentially tainted>" }

In the result list, only keep the functions that might be used by downstream libraries and is potentially invoked with malicious end-user inputs. Do not output anything other than JSON.
```

## 分析框架

### 1. 可调用性评估
确定API是否可能被下游库调用：
- **可调用**: 公共API，可能被框架或库使用
- **不可调用**: 私有方法，仅供内部使用

### 2. 输入风险评估
评估参数是否可能接收恶意输入：
- **高风险**: 解析、反序列化、执行操作
- **中风险**: 数据处理和转换操作
- **低风险**: 简单的数据访问操作

### 3. 上下文相关性
考虑API的使用场景和上下文：
- **相关**: 核心业务逻辑相关的API
- **不相关**: 工具类、配置类API

## 标注标准

### 包含的API类型
```java
// 解析类API
JSON.parse(String jsonString)           // 高风险
XMLParser.parse(InputStream stream)     // 高风险
ObjectMapper.readValue(String content)  // 高风险

// 执行类API
ScriptEngine.eval(String script)        // 高风险
Runtime.exec(String command)           // 高风险
ProcessBuilder.command(String... cmd)  // 高风险

// 数据处理API
SQLStatement.execute(String query)     // 高风险
XPath.evaluate(String expression)      // 中风险
Regex.compile(String pattern)          // 中风险
```

### 排除的API类型
```java
// 私有方法
private void internalProcess()          // 排除

// 仅供框架内部使用
protected Object frameworkOnly()        // 排除

// 工具类方法
StringUtils.isEmpty(String str)         // 排除

// 配置方法
Config.setTimeout(int timeout)          // 排除
```

## 参数命名约定

### 标准参数名称
- `input`, `data`, `content` - 输入数据
- `query`, `sql`, `command` - 查询或命令
- `script`, `code`, `expression` - 可执行代码
- `path`, `file`, `url` - 文件或网络路径
- `xml`, `json`, `config` - 结构化数据

### 索引参数
对于没有参数名的API，使用索引：
- `arg0`, `arg1`, `arg2` - 参数索引

## 使用示例

### 输入API列表
```
Package,Class,Method,Signature
com.fasterxml.jackson.databind,ObjectMapper,readValue,(Ljava/lang/String;)Ljava/lang/Object;
java.lang.Runtime,Runtime,exec,(Ljava/lang/String;)Ljava/lang/Process;
javax.script.ScriptEngine,ScriptEngine,eval,(Ljava/lang/String;)Ljava/lang/Object;
```

### 期望输出
```json
[
  {
    "package": "com.fasterxml.jackson.databind",
    "class": "ObjectMapper",
    "method": "readValue",
    "signature": "(Ljava/lang/String;)Ljava/lang/Object;",
    "tainted_input": ["arg0"]
  },
  {
    "package": "java.lang",
    "class": "Runtime",
    "method": "exec",
    "signature": "(Ljava/lang/String;)Ljava/lang/Process;",
    "tainted_input": ["arg0"]
  },
  {
    "package": "javax.script",
    "class": "ScriptEngine",
    "method": "eval",
    "signature": "(Ljava/lang/String;)Ljava/lang/Object;",
    "tainted_input": ["arg0"]
  }
]
```

## 质量控制

### 1. 准确性验证
- 检查API的功能理解是否正确
- 验证参数标识是否准确
- 确认风险评估是否合理

### 2. 一致性检查
- 统一的参数命名规则
- 标准化的JSON格式
- 一致的评估标准

### 3. 覆盖率评估
- 是否覆盖了主要风险API
- 是否遗漏了重要参数
- 是否需要补充新的API类型

## 扩展应用

### 1. 框架特定分析
针对特定框架进行定制化分析：
- Spring框架的Controller方法
- Hibernate的查询API
- Apache Commons的工具类

### 2. 领域特定标注
根据应用领域进行专项标注：
- Web应用的安全API
- 移动应用的权限API
- 云服务的配置API

### 3. 自动化集成
将标注结果集成到开发流程：
- IDE插件的实时警告
- CI/CD的安全检查
- 代码审查的辅助工具
"""
            }
        }

        for prompt_name, prompt_data in prompt_templates.items():
            entry = KnowledgeEntry(
                id="",
                content=prompt_data["content"],
                title=f"IRIS Prompt模板: {prompt_data['title']}",
                category="expert_knowledge",
                framework="general",
                language="general",
                metadata={
                    "prompt_name": prompt_name,
                    "source": "iris_prompts",
                    "description": prompt_data["description"],
                    "template_type": "llm_prompt",
                    "project": "iris"
                }
            )
            entries.append(entry)

        print(f"✅ 收集到IRIS prompt模板: {len(entries)} 条")
        return entries

    def _collect_iris_java_security(self) -> List[KnowledgeEntry]:
        """收集IRIS的Java安全分析数据"""
        entries = []

        java_security_data = {
            "java_sources": {
                "title": "Java污染源模式",
                "description": "常见的Java代码中的污染源API",
                "content": """
# Java污染源 (Taint Sources)

## HTTP请求相关
```java
// Servlet API
HttpServletRequest.getParameter(String name)
HttpServletRequest.getQueryString()
HttpServletRequest.getHeader(String name)
HttpServletRequest.getCookies()

// Spring MVC
@RequestParam String param
@PathVariable String pathVar
@RequestBody String body
```

## 文件系统相关
```java
// 文件读取
FileReader.read()
BufferedReader.readLine()
Files.readAllBytes(Path path)
Scanner.nextLine()

// 流操作
InputStream.read()
DataInputStream.readUTF()
ObjectInputStream.readObject()
```

## 命令行和环境
```java
// 命令行参数
public static void main(String[] args)  // args数组

// 环境变量
System.getenv(String name)
System.getProperty(String key)

// 系统属性
Properties.getProperty(String key)
```

## 网络相关
```java
// Socket通信
Socket.getInputStream()
ServerSocket.accept()
DatagramSocket.receive()

// HTTP客户端
HttpURLConnection.getInputStream()
HttpClient.send().body()
```

## 数据库相关
```java
// JDBC结果
ResultSet.getString(String column)
ResultSet.getObject(String column)

// ORM框架
entity.getField()  // JPA/Hibernate实体字段
```

## 框架特定
```java
// Spring Security
SecurityContextHolder.getContext().getAuthentication()

// JAX-RS
@QueryParam String query
@FormParam String formData
```
"""
            },
            "java_sinks": {
                "title": "Java危险汇点模式",
                "description": "常见的Java代码中的危险汇点API",
                "content": """
# Java危险汇点 (Taint Sinks)

## 命令执行
```java
// Runtime执行
Runtime.getRuntime().exec(String command)
Runtime.getRuntime().exec(String[] cmdarray)

// ProcessBuilder
new ProcessBuilder(String... command).start()
ProcessBuilder.command(String... command)

// 脚本引擎
ScriptEngine.eval(String script)
NashornScriptEngine.eval(String script)
```

## SQL查询
```java
// JDBC Statement
Statement.executeQuery(String sql)
Statement.executeUpdate(String sql)
Statement.execute(String sql)

// PreparedStatement（动态SQL）
PreparedStatement.executeQuery()  // 如果SQL是动态构建的

// ORM框架
entityManager.createQuery(String qlString)
session.createSQLQuery(String sql)
```

## 文件系统操作
```java
// 文件路径操作
new File(String pathname)
Paths.get(String path)
File.createTempFile(String prefix, String suffix)

// 文件I/O
FileWriter.write(String str)
PrintWriter.println(String x)
Files.write(Path path, String content)
```

## HTML输出
```java
// Servlet响应
HttpServletResponse.getWriter().write(String content)
PrintWriter.println(String x)

// JSP输出
out.println(String content)
<%= userInput %>

// 模板引擎
model.addAttribute("content", userInput)
template.process(data, writer)
```

## 网络操作
```java
// URL连接
new URL(String spec)
URI.create(String str)

// HTTP客户端
HttpRequest.newBuilder().uri(URI.create(url))
WebClient.get().uri(String url)
```

## 反射和序列化
```java
// 反射调用
Class.forName(String className)
Method.invoke(Object obj, Object... args)

// 序列化
ObjectInputStream.readObject()
XMLDecoder.readObject()

// 表达式语言
ELProcessor.eval(String expression)
SpelExpressionParser.parseExpression(String expression)
```

## 加密和证书
```java
// 证书验证
CertificateFactory.generateCertificate(InputStream in)
TrustManager.checkServerTrusted(X509Certificate[] chain, String authType)

// 加密操作
Cipher.getInstance(String transformation)
KeyStore.load(InputStream stream, char[] password)
```
"""
            },
            "java_propagators": {
                "title": "Java污染传播器模式",
                "description": "在Java代码中传播污染数据的API",
                "content": """
# Java污染传播器 (Taint Propagators)

## 字符串操作
```java
// 字符串拼接
String.concat(String str)
StringBuilder.append(String str)
StringBuffer.append(String str)
String.join(CharSequence delimiter, CharSequence... elements)

// 字符串格式化
String.format(String format, Object... args)
MessageFormat.format(String pattern, Object... args)

// 子串操作
String.substring(int beginIndex)
String.substring(int beginIndex, int endIndex)
String.replace(String target, String replacement)
```

## 集合操作
```java
// List操作
List.add(Object element)
List.add(int index, Object element)
List.set(int index, Object element)

// Map操作
Map.put(Object key, Object value)
Map.putIfAbsent(Object key, Object value)

// Set操作
Set.add(Object element)
```

## 数据结构转换
```java
// 数组转换
Arrays.asList(Object... a)
Arrays.copyOf(Object[] original, int newLength)

// 集合转换
new ArrayList(Collection<? extends E> c)
new HashSet(Collection<? extends E> c)
Collections.unmodifiableList(List<? extends T> list)
```

## I/O操作
```java
// 写入流
OutputStream.write(byte[] b)
Writer.write(String str)
PrintStream.println(String x)

// 读取到字符串
ByteArrayOutputStream.toString()
StringWriter.toString()
```

## 编码转换
```java
// URL编码/解码
URLEncoder.encode(String s)
URLDecoder.decode(String s)

// Base64编码
Base64.getEncoder().encodeToString(byte[] src)
Base64.getDecoder().decode(String src)
```

## JSON/XML处理
```java
// JSON处理
JSONObject.put(String key, Object value)
JSONArray.put(Object value)
JSONParser.parse(String json)

// XML处理
DocumentBuilder.parse(InputStream is)
SAXParser.parse(InputStream is, DefaultHandler dh)
```

## 框架特定传播器
```java
// Spring框架
Model.addAttribute(String attributeName, Object attributeValue)
HttpHeaders.add(String headerName, String headerValue)

// Hibernate
Criteria.add(Restrictions.eq(String propertyName, Object value))
Query.setParameter(String name, Object val)

// Apache Commons
StringUtils.join(Object[] array, String separator)
ArrayUtils.add(Object[] array, Object element)
```
"""
            }
        }

        for data_name, data_info in java_security_data.items():
            entry = KnowledgeEntry(
                id="",
                content=data_info["content"],
                title=f"IRIS Java安全数据: {data_info['title']}",
                category="cwe_patterns",
                framework="java",
                language="java",
                metadata={
                    "data_name": data_name,
                    "source": "iris_java_security",
                    "description": data_info["description"],
                    "security_type": "taint_analysis",
                    "project": "iris"
                }
            )
            entries.append(entry)

        print(f"✅ 收集到IRIS Java安全数据: {len(entries)} 条")
        return entries

    def _collect_iris_embedded_source(self) -> List[KnowledgeEntry]:
        """收集IRIS的源码示例"""
        entries = []

        # 从IRIS的源码中提取有用的片段
        iris_code_examples = {
            "codeql_vul_detection": {
                "title": "IRIS CodeQL漏洞检测逻辑",
                "description": "神经符号方法结合CodeQL的漏洞检测实现",
                "content": """
# IRIS CodeQL漏洞检测实现

## 核心检测逻辑
```python
def detect_vulnerabilities(self, code_snippet, cwe_type):
    \"\"\"
    使用神经符号方法检测漏洞

    Args:
        code_snippet: 代码片段
        cwe_type: CWE类型

    Returns:
        检测结果字典
    \"\"\"

    # 1. 符号分析阶段
    symbolic_patterns = self.extract_symbolic_patterns(code_snippet)

    # 2. 神经网络预测
    neural_predictions = self.neural_model.predict(code_snippet)

    # 3. CodeQL查询生成
    codeql_query = self.generate_codeql_query(symbolic_patterns, cwe_type)

    # 4. 查询执行和验证
    results = self.execute_codeql_query(codeql_query, code_snippet)

    return {
        'symbolic_patterns': symbolic_patterns,
        'neural_predictions': neural_predictions,
        'codeql_query': codeql_query,
        'detection_results': results
    }
```

## 符号模式提取
```python
def extract_symbolic_patterns(self, code):
    \"\"\"
    从代码中提取符号化的安全模式
    \"\"\"
    patterns = []

    # 数据流分析
    data_flows = self.analyze_data_flow(code)

    # 控制流分析
    control_flows = self.analyze_control_flow(code)

    # API调用分析
    api_calls = self.analyze_api_calls(code)

    return {
        'data_flows': data_flows,
        'control_flows': control_flows,
        'api_calls': api_calls
    }
```

## CodeQL查询生成
```python
def generate_codeql_query(self, patterns, cwe_type):
    \"\"\"
    基于模式生成CodeQL查询
    \"\"\"
    template = self.get_query_template(cwe_type)

    # 填充模板参数
    query_params = {
        'sources': patterns['api_calls']['sources'],
        'sinks': patterns['api_calls']['sinks'],
        'sanitizers': patterns['api_calls']['sanitizers'],
        'data_flow_conditions': patterns['data_flows']
    }

    return template.format(**query_params)
```

## 查询模板库
```python
QUERY_TEMPLATES = {
    'CWE-078': '''
import java
import semmle.code.java.dataflow.DataFlow

module Config implements DataFlow::ConfigSig {{
  predicate isSource(DataFlow::Node source) {{
    exists(MethodCall mc |
      mc.getMethod().getName() in [{sources}] and
      source.asExpr() = mc
    )
  }}

  predicate isSink(DataFlow::Node sink) {{
    exists(MethodCall mc |
      mc.getMethod().getName() in [{sinks}] and
      sink.asExpr() = mc
    )
  }}

  predicate isBarrier(DataFlow::Node node) {{
    {sanitizers}
  }}
}}

module Flow = DataFlow::Global<Config>;

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink, source, sink, "Command injection vulnerability"
'''
}
```
"""
            },
            "neusym_vulnerability_analysis": {
                "title": "IRIS神经符号漏洞分析",
                "description": "结合神经网络和符号分析的漏洞检测方法",
                "content": """
# IRIS神经符号漏洞分析框架

## 核心架构
```
输入代码片段
       ↓
符号分析器 → 提取安全模式
       ↓
神经网络 → 学习复杂模式
       ↓
符号推理 → 验证逻辑关系
       ↓
输出检测结果
```

## 符号分析模块
```python
class SymbolicAnalyzer:
    def analyze_code(self, code):
        \"\"\"执行符号化的代码分析\"\"\"

        # 1. 抽象语法树分析
        ast = self.parse_to_ast(code)

        # 2. 数据流提取
        data_flow = self.extract_data_flow(ast)

        # 3. 控制流提取
        control_flow = self.extract_control_flow(ast)

        # 4. API调用模式
        api_patterns = self.extract_api_patterns(ast)

        # 5. 安全属性推断
        security_properties = self.infer_security_properties(
            data_flow, control_flow, api_patterns
        )

        return {
            'data_flow': data_flow,
            'control_flow': control_flow,
            'api_patterns': api_patterns,
            'security_properties': security_properties
        }
```

## 神经网络模块
```python
class NeuralVulnerabilityDetector:
    def __init__(self, model_path):
        self.tokenizer = AutoTokenizer.from_pretrained(model_path)
        self.model = AutoModelForSequenceClassification.from_pretrained(model_path)

    def predict_vulnerability(self, code_snippet):
        \"\"\"预测代码片段的漏洞概率\"\"\"

        # 代码预处理
        tokens = self.tokenizer(
            code_snippet,
            truncation=True,
            padding=True,
            max_length=512,
            return_tensors="pt"
        )

        # 模型推理
        with torch.no_grad():
            outputs = self.model(**tokens)
            probabilities = torch.softmax(outputs.logits, dim=1)

        return {
            'vulnerability_score': probabilities[0][1].item(),
            'confidence': probabilities.max().item(),
            'prediction': 'vulnerable' if probabilities[0][1] > 0.5 else 'safe'
        }
```

## 符号推理模块
```python
class SymbolicReasoner:
    def verify_vulnerability(self, symbolic_patterns, neural_prediction):
        \"\"\"使用符号方法验证神经网络预测\"\"\"

        # 1. 构建符号约束
        constraints = self.build_symbolic_constraints(symbolic_patterns)

        # 2. 逻辑推理
        reasoning_result = self.perform_logical_reasoning(constraints)

        # 3. 与神经预测结合
        final_decision = self.combine_predictions(
            neural_prediction,
            reasoning_result
        )

        return {
            'symbolic_verification': reasoning_result,
            'combined_decision': final_decision,
            'confidence_score': self.calculate_confidence(
                neural_prediction, reasoning_result
            )
        }
```

## 训练数据生成
```python
class TrainingDataGenerator:
    def generate_training_samples(self, codebase):
        \"\"\"从代码库生成训练样本\"\"\"

        samples = []

        for file in codebase:
            # 解析代码
            ast = self.parse_code_file(file)

            # 提取特征
            features = self.extract_features(ast)

            # 生成标签（基于静态分析结果）
            label = self.generate_label(ast, features)

            samples.append({
                'code': file.content,
                'features': features,
                'label': label,
                'metadata': {
                    'file_path': file.path,
                    'language': file.language,
                    'complexity': self.calculate_complexity(ast)
                }
            })

        return samples
```

## 模型集成
```python
class NeuSymVulnerabilityDetector:
    def __init__(self):
        self.symbolic_analyzer = SymbolicAnalyzer()
        self.neural_detector = NeuralVulnerabilityDetector('model_path')
        self.symbolic_reasoner = SymbolicReasoner()

    def detect(self, code_snippet, cwe_type=None):
        \"\"\"完整的神经符号漏洞检测\"\"\"

        # 1. 符号分析
        symbolic_result = self.symbolic_analyzer.analyze_code(code_snippet)

        # 2. 神经网络预测
        neural_result = self.neural_detector.predict_vulnerability(code_snippet)

        # 3. 符号验证
        verification_result = self.symbolic_reasoner.verify_vulnerability(
            symbolic_result, neural_result
        )

        # 4. 结果融合
        final_result = self.fuse_results(
            symbolic_result, neural_result, verification_result
        )

        return final_result
```

## 评估指标
```python
class VulnerabilityDetectionEvaluator:
    def evaluate_model(self, test_dataset):
        \"\"\"评估检测模型的性能\"\"\"

        predictions = []
        ground_truth = []

        for sample in test_dataset:
            prediction = self.model.detect(sample['code'])
            predictions.append(prediction)
            ground_truth.append(sample['label'])

        # 计算指标
        metrics = {
            'accuracy': accuracy_score(ground_truth, predictions),
            'precision': precision_score(ground_truth, predictions),
            'recall': recall_score(ground_truth, predictions),
            'f1_score': f1_score(ground_truth, predictions),
            'auc_roc': roc_auc_score(ground_truth, predictions)
        }

        return metrics
```

## 实际应用示例
```python
# 使用示例
detector = NeuSymVulnerabilityDetector()

code_example = '''
public void executeCommand(String userInput) {
    Runtime runtime = Runtime.getRuntime();
    runtime.exec("cmd /c " + userInput);
}
'''

result = detector.detect(code_example, cwe_type='CWE-078')
print(f"检测结果: {result}")
# 输出: {'vulnerable': True, 'confidence': 0.95, 'cwe_type': 'CWE-078'}
```
"""
            }
        }

        for example_name, example_data in iris_code_examples.items():
            entry = KnowledgeEntry(
                id="",
                content=example_data["content"],
                title=f"IRIS源码示例: {example_data['title']}",
                category="code_examples",
                framework="general",
                language="python",
                metadata={
                    "example_name": example_name,
                    "source": "iris_embedded_source",
                    "description": example_data["description"],
                    "code_type": "implementation_example",
                    "project": "iris"
                }
            )
            entries.append(entry)

        print(f"✅ 收集到IRIS源码示例: {len(entries)} 条")
        return entries

    def collect_llvm_docs(self) -> List[KnowledgeEntry]:
        """收集LLVM/Clang官方文档"""
        print("🔍 收集LLVM/Clang文档...")

        entries = []

        # LLVM/Clang文档URL和本地缓存
        docs_info = [
            {
                "title": "Clang Static Analyzer Documentation",
                "description": "Clang静态分析器的官方文档，包含所有API和使用方法",
                "category": "framework_api",
                "framework": "clang",
                "content": """
# Clang Static Analyzer Documentation

Clang Static Analyzer (CSA) 是Clang编译器框架的一部分，用于静态代码分析。

## 主要组件

### Checker 框架
- **Checker基类**: 所有检查器的基类 `Checker<T>`
- **CheckerContext**: 提供分析上下文和报告功能
- **BugType**: 定义缺陷类型和报告格式

### 核心API
- **checkLocation()**: 检查内存位置访问
- **checkBind()**: 检查变量绑定
- **emitReport()**: 生成分析报告

### 分析类型
- **路径敏感分析**: 跟踪控制流和数据流
- **区间分析**: 数值范围分析
- **污点分析**: 跟踪不可信数据传播

## 使用示例

```cpp
class MyChecker : public Checker<check::Location> {
public:
  void checkLocation(SVal l, bool isLoad, const Stmt* S,
                     CheckerContext &C) const {
    if (isNullPointer(l)) {
      BugType BT{this, "NullPointerDereference"};
      C.emitReport(BugType(BT, "Dereference of null pointer", N));
    }
  }
};
```

更多详细信息请参考LLVM官方文档。
                """
            },
            {
                "title": "LLVM Programmer's Manual",
                "description": "LLVM程序员手册，包含核心库和API说明",
                "category": "framework_api",
                "framework": "llvm",
                "content": """
# LLVM Programmer's Manual

LLVM (Low Level Virtual Machine) 是现代编译器基础设施。

## 核心概念

### IR (Intermediate Representation)
- **模块(Module)**: 编译单元
- **函数(Function)**: 可调用单元
- **基本块(BasicBlock)**: 指令序列
- **指令(Instruction)**: 原子操作

### 分析遍(Pass)
- **函数遍**: 分析单个函数
- **模块遍**: 分析整个模块
- **循环遍**: 分析循环结构

### 类型系统
- **基本类型**: i32, float, double等
- **复合类型**: 数组、结构体、指针
- **函数类型**: 参数和返回值类型

## API使用

```cpp
// 创建模块
std::unique_ptr<Module> module = std::make_unique<Module>("example", context);

// 创建函数
FunctionType* funcType = FunctionType::get(Type::getVoidTy(context), false);
Function* func = Function::Create(funcType, Function::ExternalLinkage, "main", module.get());

// 创建基本块
BasicBlock* entry = BasicBlock::Create(context, "entry", func);

// 添加指令
ReturnInst::Create(context, entry);
```

更多详细信息请参考LLVM官方文档。
                """
            }
        ]

        for doc_info in docs_info:
            entry = KnowledgeEntry(
                id="",
                content=doc_info["content"],
                title=doc_info["title"],
                category=doc_info["category"],
                framework=doc_info["framework"],
                language="documentation",
                metadata={
                    "source": "llvm_official",
                    "description": doc_info["description"],
                    "file_type": "official_documentation"
                }
            )
            entries.append(entry)

        print(f"✅ 从LLVM/Clang文档收集到 {len(entries)} 个知识条目")
        return entries

    def collect_codeql_official(self) -> List[KnowledgeEntry]:
        """收集CodeQL官方文档和资源"""
        print("🔍 收集CodeQL官方资源...")

        entries = []

        # CodeQL官方资源
        codeql_resources = [
            {
                "title": "CodeQL查询语言规范",
                "description": "CodeQL查询语言的完整语法和语义规范",
                "category": "framework_api",
                "content": """
# CodeQL Query Language Specification

CodeQL是一种用于代码分析的查询语言，基于Datalog逻辑编程。

## 基本概念

### 查询结构
```ql
from /* 数据源 */
where /* 条件 */
select /* 结果 */
```

### 谓词(Predicate)
- **类谓词**: 定义类和方法
- **数据流谓词**: 分析数据流
- **控制流谓词**: 分析控制流

### 模块系统
- **import语句**: 导入标准库
- **module声明**: 定义可重用模块
- **extends子句**: 继承现有模块

## 数据流分析

### 基本模式
```ql
predicate isSource(DataFlow::Node source) {
  // 定义数据源
  exists(FunctionCall fc |
    fc.getTarget().getName() = "gets" and
    source.asExpr() = fc
  )
}

predicate isSink(DataFlow::Node sink) {
  // 定义数据汇
  exists(FunctionCall fc |
    fc.getTarget().getName() = "printf" and
    sink.asExpr() = fc.getArgument(0)
  )
}
```

### 配置模块
```ql
module Config implements DataFlow::ConfigSig {
  predicate isSource = isSource/1;
  predicate isSink = isSink/1;
}

module Flow = DataFlow::Global<Config>;
```

更多详细信息请参考CodeQL官方文档。
                """
            },
            {
                "title": "CodeQL安全分析最佳实践",
                "description": "使用CodeQL进行安全分析的最佳实践和模式",
                "category": "expert_knowledge",
                "content": """
# CodeQL Security Analysis Best Practices

## 查询设计原则

### 1. 精确性(Precision)
- 减少误报: 使用具体类型而不是通用类型
- 准确建模: 正确理解语言语义
- 边界条件: 处理所有边界情况

### 2. 性能优化
- 索引选择: 使用适当的谓词索引
- 查询分割: 将复杂查询分解为简单查询
- 缓存利用: 重用计算结果

### 3. 可维护性
- 模块化: 将查询分解为可重用模块
- 文档化: 为复杂逻辑添加注释
- 命名规范: 使用描述性名称

## 常见模式

### 数据流分析
```ql
// 正向数据流: 从源到汇
from DataFlow::PathNode source, DataFlow::PathNode sink
where
  source.getNode() instanceof Source and
  sink.getNode() instanceof Sink and
  DataFlow::localFlow(source, sink)
select sink, "Data flows from source to sink"

// 反向数据流: 从汇到源
from DataFlow::PathNode source, DataFlow::PathNode sink
where
  DataFlow::hasFlow(source, sink)
select source, sink, "Tainted data flow detected"
```

### 控制流分析
```ql
// 条件分支分析
from IfStmt ifs, Expr cond
where
  cond = ifs.getCondition() and
  cond instanceof EqualityOperation
select ifs, "Conditional branch depends on equality"
```

## 调试技巧

### 1. 分步验证
- 先验证谓词定义
- 再验证查询逻辑
- 最后验证结果格式

### 2. 性能监控
- 使用`--log-performance`选项
- 分析查询执行时间
- 优化慢查询

### 3. 结果验证
- 检查样本输入输出
- 验证边界条件
- 手动审查结果

## 扩展开发

### 自定义库
```ql
// 创建领域特定库
module Security {
  predicate isUserInput(FunctionCall fc) {
    fc.getTarget().getName() in ["gets", "scanf", "fgets"]
  }

  predicate isOutputSink(FunctionCall fc) {
    fc.getTarget().getName() in ["printf", "fprintf", "sprintf"]
  }
}
```

### 集成现有工具
- 与CI/CD集成
- 自定义规则开发
- 结果可视化

更多详细信息请参考CodeQL官方文档和社区资源。
                """
            }
        ]

        for resource in codeql_resources:
            entry = KnowledgeEntry(
                id="",
                content=resource["content"],
                title=resource["title"],
                category=resource["category"],
                framework="codeql",
                language="ql",
                metadata={
                    "source": "codeql_official",
                    "description": resource["description"],
                    "file_type": "documentation"
                }
            )
            entries.append(entry)

        print(f"✅ 从CodeQL官方资源收集到 {len(entries)} 个知识条目")
        return entries

    def collect_cwe_database(self) -> List[KnowledgeEntry]:
        """从MITRE CWE官方数据库收集数据"""
        print("🔍 收集MITRE CWE数据库...")

        entries = []

        # CWE核心概念和分类
        cwe_concepts = [
            {
                "id": "CWE-Definition",
                "title": "CWE定义和概念",
                "content": """
Common Weakness Enumeration (CWE) 通用弱点枚举

CWE是由MITRE公司维护的软件安全弱点分类标准。

核心概念：
1. Weakness（弱点）：软件中可能导致安全问题的缺陷
2. Category（类别）：弱点的逻辑分组
3. View（视图）：针对特定用途的弱点组织方式
4. Chain（链）：多个弱点组合形成的攻击链

弱点分类：
- Research Concepts: 研究概念（理论性）
- Development Concepts: 开发概念（实践性）
- Hardware Design: 硬件设计弱点
- Software Development: 软件开发弱点
- Architectural Concepts: 架构概念

使用场景：
- 安全代码审查
- 漏洞数据库分类
- 安全工具开发
- 安全培训和教育
                """,
                "category": "cwe_patterns",
                "framework": "general"
            },
            {
                "id": "CWE-Top-25",
                "title": "CWE Top 25 Most Dangerous Software Weaknesses",
                "content": """
2023 CWE Top 25 最危险的软件弱点

排名前5的弱点：
1. CWE-79: Cross-site Scripting (XSS) - 跨站脚本攻击
2. CWE-89: SQL Injection - SQL注入
3. CWE-120: Buffer Overflow - 缓冲区溢出
4. CWE-125: Out-of-bounds Read - 越界读取
5. CWE-20: Improper Input Validation - 输入验证不当

这些弱点占所有已知安全漏洞的很大比例，开发者应重点关注。

缓解策略：
- 输入验证和清理
- 参数化查询
- 边界检查
- 最小权限原则
                """,
                "category": "cwe_patterns",
                "framework": "general"
            }
        ]

        for concept in cwe_concepts:
            entry = KnowledgeEntry(
                id="",
                content=concept["content"],
                title=concept["title"],
                category=concept["category"],
                framework=concept["framework"],
                language="general",
                metadata={
                    "cwe_id": concept["id"],
                    "source": "mitre_cwe",
                    "file_type": "concept_overview"
                }
            )
            entries.append(entry)

        print(f"✅ 从CWE数据库收集到 {len(entries)} 个知识条目")
        return entries

    def collect_security_best_practices(self) -> List[KnowledgeEntry]:
        """收集安全编码最佳实践"""
        print("🔒 收集安全编码最佳实践...")

        entries = []

        best_practices = [
            {
                "title": "输入验证最佳实践",
                "content": """
输入验证安全最佳实践

1. 防御原则：
   - 永远不要信任用户输入
   - 在服务器端验证所有输入
   - 使用白名单而不是黑名单
   - 验证输入类型、长度、格式和范围

2. 常见漏洞防范：
   - SQL注入：使用参数化查询
   - XSS：输出编码和CSP
   - CSRF：使用Anti-CSRF令牌
   - 命令注入：避免shell命令拼接

3. 实现技术：
   - 正则表达式验证
   - 类型检查和转换
   - 长度限制
   - 字符集限制

4. 框架支持：
   - OWASP Validation API
   - Spring Validation
   - Django Forms
   - Express Validator
                """,
                "category": "expert_knowledge",
                "framework": "general"
            },
            {
                "title": "内存安全编程指南",
                "content": """
内存安全编程最佳实践

1. 缓冲区溢出防范：
   - 使用安全的字符串函数（strncpy, strncat）
   - 检查数组边界
   - 使用抽象数据类型

2. 空指针解引用防范：
   - 总是检查指针是否为空
   - 使用断言和异常处理
   - 初始化指针变量

3. 释放后使用防范：
   - 设置指针为空 after free
   - 使用智能指针（RAII）
   - 避免复杂的对象生命周期

4. 内存泄漏防范：
   - 配对使用malloc/free
   - 使用内存检查工具（Valgrind）
   - 实现资源管理类

5. 现代语言特性：
   - Rust的所有权系统
   - C++智能指针
   - Java垃圾回收
   - Go自动内存管理
                """,
                "category": "expert_knowledge",
                "framework": "general"
            },
            {
                "title": "静态分析工具使用指南",
                "content": """
静态分析工具使用最佳实践

1. 工具选择：
   - Clang Static Analyzer: C/C++代码分析
   - SpotBugs: Java字节码分析
   - ESLint: JavaScript代码质量
   - SonarQube: 多语言代码质量平台

2. 集成到开发流程：
   - 持续集成中运行
   - 代码审查前检查
   - 定期全量扫描
   - 跟踪问题趋势

3. 结果处理：
   - 优先处理高严重性问题
   - 建立问题分类和修复流程
   - 监控误报率和漏报率
   - 定期更新规则库

4. 团队协作：
   - 统一工具配置
   - 建立问题修复规范
   - 培训开发者理解报告
   - 建立反馈机制改进规则
                """,
                "category": "expert_knowledge",
                "framework": "general"
            }
        ]

        for practice in best_practices:
            entry = KnowledgeEntry(
                id="",
                content=practice["content"],
                title=practice["title"],
                category=practice["category"],
                framework=practice["framework"],
                language="general",
                metadata={
                    "practice_type": "security_coding",
                    "source": "security_best_practices",
                    "file_type": "guidelines"
                }
            )
            entries.append(entry)

        print(f"✅ 从安全最佳实践收集到 {len(entries)} 个知识条目")
        return entries

    def collect_open_source_tools(self) -> List[KnowledgeEntry]:
        """收集开源静态分析工具数据"""
        print("🛠️  收集开源静态分析工具数据...")

        entries = []

        tools_data = [
            {
                "name": "Cppcheck",
                "description": """
Cppcheck - C/C++静态分析工具

特点：
- 专注于C/C++代码缺陷检测
- 速度快，资源占用少
- 支持多种输出格式
- 可扩展规则系统

使用示例：
```bash
cppcheck --enable=all --std=c++11 src/
```

优势：
- 开源免费
- 易于集成到CI/CD
- 支持增量分析
- 误报率相对较低

局限性：
- 分析深度有限
- 复杂逻辑分析能力弱
- 不支持跨文件分析
                """,
                "language": "cpp",
                "category": "expert_knowledge"
            },
            {
                "name": "Infer",
                "description": """
Facebook Infer - 多语言静态分析工具

支持语言：
- Java
- C/C++
- Objective-C

核心功能：
- 空指针解引用检测
- 资源泄漏检测
- 竞态条件检测
- 注释辅助验证

优势：
- Facebook大规模使用验证
- 支持大规模代码库
- 分析精度高
- 良好的可扩展性

使用示例：
```bash
infer run -- javac Hello.java
```
                """,
                "language": "multi",
                "category": "expert_knowledge"
            },
            {
                "name": "Semgrep",
                "description": """
Semgrep - 轻量级静态分析工具

特点：
- 使用模式匹配进行代码分析
- 支持多种编程语言
- 易于编写自定义规则
- 快速扫描大规模代码库

优势：
- 学习成本低
- 规则编写灵活
- 扫描速度快
- 社区规则丰富

使用示例：
```bash
semgrep --config=auto src/
```

应用场景：
- 安全漏洞扫描
- 代码规范检查
- 技术债务识别
                """,
                "language": "multi",
                "category": "expert_knowledge"
            }
        ]

        for tool in tools_data:
            entry = KnowledgeEntry(
                id="",
                content=tool["description"],
                title=f"静态分析工具: {tool['name']}",
                category=tool["category"],
                framework="general",
                language=tool["language"],
                metadata={
                    "tool_name": tool["name"],
                    "source": "open_source_tools",
                    "file_type": "tool_description"
                }
            )
            entries.append(entry)

        print(f"✅ 从开源工具收集到 {len(entries)} 个知识条目")
        return entries

    def collect_security_best_practices(self) -> List[KnowledgeEntry]:
        """收集安全编码最佳实践"""
        print("🔍 收集安全编码最佳实践...")

        entries = []

        # 安全编码最佳实践
        security_practices = [
            {
                "title": "输入验证最佳实践",
                "category": "expert_knowledge",
                "content": """
# 输入验证最佳实践

## 基本原则

### 1. 防御性编程
- 永远不要信任外部输入
- 验证所有输入数据的格式和范围
- 使用白名单而不是黑名单

### 2. 输入验证层次
```python
# 客户端验证（用户体验）
# 服务器端验证（安全保障）
# 数据库验证（数据完整性）
```

### 3. 常见输入类型验证

#### 字符串输入
```cpp
// C++ 字符串验证
bool isValidString(const std::string& input) {
    // 长度检查
    if (input.length() > MAX_LENGTH) return false;

    // 字符集检查
    for (char c : input) {
        if (!isalnum(c) && c != '_' && c != '-') return false;
    }

    return true;
}
```

#### 数值输入
```cpp
// 数值范围检查
int safeConvert(const std::string& str) {
    try {
        int value = std::stoi(str);
        if (value < MIN_VALUE || value > MAX_VALUE) {
            throw std::out_of_range("Value out of range");
        }
        return value;
    } catch (const std::exception& e) {
        // 处理转换错误
        return DEFAULT_VALUE;
    }
}
```

### 4. SQL注入防护
```sql
-- 安全的方式：使用参数化查询
PREPARE stmt FROM 'SELECT * FROM users WHERE id = ?';
EXECUTE stmt USING user_id;

-- 危险的方式：字符串拼接（不要使用）
sql = "SELECT * FROM users WHERE id = " + user_id;
```

### 5. XSS防护
```javascript
// 前端转义
function escapeHtml(text) {
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return text.replace(/[&<>"']/g, m => map[m]);
}

// 后端验证
const validator = require('validator');
if (!validator.isEmail(email)) {
    return res.status(400).json({ error: 'Invalid email' });
}
```

## 框架特定实践

### Web框架
- 使用内置验证器
- 实施CSRF保护
- 配置安全头

### API设计
- 使用类型安全的接口
- 实施速率限制
- 记录和监控异常

## 工具推荐
- OWASP ZAP：Web应用安全扫描
- SQLMap：SQL注入测试
- Bandit：Python安全检查
                """
            },
            {
                "title": "内存安全编程指南",
                "category": "expert_knowledge",
                "content": """
# 内存安全编程指南

## C/C++ 内存安全

### 1. 避免常见错误

#### 缓冲区溢出
```cpp
// 危险：固定大小缓冲区
char buffer[100];
strcpy(buffer, user_input);  // 可能溢出

// 安全：检查长度
char buffer[100];
if (strlen(user_input) < sizeof(buffer)) {
    strcpy(buffer, user_input);
} else {
    // 处理错误
}
```

#### 使用后释放
```cpp
// 危险：释放后使用
int* ptr = new int(42);
delete ptr;
// ... 其他代码 ...
*ptr = 100;  // 未定义行为

// 安全：释放后置空
int* ptr = new int(42);
delete ptr;
ptr = nullptr;
// 现在访问ptr会崩溃而不是未定义行为
```

#### 内存泄漏
```cpp
// 危险：忘记释放
void processData() {
    int* data = new int[1000];
    // 处理数据...
    // 忘记 delete[] data;
}

// 安全：使用RAII
class DataProcessor {
private:
    std::vector<int> data;  // 自动管理内存

public:
    void process() {
        data.resize(1000);
        // 处理数据...
        // 自动释放
    }
};
```

### 2. 智能指针使用

#### unique_ptr
```cpp
// 独占所有权
std::unique_ptr<int> ptr = std::make_unique<int>(42);
func(std::move(ptr));  // 转移所有权

// 数组版本
auto arr = std::make_unique<int[]>(100);
```

#### shared_ptr
```cpp
// 共享所有权
std::shared_ptr<int> ptr1 = std::make_shared<int>(42);
std::shared_ptr<int> ptr2 = ptr1;  // 引用计数+1
// 自动释放当最后一个shared_ptr销毁
```

### 3. 容器安全

#### 向量边界检查
```cpp
std::vector<int> vec = {1, 2, 3};

// 安全访问
if (index < vec.size()) {
    value = vec[index];
}

// 或使用at()方法（会抛出异常）
try {
    value = vec.at(index);
} catch (const std::out_of_range& e) {
    // 处理越界
}
```

### 4. 字符串安全

#### C风格字符串
```cpp
// 使用安全函数
char dest[100];
strncpy(dest, source, sizeof(dest) - 1);
dest[sizeof(dest) - 1] = '\\0';  // 确保null终止
```

#### C++字符串
```cpp
// std::string 自动管理内存
std::string safe_concat(const std::string& a, const std::string& b) {
    return a + b;  // 自动处理内存
}
```

## Rust内存安全

Rust通过所有权系统提供编译时内存安全：

```rust
// Rust自动管理内存
fn process_data(data: Vec<i32>) -> Vec<i32> {
    // data的所有权转移到函数
    let mut result = Vec::new();
    for item in data {
        result.push(item * 2);
    }
    result  // 返回所有权
}
```

## 工具和最佳实践

### 静态分析工具
- Valgrind：内存泄漏检测
- AddressSanitizer：内存错误检测
- Clang Static Analyzer：编译时分析

### 代码审查清单
- [ ] 所有new都有对应的delete
- [ ] 数组访问都在边界内
- [ ] 指针使用前检查null
- [ ] 字符串操作使用安全函数
- [ ] 使用RAII管理资源

### 性能考虑
- 避免不必要的拷贝
- 使用移动语义
- 合理选择容器类型
                """
            }
        ]

        for practice in security_practices:
            entry = KnowledgeEntry(
                id="",
                content=practice["content"],
                title=practice["title"],
                category=practice["category"],
                framework="general",
                language="general",
                metadata={
                    "source": "security_best_practices",
                    "practice_type": "coding_guidelines",
                    "file_type": "documentation"
                }
            )
            entries.append(entry)

        print(f"✅ 收集到 {len(entries)} 个安全最佳实践条目")
        return entries

    def collect_open_source_tools(self) -> List[KnowledgeEntry]:
        """收集开源静态分析工具数据"""
        print("🔍 收集开源静态分析工具数据...")

        entries = []

        # 开源静态分析工具
        tools = [
            {
                "name": "Cppcheck",
                "description": "Cppcheck是一个静态分析工具，专注于C/C++代码缺陷检测，无需编译即可分析代码。",
                "language": "cpp",
                "analysis_type": "defect_detection",
                "content": """
# Cppcheck - C/C++ 静态分析工具

## 主要功能
- **内存泄漏检测**: 识别new/delete不匹配
- **缓冲区溢出**: 检测数组越界访问
- **空指针解引用**: 发现潜在的null指针使用
- **未初始化变量**: 警告未初始化的局部变量
- **类型转换问题**: 检测危险的类型转换

## 使用示例
```bash
# 基本用法
cppcheck file.cpp

# 启用所有检查
cppcheck --enable=all file.cpp

# 生成XML报告
cppcheck --xml file.cpp > report.xml

# 检查整个项目
cppcheck --project=compile_commands.json
```

## 配置选项
- `--enable=<id>`: 启用特定检查
- `--suppress=<spec>`: 抑制特定警告
- `--std=<version>`: 指定C/C++标准版本
- `--platform=<type>`: 指定目标平台

## 集成方式
- **命令行**: 直接调用cppcheck
- **IDE集成**: 支持VSCode, Vim等编辑器
- **CI/CD**: 集成到构建流程中

## 优势
- **速度快**: 无需编译即可分析
- **轻量级**: 资源消耗少
- **开源**: 完全免费
- **可扩展**: 支持自定义规则
                """
            },
            {
                "name": "Infer",
                "description": "Facebook开发的静态分析工具，支持Java、C/C++、Objective-C，用于检测空指针、资源泄漏等问题。",
                "language": "multi",
                "analysis_type": "bug_finding",
                "content": """
# Infer - 多语言静态分析工具

## 支持语言
- Java (Android应用)
- C, C++
- Objective-C

## 核心分析器

### 1. 过程间分析
- 跟踪函数调用链
- 理解数据流传播
- 检测跨函数的缺陷

### 2. 注解系统
```java
// 空值注解
@Nullable String getName() {
    return this.name;  // 可能返回null
}

@Nonnull String processName() {
    String name = getName();
    return name.toUpperCase();  // 可能NullPointerException
}
```

### 3. 资源管理
```java
// 文件句柄泄漏检测
FileInputStream fis = new FileInputStream("file.txt");
// 忘记关闭流
// Infer会警告资源泄漏
```

## 使用方法
```bash
# 分析Java项目
infer run -- mvn compile

# 分析C++项目
infer run -- make

# 生成特定类型报告
infer run --reactive -- mvn compile

# 增量分析
infer run --incremental -- mvn compile
```

## 检测能力

### Java特有
- NullPointerException
- 资源泄漏
- 线程安全问题
- Android特定问题

### C/C++特有
- 内存泄漏
- 缓冲区溢出
- 空指针解引用
- 竞争条件

### 优势
- **精确**: 低误报率
- **快速**: 增量分析支持
- **集成**: 与主流构建工具集成
- **开源**: Facebook维护
                """
            },
            {
                "name": "SpotBugs",
                "description": "Java静态分析工具，专注于字节码级别的缺陷检测，继承FindBugs的优秀传统。",
                "language": "java",
                "analysis_type": "bytecode_analysis",
                "content": """
# SpotBugs - Java字节码分析工具

## 检测规则分类

### 1. Correctness (正确性)
- **NP**: Null pointer dereference
- **NM**: Method naming convention
- **EQ**: Bad equals() implementation

### 2. Bad Practice (不良实践)
- **UR**: Unread field
- **UUF**: Unused field
- **DM**: Dubious method

### 3. Performance (性能)
- **SIC**: Inner class could be static
- **SS**: Unread field should be static
- **UrF**: Unread field

### 4. Security (安全)
- **MS**: Mutable static field
- **PT**: Absolute path traversal
- **SQL**: SQL injection

## 使用示例
```bash
# 分析JAR文件
spotbugs -textui myapp.jar

# 分析类文件目录
spotbugs -textui build/classes/

# 生成HTML报告
spotbugs -html -output report.html myapp.jar

# 使用自定义规则
spotbugs -pluginList myrules.jar -textui myapp.jar
```

## 集成方式

### Maven插件
```xml
<plugin>
    <groupId>com.github.spotbugs</groupId>
    <artifactId>spotbugs-maven-plugin</artifactId>
    <version>4.7.3.0</version>
    <configuration>
        <effort>Max</effort>
        <threshold>Low</threshold>
    </configuration>
</plugin>
```

### Gradle插件
```gradle
plugins {
    id 'com.github.spotbugs' version '5.0.14'
}

spotbugs {
    effort = 'max'
    reportLevel = 'low'
}
```

## 自定义规则

```java
public class CustomDetector extends BytecodeScanningDetector {
    @Override
    public void sawOpcode(int seen) {
        if (seen == INVOKEVIRTUAL) {
            // 自定义检测逻辑
        }
    }
}
```

## 优势
- **字节码级别**: 分析编译后的代码
- **成熟稳定**: FindBugs的继任者
- **规则丰富**: 400+种检测规则
- **性能良好**: 分析速度快
                """
            },
            {
                "name": "Semgrep",
                "description": "轻量级静态分析工具，使用模式匹配进行代码分析，支持20+种编程语言。",
                "language": "multi",
                "analysis_type": "pattern_matching",
                "content": """
# Semgrep - 通用代码分析工具

## 支持语言
- Python, JavaScript, TypeScript
- Java, C#, Go, Rust
- C, C++, PHP, Ruby
- 以及更多...

## 规则格式

### 1. 简单模式匹配
```yaml
rules:
- id: dangerous-subprocess-use
  pattern: subprocess.call(..., shell=True)
  message: Avoid using shell=True with subprocess
  severity: WARNING
```

### 2. 复杂模式
```yaml
rules:
- id: insecure-random
  patterns:
  - pattern: random.randint(0, $X)
  - pattern-not: random.seed(...)
  message: Using random without seed is insecure
  severity: ERROR
```

### 3. 跨函数模式
```yaml
rules:
- id: tainted-data-to-sink
  mode: taint
  pattern-sources:
  - pattern: input(...)
  pattern-sinks:
  - pattern: eval(...)
  message: User input flows to eval
```

## 使用方法
```bash
# 运行内置规则
semgrep --config auto file.py

# 使用自定义规则
semgrep --config myrules.yaml src/

# 扫描并自动修复
semgrep --config auto --autofix file.py

# 生成SARIF报告
semgrep --config auto --sarif --output report.sarif
```

## 规则生态

### 官方规则集
- **security**: 安全漏洞检测
- **best-practice**: 编码最佳实践
- **correctness**: 代码正确性
- **performance**: 性能优化

### 社区规则
```bash
# 安装社区规则
semgrep install-semgrep-rules

# 使用特定规则包
semgrep --config r2c-security-audit
```

## 集成支持

### CI/CD集成
```yaml
# GitHub Actions
- uses: returntocorp/semgrep-action@v1
  with:
    config: auto
```

### IDE集成
- VSCode插件
- Vim插件
- JetBrains插件

## 优势
- **多语言**: 支持20+种语言
- **易编写**: 简单的YAML规则格式
- **快速**: 基于AST的模式匹配
- **可扩展**: 丰富的规则生态
                """
            }
        ]

        for tool in tools:
            entry = KnowledgeEntry(
                id="",
                content=tool["content"],
                title=f"{tool['name']} - {tool['description']}",
                category="expert_knowledge",
                framework="general",
                language=tool["language"],
                metadata={
                    "tool_name": tool["name"],
                    "analysis_type": tool["analysis_type"],
                    "source": "open_source_tools",
                    "file_type": "tool_documentation"
                }
            )
            entries.append(entry)

        print(f"✅ 收集到 {len(entries)} 个开源工具条目")
        return entries

def collect_clang_api_docs() -> List[KnowledgeEntry]:
    """
    收集Clang Static Analyzer完整API文档信息

    Returns:
        知识条目列表
    """
    entries = []

    # 完整的Clang Static Analyzer API文档
    clang_apis = [
        # 基础Checker框架
        {
            "name": "Checker基类体系",
            "description": """
# Clang Static Analyzer Checker框架

Checker<T> 是所有静态分析检查器的基类模板，支持多种回调类型。

## 继承方式
```cpp
// 基本继承
class MyChecker : public Checker<check::PreCall> {
public:
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
};

// 多回调类型
class MyChecker : public Checker<check::PreCall, check::PostCall> {
public:
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
};
```

## 支持的回调类型
- `check::PreCall` - 函数调用前检查
- `check::PostCall` - 函数调用后检查
- `check::PreStmt<T>` - 语句前检查（如ReturnStmt, IfStmt）
- `check::PostStmt<T>` - 语句后检查
- `check::Location` - 内存位置访问检查
- `check::Bind` - 变量绑定检查
- `check::EndFunction` - 函数结束检查
- `check::EndAnalysis` - 分析结束检查
- `check::BeginFunction` - 函数开始检查
- `check::BranchCondition` - 分支条件检查
- `check::NewAllocator` - 新分配器检查
- `check::LiveSymbols` - 活符号检查
- `check::DeadSymbols` - 死符号检查
- `check::RegionChanges` - 区域变化检查
- `check::PointerEscape` - 指针逃逸检查
- `check::ConstPointerEscape` - 常量指针逃逸检查
- `check::Event<ImplicitNullDerefEvent>` - 隐式空解引用事件
- `check::ASTCodeBody` - AST代码体检查
- `check::ASTDecl<T>` - AST声明检查
            """,
            "category": "framework_api",
            "framework": "clang"
        },
        {
            "name": "BugType和Bug报告",
            "description": """
# BugType和Bug报告API

## BugType类
用于定义缺陷类型和报告格式。

```cpp
class BugType {
public:
  BugType(const CheckerBase *Checker, StringRef Name,
          StringRef Category = "Logic error",
          bool SuppressOnSink = false);
};
```

## 创建Bug报告
```cpp
// 简单Bug报告
void reportBug(CheckerContext &C, const char *Message) const {
  if (!BT) {
    BT.reset(new BugType(this, "MyBugType", "Memory Error"));
  }

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N) return;

  auto Report = std::make_unique<PathSensitiveBugReport>(*BT, Message, N);
  C.emitReport(std::move(Report));
}

// 带位置信息的Bug报告
void reportBugWithLocation(CheckerContext &C, const Stmt *S,
                          const char *Message) const {
  PathDiagnosticLocation Loc =
    PathDiagnosticLocation::createBegin(S, C.getSourceManager(), C.getLocationContext());

  auto Report = std::make_unique<PathSensitiveBugReport>(*BT, Message, N);
  Report->setLocation(Loc);
  C.emitReport(std::move(Report));
}
```

## Bug报告增强功能
```cpp
// 添加范围高亮
Report->addRange(Stmt->getSourceRange());

// 添加额外诊断信息
Report->addNote(Location, "Additional diagnostic message");

// 修复建议
Report->addFixItHint(FixItHint::CreateReplacement(
  Stmt->getSourceRange(), "suggested_fix()"));
```
            """,
            "category": "framework_api",
            "framework": "clang"
        },
        {
            "name": "程序状态管理",
            "description": """
# Program State Management

## 程序状态类
```cpp
class ProgramState {
public:
  // 获取约束管理器
  ConstraintManager &getConstraintManager() const;

  // 获取存储管理器
  StoreManager &getStoreManager() const;

  // 检查假设
  ProgramStateRef assume(DefinedOrUnknownSVal Cond, bool Assumption) const;

  // 设置存储值
  ProgramStateRef setStore(Store St) const;

  // 获取存储值
  SVal getSVal(const MemRegion *R, QualType T = QualType()) const;
  SVal getSVal(Loc L, QualType T = QualType()) const;
};
```

## 状态注册
```cpp
// 注册状态跟踪
REGISTER_MAP_WITH_PROGRAMSTATE(MyStateMap, const MemRegion *, MyStateInfo)

// 自定义状态结构
struct MyStateInfo {
  bool isInitialized = false;
  const Stmt *initStmt = nullptr;

  bool operator==(const MyStateInfo &Other) const {
    return isInitialized == Other.isInitialized;
  }

  void Profile(llvm::FoldingSetNodeID &ID) const {
    ID.AddBoolean(isInitialized);
  }
};
```

## 状态操作
```cpp
// 获取状态
ProgramStateRef State = C.getState();
const MyStateInfo *Info = State->get<MyStateMap>(Region);

// 设置状态
MyStateInfo NewInfo{/* ... */};
State = State->set<MyStateMap>(Region, NewInfo);
C.addTransition(State);

// 移除状态
State = State->remove<MyStateMap>(Region);
C.addTransition(State);
```
            """,
            "category": "framework_api",
            "framework": "clang"
        },
        {
            "name": "符号值(SVal)和内存区域",
            "description": """
# SVal和MemRegion系统

## SVal类型
```cpp
class SVal {
public:
  // 基本类型检查
  bool isUnknown() const;
  bool isUndef() const;
  bool isUnknownOrUndef() const;
  bool isValid() const;

  // 具体类型转换
  const DefinedOrUnknownSVal *castAs() const;
  const DefinedSVal *castAs() const;
  const KnownSVal *castAs() const;
  const UnknownVal *castAs() const;
  const UndefinedVal *castAs() const;
  const Loc *castAs() const;
  const NonLoc *castAs() const;
};
```

## 内存区域类型
```cpp
// 基本区域类型
class MemRegion {
public:
  virtual MemRegionManager *getMemRegionManager() const;
  virtual const MemRegion *getBaseRegion() const;
  virtual bool isSubRegionOf(const MemRegion *R) const;
};

// 具体区域类型
class SymbolicRegion : public SubRegion { /* 符号区域 */ };
class AllocaRegion : public SubRegion { /* 栈分配区域 */ };
class GlobalImmutableSpaceRegion : public MemSpaceRegion { /* 全局只读区域 */ };
class HeapSpaceRegion : public MemSpaceRegion { /* 堆区域 */ };
class StackLocalsSpaceRegion : public StackSpaceRegion { /* 栈局部变量区域 */ };
class StackArgumentsSpaceRegion : public StackSpaceRegion { /* 栈参数区域 */ };
```

## 区域操作
```cpp
// 获取内存区域
const MemRegion *MR = State->getSVal(Expr).getAsRegion();

// 检查区域类型
if (const SymbolicRegion *SymR = dyn_cast<SymbolicRegion>(MR)) {
  // 处理符号区域
}

// 获取基区域
const MemRegion *BaseR = MR->getBaseRegion();

// 区域比较
if (MR1->isSubRegionOf(MR2)) {
  // MR1是MR2的子区域
}
```

## 符号值操作
```cpp
// 从表达式获取SVal
SVal Val = C.getSVal(Expr);

// 检查是否为特定值
if (Val.isZeroConstant()) {
  // 是零常量
}

// 转换为具体类型
if (const nonloc::ConcreteInt *CI = Val.getAs()) {
  llvm::APSInt IntVal = CI->getValue();
  // 使用整数值
}
```
            """,
            "category": "framework_api",
            "framework": "clang"
        },
        {
            "name": "约束管理器",
            "description": """
# Constraint Manager API

## 基本接口
```cpp
class ConstraintManager {
public:
  virtual ProgramStateRef assume(ProgramStateRef State,
                                DefinedSVal Cond,
                                bool Assumption) = 0;

  virtual const llvm::APSInt* getSymMaxVal(ProgramStateRef State,
                                          SymbolRef Sym) const = 0;

  virtual const llvm::APSInt* getSymMinVal(ProgramStateRef State,
                                          SymbolRef Sym) const = 0;
};
```

## 范围约束
```cpp
// 获取符号的最大值
const llvm::APSInt *MaxVal = State->getConstraintManager().getSymMaxVal(State, Sym);

// 获取符号的最小值
const llvm::APSInt *MinVal = State->getConstraintManager().getSymMinVal(State, Sym);

// 检查值是否在范围内
bool isInRange(SymbolRef Sym, const llvm::APSInt &Val) {
  const llvm::APSInt *Min = State->getConstraintManager().getSymMinVal(State, Sym);
  const llvm::APSInt *Max = State->getConstraintManager().getSymMaxVal(State, Sym);

  if (Min && Max) {
    return Val >= *Min && Val <= *Max;
  }
  return false;
}
```

## 假设操作
```cpp
// 假设条件为真
ProgramStateRef StateTrue = State->assume(Cond, true);

// 假设条件为假
ProgramStateRef StateFalse = State->assume(Cond, false);

// 分支分析
if (StateTrue && StateFalse) {
  // 条件可能为真也可能为假
  // 需要分别分析两条路径
} else if (StateTrue) {
  // 条件总是为真
} else if (StateFalse) {
  // 条件总是为假
}
```
            """,
            "category": "framework_api",
            "framework": "clang"
        },
        {
            "name": "AST匹配器",
            "description": """
# AST Matchers API

## 基本概念
AST匹配器用于在Clang AST中查找特定的代码模式。

```cpp
// 包含头文件
#include "clang/ASTMatchers/ASTMatchers.h"

// 使用命名空间
using namespace clang::ast_matchers;
```

## 基本匹配器
```cpp
// 声明匹配器
auto FuncDeclMatcher = functionDecl(hasName("malloc")).bind("mallocCall");

// 语句匹配器
auto ReturnMatcher = returnStmt(has(expr()))).bind("return");

// 表达式匹配器
auto AssignMatcher = binaryOperator(hasOperatorName("=")).bind("assignment");
```

## 复合匹配器
```cpp
// 函数声明匹配器
auto MallocFunction = functionDecl(
  hasName("malloc"),
  parameterCountIs(1),
  returns(pointerType())
);

// 调用表达式匹配器
auto MallocCall = callExpr(
  callee(MallocFunction),
  argumentCountIs(1)
);

// 赋值语句匹配器
auto MallocAssignment = binaryOperator(
  hasOperatorName("="),
  hasRHS(MallocCall)
);
```

## 匹配器组合
```cpp
// 或操作
auto MemoryFunction = functionDecl(anyOf(
  hasName("malloc"),
  hasName("calloc"),
  hasName("realloc")
));

// 与操作
auto UnsafeMalloc = callExpr(
  allOf(
    callee(functionDecl(hasName("malloc"))),
    hasArgument(0, integerLiteral(equals(0)))
  )
);
```

## 使用匹配器
```cpp
void MyChecker::checkASTCodeBody(const Decl *D, AnalysisManager &AM,
                                BugReporter &BR) const {
  // 创建匹配器
  auto Matcher = callExpr(callee(functionDecl(hasName("malloc")))).bind("malloc");

  // 运行匹配
  auto Matches = match(Matcher, *D, AM.getASTContext());

  // 处理结果
  for (const auto &Match : Matches) {
    const CallExpr *Call = Match.getNodeAs<CallExpr>("malloc");
    // 报告问题
  }
}
```
            """,
            "category": "framework_api",
            "framework": "clang"
        },
        {
            "name": "路径敏感分析",
            "description": """
# Path-Sensitive Analysis

## ExplodedGraph概念
```cpp
// ExplodedNode表示程序的特定状态
class ExplodedNode {
public:
  const ProgramState *getState() const;
  const LocationContext *getLocationContext() const;
  ExplodedNode *getPredecessor() const;
  const Stmt *getStmt() const;
};
```

## 节点操作
```cpp
// 创建新节点
ExplodedNode *NewNode = C.generateNonFatalErrorNode();
ExplodedNode *ErrorNode = C.generateFatalErrorNode();

// 检查节点状态
if (!Node) {
  return; // 无法创建节点
}

// 获取节点信息
const ProgramState *State = Node->getState();
const LocationContext *LC = Node->getLocationContext();
const Stmt *CurrentStmt = Node->getStmt();
```

## 路径遍历
```cpp
// 遍历到当前节点的路径
void traversePath(ExplodedNode *Node) {
  for (ExplodedNode *N = Node; N; N = N->getPredecessor()) {
    const Stmt *S = N->getStmt();
    if (S) {
      // 处理路径上的语句
    }
  }
}

// 检查路径条件
bool isReachable(ExplodedNode *Node) {
  // 检查是否存在到达该节点的路径
  return Node->getPredecessor() != nullptr;
}
```

## 分支处理
```cpp
// 处理条件分支
ProgramStateRef State = C.getState();
SVal Condition = C.getSVal(CondExpr);

// 假设条件为真
ProgramStateRef TrueState = State->assume(Condition, true);
if (TrueState) {
  ExplodedNode *TrueNode = C.generateNonFatalErrorNode(TrueState);
  // 处理真分支
}

// 假设条件为假
ProgramStateRef FalseState = State->assume(Condition, false);
if (FalseState) {
  ExplodedNode *FalseNode = C.generateNonFatalErrorNode(FalseState);
  // 处理假分支
}
```
            """,
            "category": "framework_api",
            "framework": "clang"
        },
        {
            "name": "实用工具和辅助函数",
            "description": """
# Utility Functions and Helpers

## 字符串和类型操作
```cpp
// 检查类型
bool isPointerType(QualType T) {
  return T->isPointerType();
}

bool isArrayType(QualType T) {
  return T->isArrayType();
}

// 获取类型信息
QualType getPointeeType(QualType T) {
  return T->getPointeeType();
}

StringRef getTypeName(QualType T) {
  return T.getAsString();
}
```

## 位置和范围
```cpp
// 获取源位置
SourceLocation Loc = Stmt->getBeginLoc();
SourceRange Range = Stmt->getSourceRange();

// 检查位置有效性
bool isValidLocation(SourceLocation Loc) {
  return Loc.isValid();
}

// 获取文件名和行号
StringRef FileName = SM.getFilename(Loc);
unsigned LineNo = SM.getSpellingLineNumber(Loc);
```

## 符号和值操作
```cpp
// 检查符号类型
bool isSymbol(SymbolRef Sym) {
  return Sym && !Sym->isUnknown();
}

// 获取符号值
const llvm::APSInt *getSymbolValue(SymbolRef Sym, ProgramStateRef State) {
  return State->getConstraintManager().getSymVal(State, Sym);
}

// 符号比较
bool areEqual(SymbolRef Sym1, SymbolRef Sym2) {
  return Sym1 == Sym2;
}
```

## 容器和迭代器
```cpp
// 遍历函数参数
void processFunctionParams(const FunctionDecl *FD) {
  for (auto Param : FD->parameters()) {
    // 处理每个参数
  }
}

// 遍历语句子节点
void processStmtChildren(const Stmt *S) {
  for (const Stmt *Child : S->children()) {
    // 处理每个子节点
  }
}
```

## 调试和日志
```cpp
// 调试输出
void debugStmt(const Stmt *S, ASTContext &Ctx) {
  S->dump(Ctx);
}

void debugType(QualType T) {
  T.dump();
}

// 条件调试
#ifndef NDEBUG
#define DEBUG_STMT(S) (S)->dump(Ctx)
#else
#define DEBUG_STMT(S)
#endif
```
            """,
            "category": "framework_api",
            "framework": "clang"
        },
        {
            "name": "错误处理和异常安全",
            "description": """
# Error Handling and Exception Safety

## 异常安全检查
```cpp
// 检查是否在try块中
bool isInTryBlock(const LocationContext *LC) {
  for (const LocationContext *Ctx = LC; Ctx; Ctx = Ctx->getParent()) {
    if (isa<CXXTryStmt>(Ctx->getDecl())) {
      return true;
    }
  }
  return false;
}

// 检查异常处理
bool hasExceptionHandler(const CXXThrowExpr *Throw, CheckerContext &C) {
  // 检查是否存在合适的catch块
  // 实现细节...
}
```

## 资源管理
```cpp
// 检查RAII模式
bool usesRAII(const VarDecl *VD) {
  QualType T = VD->getType();
  if (const CXXRecordDecl *RD = T->getAsCXXRecordDecl()) {
    // 检查是否有析构函数
    return RD->hasUserDeclaredDestructor();
  }
  return false;
}

// 检查智能指针
bool isSmartPointer(QualType T) {
  StringRef TypeName = T.getAsString();
  return TypeName.startswith("std::unique_ptr") ||
         TypeName.startswith("std::shared_ptr") ||
         TypeName.startswith("std::weak_ptr");
}
```

## 内存管理检查
```cpp
// 检查内存释放
bool isMemoryDeallocated(const MemRegion *Region, ProgramStateRef State) {
  // 检查区域是否已被释放
  // 实现细节...
}

// 检查双重释放
bool isDoubleFree(const MemRegion *Region, ProgramStateRef State) {
  // 检查是否已被释放过
  // 实现细节...
}
```

## 断言和不变式
```cpp
// 添加运行时断言
void addAssertion(ProgramStateRef State, const SVal &Val, bool Expected) {
  // 在状态中添加断言
  // 实现细节...
}

// 检查不变式
bool checkInvariant(ProgramStateRef State, const MemRegion *Region) {
  // 检查区域的不变式
  // 实现细节...
}
```
            """,
            "category": "framework_api",
            "framework": "clang"
        },
        {
            "name": "性能优化和内存管理",
            "description": """
# Performance Optimization and Memory Management

## 内存池使用
```cpp
// 使用BumpPtrAllocator
llvm::BumpPtrAllocator &Alloc = C.getAllocator();

// 分配内存
void *Ptr = Alloc.Allocate(Size, Alignment);

// 注意：BumpPtrAllocator不会释放单个分配
```

## 缓存机制
```cpp
// 结果缓存
class ResultCache {
private:
  llvm::DenseMap<const Stmt *, AnalysisResult> Cache;

public:
  const AnalysisResult *get(const Stmt *S) const {
    auto It = Cache.find(S);
    return It != Cache.end() ? &It->second : nullptr;
  }

  void set(const Stmt *S, const AnalysisResult &Result) {
    Cache[S] = Result;
  }
};
```

## 增量分析
```cpp
// 检测变更
bool hasChanged(const Decl *D, AnalysisManager &AM) {
  // 检查声明是否在上次分析后改变
  // 实现细节...
}

// 增量更新
void updateAnalysis(const Decl *D, AnalysisManager &AM) {
  if (hasChanged(D, AM)) {
    // 只重新分析变更的部分
    performIncrementalAnalysis(D);
  }
}
```

## 分析限制
```cpp
// 设置分析深度限制
const unsigned MaxDepth = 10;
static unsigned CurrentDepth = 0;

bool shouldContinueAnalysis() {
  return CurrentDepth < MaxDepth;
}

// 超时控制
bool hasTimedOut() {
  auto CurrentTime = std::chrono::steady_clock::now();
  auto Elapsed = CurrentTime - StartTime;
  return Elapsed > MaxAnalysisTime;
}
```

## 资源清理
```cpp
// 清理分析状态
void cleanupAnalysis(CheckerContext &C) {
  // 释放临时资源
  // 重置缓存
  // 清理状态
}

// 内存使用监控
size_t getMemoryUsage() {
  // 获取当前内存使用量
  // 实现细节...
}

bool shouldThrottleAnalysis() {
  return getMemoryUsage() > MaxMemoryUsage;
}
```
            """,
            "category": "framework_api",
            "framework": "clang"
        }
    ]

    for api in clang_apis:
        entry = KnowledgeEntry(
            id="",
            content=api["description"],
            title=f"Clang API: {api['name']}",
            category="framework_api",
            framework="clang",
            language="cpp",
            metadata={
                "api_name": api["name"],
                "source": "clang_documentation",
                "api_category": "core_api"
            }
        )
        entries.append(entry)

    print(f"✅ 收集到 {len(entries)} 个Clang API文档条目")
    return entries

def collect_codeql_api_docs() -> List[KnowledgeEntry]:
    """
    收集CodeQL API文档信息

    Returns:
        知识条目列表
    """
    entries = []

    # 完整的CodeQL API信息
    codeql_apis = [
        {
            "name": "数据流分析核心API",
            "description": """
# CodeQL Data Flow Analysis API

## 核心概念

### DataFlow::Node
数据流图中的节点，表示程序中的一个位置。

```ql
class DataFlow::Node {
  // 获取节点对应的表达式
  Expr getExpr();

  // 获取节点对应的AST节点
  AstNode asAstNode();

  // 检查节点是否有后继
  predicate hasSuccessor(DataFlow::Node successor);

  // 获取节点的字符串表示
  string toString();
}
```

### DataFlow::PathNode
路径敏感数据流分析中的路径节点。

```ql
class DataFlow::PathNode {
  // 获取数据流节点
  DataFlow::Node getNode();

  // 获取路径图
  DataFlow::PathGraph getPathGraph();

  // 获取路径摘要
  string getPathSummary();
}
```

## 基本数据流分析

### 简单数据流
```ql
// 导入数据流库
import semmle.code.java.dataflow.DataFlow

// 定义配置
module Config implements DataFlow::ConfigSig {
predicate isSource(DataFlow::Node source) {
    // 污染源：用户输入
    exists(MethodCall mc |
      mc.getMethod().getName() = "getParameter" and
      source.asExpr() = mc
  )
}

predicate isSink(DataFlow::Node sink) {
    // 污染汇：SQL执行
    exists(MethodCall mc |
      mc.getMethod().getName() = "executeQuery" and
      sink.asExpr() = mc.getArgument(0)
    )
  }
}

// 创建全局数据流
module Flow = DataFlow::Global<Config>;

// 查询数据流路径
from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink, source, sink,
  "Data flows from $@ to $@",
  source.getNode(), "source",
  sink.getNode(), "sink"
```

### 局部数据流
```ql
// 在方法内跟踪数据流
from DataFlow::Node source, DataFlow::Node sink
where
  source.asExpr().(MethodCall).getMethod().getName() = "getParameter" and
  sink.asExpr().(MethodCall).getMethod().getName() = "executeQuery" and
  DataFlow::localFlow(source, sink)
select sink, "Local data flow detected"
```

### 跨过程数据流
```ql
// 跟踪跨函数的数据流
from DataFlow::Node source, DataFlow::Node sink
where
  source.asExpr().(MethodCall).getMethod().getName() = "getParameter" and
  sink.asExpr().(MethodCall).getMethod().getName() = "executeQuery" and
  DataFlow::flow(source, sink)
select sink, "Inter-procedural data flow detected"
```
            """,
            "category": "framework_api",
            "framework": "codeql"
        },
        {
            "name": "污点跟踪API",
            "description": """
# CodeQL Taint Tracking API

## 污点跟踪基础

### 污点源 (Taint Sources)
```ql
// 基本污点源定义
predicate isSource(DataFlow::Node source) {
  // HTTP参数
  exists(MethodCall mc |
    mc.getMethod().getName() = "getParameter" and
    source.asExpr() = mc
  ) or
  // 文件读取
  exists(MethodCall mc |
    mc.getMethod().getName() = "readLine" and
    source.asExpr() = mc
  ) or
  // 环境变量
  exists(MethodCall mc |
    mc.getMethod().getName() = "getenv" and
    source.asExpr() = mc
  )
}
```

### 污点汇 (Taint Sinks)
```ql
// 危险操作定义
predicate isSink(DataFlow::Node sink) {
  // SQL注入
  exists(MethodCall mc |
    mc.getMethod().getName() = "executeQuery" and
    sink.asExpr() = mc.getArgument(0)
  ) or
  // 命令注入
  exists(MethodCall mc |
    mc.getMethod().getName() = "exec" and
    sink.asExpr() = mc.getArgument(0)
  ) or
  // XSS
  exists(MethodCall mc |
    mc.getMethod().getName() = "write" and
    mc.getReceiver().getType().getName() = "HttpServletResponse" and
    sink.asExpr() = mc.getArgument(0)
  )
}
```

### 污点屏障 (Taint Barriers)
```ql
  // 净化函数定义
predicate isSanitizer(DataFlow::Node node) {
  // 输入验证
  exists(MethodCall mc |
    mc.getMethod().getName() = "validateInput" and
    node.asExpr() = mc
  ) or
  // HTML编码
  exists(MethodCall mc |
    mc.getMethod().getName() = "encodeForHTML" and
    node.asExpr() = mc
  ) or
  // SQL转义
  exists(MethodCall mc |
    mc.getMethod().getName() = "escapeSql" and
    node.asExpr() = mc
  )
}
```

## 污点跟踪配置

### 标准配置
```ql
module TaintConfig implements TaintTracking::ConfigSig {
  predicate isSource = isSource/1;
  predicate isSink = isSink/1;
  predicate isBarrier = isSanitizer/1;
}
```

### 自定义配置
```ql
module CustomTaintConfig implements TaintTracking::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    // 自定义污点源逻辑
    source.asExpr().(MethodCall).getMethod().getName() = "getUserInput"
  }

  predicate isSink(DataFlow::Node sink) {
    // 自定义污点汇逻辑
    exists(MethodCall mc |
      mc.getMethod().getName() = "dangerousOperation" and
      sink.asExpr() = mc.getArgument(0)
    )
  }

  predicate isBarrier(DataFlow::Node node) {
    // 自定义屏障逻辑
    node.asExpr().(MethodCall).getMethod().getName() = "sanitize"
  }
}
```

## 污点跟踪查询

### 基本污点跟踪
```ql
module TaintFlow = TaintTracking::Global<TaintConfig>;

from TaintFlow::PathNode source, TaintFlow::PathNode sink
where TaintFlow::flowPath(source, sink)
select sink, source, sink,
  "Taint flows from $@ to $@",
  source.getNode(), "source",
  sink.getNode(), "sink"
```

### 带步骤的污点跟踪
```ql
from TaintFlow::PathNode source, TaintFlow::PathNode sink
where
  TaintFlow::flowPath(source, sink) and
  sink.getNode().asExpr().(MethodCall).getMethod().getName() = "executeQuery"
select sink,
  "SQL injection vulnerability: tainted data reaches SQL execution"
```

### 局部污点跟踪
```ql
from DataFlow::Node source, DataFlow::Node sink
where
  isSource(source) and
  isSink(sink) and
  TaintTracking::localTaint(source, sink)
select sink, "Local taint flow detected"
```
            """,
            "category": "framework_api",
            "framework": "codeql"
        },
        {
            "name": "控制流分析API",
            "description": """
# CodeQL Control Flow Analysis API

## 控制流图 (CFG)

### 基本块 (BasicBlock)
```ql
class BasicBlock {
  // 获取基本块的语句
  Stmt getStmt(int index);

  // 获取基本块的语句数量
  int getStmtCount();

  // 检查基本块是否为空
  predicate isEmpty();
}
```

### 控制流边 (Control Flow Edges)
```ql
// 从基本块A到基本块B的控制流
predicate controlFlowEdge(BasicBlock pred, BasicBlock succ) {
  // 实现细节...
}

// 获取基本块的前驱
BasicBlock getAPredecessor(BasicBlock bb) {
  exists(BasicBlock pred | controlFlowEdge(pred, bb) | result = pred)
}

// 获取基本块的后继
BasicBlock getASuccessor(BasicBlock bb) {
  exists(BasicBlock succ | controlFlowEdge(bb, succ) | result = succ)
}
```

## 条件和分支

### 条件语句
```ql
// 分析if语句
from IfStmt ifs, Expr cond
where cond = ifs.getCondition()
select ifs, cond, "Conditional statement found"

// 分析条件表达式
from ConditionalExpr condExpr
select condExpr,
  condExpr.getCondition(),
  condExpr.getTrueExpr(),
  condExpr.getFalseExpr()
```

### 循环结构
```ql
// 分析for循环
from ForStmt forLoop
select forLoop,
  forLoop.getInit(),
  forLoop.getCondition(),
  forLoop.getUpdate(),
  forLoop.getStmt()

// 分析while循环
from WhileStmt whileLoop
select whileLoop,
  whileLoop.getCondition(),
  whileLoop.getStmt()
```

### 异常处理
```ql
// 分析try-catch块
from TryStmt tryStmt
select tryStmt,
  tryStmt.getTryBlock(),
  tryStmt.getCatchClause(0)  // 第一个catch块

// 分析throw语句
from ThrowExpr throwExpr
select throwExpr, throwExpr.getSubExpr()
```

## 路径敏感分析

### 条件路径
```ql
// 检查特定路径上的条件
predicate conditionHoldsOnPath(BasicBlock start, BasicBlock end, Expr condition) {
  // 检查从start到end的路径上condition是否总是为真
  // 实现细节...
}

// 可达性分析
predicate isReachable(BasicBlock bb) {
  exists(BasicBlock entry | isEntryBlock(entry) |
    controlFlowEdge+(entry, bb))
}
```

### 支配关系
```ql
// 支配关系：A支配B，如果所有到达B的路径都经过A
predicate dominates(BasicBlock dominator, BasicBlock dominated) {
  // 实现支配关系检查
  // 实现细节...
}

// 严格支配
predicate strictlyDominates(BasicBlock dominator, BasicBlock dominated) {
  dominates(dominator, dominated) and dominator != dominated
}
```

## 控制依赖

### 后支配
```ql
// 后支配：A后支配B，如果所有离开B的路径都经过A
predicate postDominates(BasicBlock postDominator, BasicBlock postDominated) {
  // 实现后支配检查
  // 实现细节...
}
```

### 控制依赖边
```ql
// 基本块B控制依赖于基本块A，如果：
// 1. A有一个后继A1和A2
// 2. 从A1可达B，从A2可达B
// 3. A1和A2都不支配B
predicate controlDependent(BasicBlock control, BasicBlock dependent) {
  exists(BasicBlock a1, BasicBlock a2 |
    controlFlowEdge(control, a1) and
    controlFlowEdge(control, a2) and
    a1 != a2 and
    isReachable(a1, dependent) and
    isReachable(a2, dependent) and
    not dominates(a1, dependent) and
    not dominates(a2, dependent))
}
```
            """,
            "category": "framework_api",
            "framework": "codeql"
        },
        {
            "name": "查询语言基础",
            "description": """
# CodeQL Query Language Fundamentals

## 查询结构

### 基本查询格式
```ql
from /* 变量声明 */
where /* 条件过滤 */
select /* 结果选择 */
```

### 完整查询示例
```ql
from MethodCall mc, Method method
where
  mc.getMethod() = method and
  method.getName() = "executeQuery" and
  mc.getNumArgument() = 1
select mc, "Found SQL execution call"
```

## 谓词 (Predicates)

### 谓词定义
```ql
// 无参数谓词
predicate isJava() {
  exists(File f | f.getExtension() = "java")
}

// 有参数谓词
predicate hasMethod(Class c, string methodName) {
  exists(Method m |
    m.getDeclaringType() = c and
    m.getName() = methodName
  )
}

// 递归谓词
predicate isInLoop(Stmt s) {
  s instanceof LoopStmt or
  exists(Stmt parent | isInLoop(parent) and parent = s.getParent())
}
```

### 谓词调用
```ql
from Class c
where hasMethod(c, "toString")
select c, "Class has toString method"
```

## 模块系统

### 模块定义
```ql
module MyAnalysis {
  // 私有谓词
  predicate privateHelper() { ... }

  // 导出的谓词
  predicate isInteresting(Class c) { ... }
}
```

### 模块导入
```ql
import MyAnalysis

from Class c
where MyAnalysis::isInteresting(c)
select c
```

### 参数化模块
```ql
module AnalysisForMethod(string methodName) {
  predicate callsMethod() {
    exists(MethodCall mc |
      mc.getMethod().getName() = methodName
    )
  }
}

// 使用参数化模块
module StringAnalysis = AnalysisForMethod("String");
```

## 类型系统

### 基本类型
```ql
// 字符串
string getName() { result = "example" }

// 整数
int getCount() { result = 42 }

// 布尔值
boolean isValid() { result = true }

// 浮点数
float getRatio() { result = 3.14 }
```

### 类类型
```ql
class MyClass extends @class {
  string getName() { result = this.getStringValue() }
  int getLine() { result = this.getLocation().getStartLine() }
}
```

## 聚合操作

### 计数
```ql
// 计算每个类的方发表数量
from Class c
select c, count(Method m | m.getDeclaringType() = c)
```

### 求和
```ql
// 计算方法的总行数
from Method m
select m, sum(int line | line = m.getLocation().getNumberOfLines())
```

### 平均值
```ql
// 计算平均方法长度
select avg(float lines |
  exists(Method m | lines = m.getNumberOfLines())
)
```

### 最小/最大值
```ql
// 找到最长的方法
from Method m
select m, max(int lines | lines = m.getNumberOfLines())
```

## 字符串操作

### 字符串连接
```ql
string fullName() {
  result = "Method: " + this.getName()
}
```

### 字符串比较
```ql
predicate hasPrefix(string s, string prefix) {
  s.prefixOf(prefix)
}

predicate hasSuffix(string s, string suffix) {
  s.suffixOf(suffix)
}
```

### 正则表达式
```ql
predicate matchesPattern(string s) {
  s.regexpMatch("get.*")
}
```

## 递归查询

### 递归谓词
```ql
// 计算继承深度
int inheritanceDepth(Class c) {
  if exists(Class super | super = c.getASupertype())
  then 1 + max(int depth |
    exists(Class super | super = c.getASupertype() |
      depth = inheritanceDepth(super)
    )
  )
  else 0
}
```

### 传递闭包
```ql
// 传递闭包：所有子类
Class getADescendant(Class c) {
  result = c or
  result = getADescendant(c.getASubtype())
}
```

### 固定点计算
```ql
// 找到所有可能受污染的方法
predicate tainted(Method m) {
  // 直接调用污染源
  exists(MethodCall mc |
    mc.getCaller() = m and
    tainted(mc.getCallee())
  ) or
  // 基础情况：直接调用污染源
  exists(MethodCall mc |
    mc.getCaller() = m and
    isSource(mc.getCallee())
  )
}
```
            """,
            "category": "framework_api",
            "framework": "codeql"
        },
        {
            "name": "标准库和内置谓词",
            "description": """
# CodeQL Standard Library and Built-in Predicates

## 字符串库

### 字符串操作
```ql
// 字符串长度
int stringLength(string s) {
  result = s.length()
}

// 子字符串
string substring(string s, int start, int end) {
  result = s.substring(start, end)
}

// 字符串查找
int indexOf(string s, string substr) {
  result = s.indexOf(substr)
}

// 大小写转换
string toLowerCase(string s) {
  result = s.toLowerCase()
}

string toUpperCase(string s) {
  result = s.toUpperCase()
}

// 字符串替换
string replaceAll(string s, string old, string new) {
  result = s.replaceAll(old, new)
}
```

### 正则表达式
```ql
// 正则匹配
predicate regexpMatch(string s, string regex) {
  s.regexpMatch(regex)
}

// 正则替换
string regexpReplaceAll(string s, string regex, string replacement) {
  result = s.regexpReplaceAll(regex, replacement)
}

// 正则分组提取
string regexpCapture(string s, string regex, int group) {
  result = s.regexpCapture(regex, group)
}
```

## 集合操作

### 列表操作
```ql
// 列表构造函数
List[string] getStringList() {
  result = ["a", "b", "c"]
}

// 列表连接
List[string] concatLists(List[string] l1, List[string] l2) {
  result = l1 + l2
}

// 列表长度
int listLength(List[string] l) {
  result = l.length()
}

// 列表索引访问
string getElement(List[string] l, int index) {
  result = l.getElement(index)
}
```

### 集合操作
```ql
// 集合构造函数
Set[string] getStringSet() {
  result = {"a", "b", "c"} as Set
}

// 集合并集
Set[string] unionSets(Set[string] s1, Set[string] s2) {
  result = s1.union(s2)
}

// 集合交集
Set[string] intersectSets(Set[string] s1, Set[string] s2) {
  result = s1.intersect(s2)
}

// 成员检查
predicate inSet(string s, Set[string] set) {
  set.contains(s)
}
```

## 数学操作

### 算术运算
```ql
// 基本运算
int add(int x, int y) { result = x + y }
int subtract(int x, int y) { result = x - y }
int multiply(int x, int y) { result = x * y }
int divide(int x, int y) { result = x / y }
int modulo(int x, int y) { result = x % y }

// 比较运算
boolean equals(int x, int y) { result = x = y }
boolean lessThan(int x, int y) { result = x < y }
boolean greaterThan(int x, int y) { result = x > y }

// 位运算
int bitwiseAnd(int x, int y) { result = x & y }
int bitwiseOr(int x, int y) { result = x | y }
int bitwiseXor(int x, int y) { result = x ^ y }
int shiftLeft(int x, int n) { result = x << n }
int shiftRight(int x, int n) { result = x >> n }
```

### 统计函数
```ql
// 计数
int countElements(Class c) {
  result = count(Method m | m.getDeclaringType() = c)
}

// 求和
int sumLines(Class c) {
  result = sum(Method m |
    m.getDeclaringType() = c and
    result = m.getNumberOfLines()
  )
}

// 平均值
float avgLines(Class c) {
  result = avg(Method m |
    m.getDeclaringType() = c and
    result = m.getNumberOfLines()
  )
}

// 最大值
int maxLines(Class c) {
  result = max(Method m |
    m.getDeclaringType() = c and
    result = m.getNumberOfLines()
  )
}

// 最小值
int minLines(Class c) {
  result = min(Method m |
    m.getDeclaringType() = c and
    result = m.getNumberOfLines()
  )
}
```

## 文件和位置操作

### 文件操作
```ql
// 获取文件扩展名
string getFileExtension(File f) {
  result = f.getExtension()
}

// 获取文件基本名
string getFileBaseName(File f) {
  result = f.getBaseName()
}

// 检查文件是否存在
predicate fileExists(string path) {
  exists(File f | f.getAbsolutePath() = path)
}
```

### 位置操作
```ql
// 获取位置信息
int getStartLine(Location loc) {
  result = loc.getStartLine()
}

int getEndLine(Location loc) {
  result = loc.getEndLine()
}

int getStartColumn(Location loc) {
  result = loc.getStartColumn()
}

int getEndColumn(Location loc) {
  result = loc.getEndColumn()
}

string getFilePath(Location loc) {
  result = loc.getFile().getAbsolutePath()
}
```

## 类型检查谓词

### 类型关系
```ql
// 子类型检查
predicate isSubtype(Type sub, Type sup) {
  sub.getASupertype*() = sup
}

// 接口实现检查
predicate implementsInterface(Class c, Interface i) {
  c.getASupertype+() = i
}

// 方法覆盖检查
predicate overrides(Method overriding, Method overridden) {
  overriding.getName() = overridden.getName() and
  overriding.getDeclaringType().getASupertype+() = overridden.getDeclaringType() and
  overriding.getSignature() = overridden.getSignature()
}
```

### 可见性检查
```ql
predicate isPublic(Method m) {
  m.isPublic()
}

predicate isPrivate(Method m) {
  m.isPrivate()
}

predicate isProtected(Method m) {
  m.isProtected()
}

predicate isPackagePrivate(Method m) {
  not (m.isPublic() or m.isPrivate() or m.isProtected())
}
```

## 实用工具谓词

### 调试和日志
```ql
// 字符串转换
string toString(Element e) {
  result = e.toString()
}

// 类型名称
string getTypeName(Type t) {
  result = t.getName()
}

// 限定名
string getQualifiedName(NamedElement e) {
  result = e.getQualifiedName()
}
```
            """,
            "category": "framework_api",
            "framework": "codeql"
        },
        {
            "name": "扩展机制和自定义库",
            "description": """
# CodeQL Extension Mechanisms and Custom Libraries

## QL扩展机制

### 自定义谓词库
```ql
// MySecurity.ql
module MySecurity {
  // 自定义安全相关谓词
  predicate isSensitiveDataType(Type t) {
    t.getName().regexpMatch(".*(password|credit|ssn).*")
  }

  predicate isEncryptionMethod(Method m) {
    m.getName().regexpMatch(".*(encrypt|hash|encode).*")
  }

  predicate isDecryptionMethod(Method m) {
    m.getName().regexpMatch(".*(decrypt|unhash|decode).*")
  }
}
```

### 数据扩展模型
```ql
// MyDataExtensions.qll
module MyDataExtensions {
  // 自定义数据流模型
  class MySource extends DataFlow::Node {
    MySource() {
      // 自定义污染源定义
      this.asExpr().(MethodCall).getMethod().getName() = "getMyInput"
    }
  }

  class MySink extends DataFlow::Node {
    MySink() {
      // 自定义污染汇定义
      this.asExpr().(MethodCall).getMethod().getName() = "executeMyQuery"
    }
  }
}
```

## 模块化查询设计

### 查询模块化
```ql
// BaseSecurity.ql - 基础安全模块
module BaseSecurity {
  predicate isUserInput(DataFlow::Node node) {
    exists(MethodCall mc |
      mc.getMethod().getName() in ["getParameter", "readLine", "nextLine"] and
      node.asExpr() = mc
    )
  }

  predicate isDangerousSink(DataFlow::Node node) {
    exists(MethodCall mc |
      mc.getMethod().getName() in ["executeQuery", "exec", "eval"] and
      node.asExpr() = mc.getArgument(0)
    )
  }
}

// SpecificVulnerability.ql - 具体漏洞查询
import BaseSecurity

module Config implements DataFlow::ConfigSig {
  predicate isSource = BaseSecurity::isUserInput/1;
  predicate isSink = BaseSecurity::isDangerousSink/1;
}

module Flow = DataFlow::Global<Config>;

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink, source, sink, "Data flow from user input to dangerous operation"
```

## 自定义数据流模型

### 摘要模型 (Summary Models)
```ql
// MyLibraryModels.qll
module MyLibraryModels {
  // 方法摘要：定义方法如何传播数据
  predicate summaryModel(MethodCall mc, DataFlow::Node input, DataFlow::Node output) {
    // 字符串连接方法
    mc.getMethod().getName() = "concat" and
    (input.asExpr() = mc.getArgument(0) or input.asExpr() = mc.getArgument(1)) and
    output.asExpr() = mc
  }

  // 污染步骤：定义污染如何传播
  predicate stepModel(MethodCall mc, DataFlow::Node input, DataFlow::Node output) {
    // URL编码方法 - 认为输入已被清理
    mc.getMethod().getName() = "encodeURIComponent" and
    input.asExpr() = mc.getArgument(0) and
    output.asExpr() = mc
  }
}
```

### 源/汇模型 (Source/Sink Models)
```ql
// MyExternalModels.qll
module MyExternalModels {
  // 自定义污染源
  predicate sourceModel(DataFlow::Node node, string kind) {
    // 第三方库的输入方法
    exists(MethodCall mc |
      mc.getReceiver().getType().getName() = "ThirdPartyLibrary" and
      mc.getMethod().getName() = "getInput" and
      node.asExpr() = mc and
      kind = "third-party-input"
    )
  }

  // 自定义污染汇
  predicate sinkModel(DataFlow::Node node, string kind) {
    // 危险的第三方库方法
    exists(MethodCall mc |
      mc.getReceiver().getType().getName() = "DangerousLibrary" and
      mc.getMethod().getName() = "execute" and
      node.asExpr() = mc.getArgument(0) and
      kind = "code-injection"
    )
  }
}
```

## 扩展YAML配置

### 扩展包配置
```yaml
# qlpack.yml
name: my-custom-queries
version: 1.0.0
libraryPathDependencies:
  - codeql/java-all
  - codeql/javascript-all

dependencies:
  - my/library/models: "*"
```

### 数据扩展配置
```yaml
# MyExtensions.yml
extensions:
  - addsTo:
      pack: codeql/java-all
      extensible: sourceModel
    data:
      - ["my.package", "MyClass", "getInput", "", "third-party-input"]

  - addsTo:
      pack: codeql/java-all
      extensible: sinkModel
    data:
      - ["my.package", "MyClass", "execute", "0", "code-injection"]
```

## 自定义查询管道

### 分析管道扩展
```python
# my_analysis_pipeline.py
from codeql import AnalysisPipeline

class MyAnalysisPipeline(AnalysisPipeline):
    def __init__(self):
        super().__init__()
        self.add_custom_models()

    def add_custom_models(self):
        # 添加自定义数据流模型
        self.add_model_file("MyLibraryModels.qll")
        self.add_model_file("MyExternalModels.qll")

    def run_custom_analysis(self):
        # 执行自定义分析步骤
        self.run_query("MySecurity.ql")
        self.run_query("MyVulnerabilityChecks.ql")

# 使用自定义管道
pipeline = MyAnalysisPipeline()
pipeline.run_custom_analysis()
```

## 性能优化

### 查询优化技巧
```ql
// 使用索引友好的谓词
from Method m
where m.getName() = "toString"  // 索引友好
select m

// 避免笛卡尔积
from Method m, Class c
where m.getDeclaringType() = c  // 使用连接而不是笛卡尔积
select m, c
```

### 缓存和重用
```ql
// 缓存复杂计算结果
cached predicate expensiveComputation(Class c) {
  // 复杂计算，只执行一次
  exists(Method m |
    m.getDeclaringType() = c and
    // 复杂条件...
  )
}

// 重用计算结果
from Class c
where expensiveComputation(c)
select c
```

## 测试和验证

### 单元测试
```ql
// MySecurityTest.ql
import MySecurity

from Class c
where MySecurity::isInteresting(c)
select c, "Found interesting class for testing"
```

### 集成测试
```python
# test_my_extensions.py
def test_my_extensions():
    # 测试自定义扩展
    results = run_codeql_query("MySecurity.ql")
    assert len(results) > 0, "No results from custom security queries"

    # 验证扩展正确加载
    assert model_loaded("MyLibraryModels"), "Custom models not loaded"
```

## 最佳实践

### 模块组织
```
MySecurityPack/
├── qlpack.yml                    # 包配置
├── MySecurity.ql                 # 主要查询
├── models/                       # 数据模型
│   ├── MyLibraryModels.qll
│   └── MyExternalModels.qll
├── queries/                      # 查询文件
│   ├── CWE-089.ql               # SQL注入
│   └── CWE-078.ql               # 命令注入
└── tests/                       # 测试文件
    ├── MySecurityTest.ql
    └── test_my_extensions.py
```

### 命名约定
- 模块名使用驼峰命名：`MySecurityModule`
- 谓词名使用驼峰命名：`isSensitiveData`
- 文件名使用驼峰命名：`MySecurityQueries.ql`
- 测试文件名添加`Test`后缀：`MySecurityTest.ql`

### 文档化
```ql
/**
 * MySecurity模块
 *
 * 提供自定义安全分析功能，包括：
 * - 敏感数据识别
 * - 危险操作检测
 * - 数据流分析扩展
 *
 * @author Your Name
 * @version 1.0.0
 * @since 2023-01-01
 */
module MySecurity {
  // 模块实现...
}
```
            """,
            "category": "framework_api",
            "framework": "codeql"
        }
    ]

    for api in codeql_apis:
        entry = KnowledgeEntry(
            id="",
            content=api["description"],
            title=f"CodeQL API: {api['name']}",
            category=api["category"],
            framework=api["framework"],
            language="ql",
            metadata={
                "api_name": api["name"],
                "source": "codeql_documentation"
            }
        )
        entries.append(entry)

    print(f"✅ 收集到 {len(entries)} 个CodeQL API文档条目")
    return entries

def main():
    """主函数"""
    print("🤖 从KNighter和官方文档收集知识库数据")
    print("=" * 50)

    # 初始化数据收集器
    collector = ComprehensiveDataCollector()

    # 收集所有知识条目
    all_entries = []

    # 1. 从KNighter收集检查器示例
    print("\n" + "="*60)
    print("📂 第一阶段: 收集KNighter项目数据")
    print("="*60)

    # 尝试多个可能的KNighter路径
    possible_knighter_paths = [
        "/home/spa/KNighter",      # 宿主机路径
        "../KNighter",            # 相对路径
        str(project_root.parent / "KNighter"),  # 项目同级目录
        "/app/KNighter"          # 容器内路径（备选）
    ]

    knighter_entries = []
    knighter_path = None

    for path in possible_knighter_paths:
        if Path(path).exists():
            knighter_path = Path(path)
            print(f"✅ 找到KNighter项目: {knighter_path}")
            knighter_entries = collector.collect_knighter_data()
            break

    if not knighter_entries:
        print("⚠️  未找到KNighter项目，跳过KNighter数据收集")
        print("💡 请确保KNighter项目在以下路径之一:")
        for path in possible_knighter_paths:
            print(f"   - {path}")
    else:
        print(f"✅ KNighter数据收集完成，共 {len(knighter_entries)} 条")

    all_entries.extend(knighter_entries)

    # 2. 从IRIS收集数据
    print("\n" + "="*60)
    print("🌸 第二阶段: 收集IRIS项目数据")
    print("="*60)

    iris_entries = collector.collect_iris_data()
    if iris_entries:
        print(f"✅ IRIS数据收集完成，共 {len(iris_entries)} 条")
    else:
        print("⚠️  IRIS数据收集跳过")

    all_entries.extend(iris_entries)

    # 3. 收集官方文档和外部数据
    print("\n" + "="*60)
    print("📚 第三阶段: 收集官方文档和外部数据")
    print("="*60)

    # CWE数据库
    cwe_entries = collector.collect_cwe_database()
    all_entries.extend(cwe_entries)
    print(f"✅ CWE数据库收集完成，共 {len(cwe_entries)} 条")

    # LLVM/Clang官方文档
    llvm_entries = collector.collect_llvm_docs()
    all_entries.extend(llvm_entries)
    print(f"✅ LLVM/Clang文档收集完成，共 {len(llvm_entries)} 条")

    # CodeQL官方资源
    codeql_official_entries = collector.collect_codeql_official()
    all_entries.extend(codeql_official_entries)
    print(f"✅ CodeQL官方资源收集完成，共 {len(codeql_official_entries)} 条")

    # 安全最佳实践
    security_entries = collector.collect_security_best_practices()
    all_entries.extend(security_entries)
    print(f"✅ 安全最佳实践收集完成，共 {len(security_entries)} 条")

    # 开源工具数据
    tools_entries = collector.collect_open_source_tools()
    all_entries.extend(tools_entries)
    print(f"✅ 开源工具数据收集完成，共 {len(tools_entries)} 条")

    # 内置API文档（最后收集，避免重复）
    clang_api_entries = collect_clang_api_docs()
    all_entries.extend(clang_api_entries)
    print(f"✅ Clang API文档收集完成，共 {len(clang_api_entries)} 条")

    codeql_api_entries = collect_codeql_api_docs()
    all_entries.extend(codeql_api_entries)
    print(f"✅ CodeQL API文档收集完成，共 {len(codeql_api_entries)} 条")

    print(f"\n📊 总共收集到 {len(all_entries)} 个知识条目")

    # 按类别分别保存数据
    data_dir = project_root / "data"
    data_dir.mkdir(parents=True, exist_ok=True)

    # 按类别分组
    entries_by_category = {}
    for entry in all_entries:
        category = entry.category
        if category not in entries_by_category:
            entries_by_category[category] = []
        entries_by_category[category].append(entry)

    # 保存各分类数据
    saved_files = []
    total_saved = 0

    for category, entries in entries_by_category.items():
        filename = f"knowledge_{category}.json"
        output_file = data_dir / filename

        data = {
            "metadata": {
                "category": category,
                "total_entries": len(entries),
                "source": "knighter_database" if category in ["code_examples", "cwe_patterns"] else "api_docs",
                "collected_at": datetime.now().isoformat()
            },
            "entries": [entry.__dict__ for entry in entries]
        }

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

        saved_files.append(str(output_file))
        total_saved += len(entries)
        print(f"✅ 保存 {category} 类别: {len(entries)} 条 → {filename}")

    # 同时保存汇总文件
    summary_file = data_dir / "knowledge_summary.json"
    summary_data = {
        "metadata": {
            "total_entries": len(all_entries),
            "categories": list(entries_by_category.keys()),
            "sources": ["knighter_database", "clang_docs", "codeql_docs"],
            "collected_at": datetime.now().isoformat(),
            "files": saved_files
        },
        "category_stats": {
            category: len(entries)
            for category, entries in entries_by_category.items()
        }
    }

    with open(summary_file, 'w', encoding='utf-8') as f:
        json.dump(summary_data, f, ensure_ascii=False, indent=2)

    print(f"✅ 汇总文件已保存: {summary_file}")
    print(f"📊 数据分布: {summary_data['category_stats']}")

    # 保存收集到的数据（暂不导入到知识库）
    print("\n💾 保存收集到的数据...")
    print("⚠️  注意：知识库导入功能暂时跳过，请手动运行以下命令完成导入：")
    print("   cd /home/spa/LLM-Native")
    print("   python3 -c \"from src.knowledge_base.manager import KnowledgeBaseManager; kb = KnowledgeBaseManager(); kb.bulk_add_entries(your_entries)\"")

    # 显示收集统计
    print(f"\n📊 数据收集完成统计:")
    print(f"  总条目数: {len(all_entries)}")
    print(f"  数据文件: {len(saved_files)} 个分类文件")
    print(f"  存储位置: {data_dir}")
    print(f"  汇总文件: {summary_file}")

    print("\n🎉 知识库数据收集和导入完成！")
    return 0

if __name__ == "__main__":
    sys.exit(main())
