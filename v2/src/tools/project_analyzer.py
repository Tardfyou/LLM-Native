"""
项目分析工具 - 分析大型项目结构

提供:
- ProjectAnalyzerTool: 扫描项目结构，分析依赖
"""

import os
import re
import json
from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass, field
from pathlib import Path

from ..agent.tools import Tool, ToolResult


@dataclass
class ProjectInfo:
    """项目信息"""
    root_path: str
    source_files: List[str]
    header_files: List[str]
    languages: Set[str]
    has_compile_commands: bool
    build_system: Optional[str]
    dependencies: Dict[str, List[str]]


class ProjectAnalyzerTool(Tool):
    """项目结构分析工具"""

    # 源文件扩展名
    SOURCE_EXTENSIONS = {'.c', '.cpp', '.cc', '.cxx', '.m', '.mm'}
    HEADER_EXTENSIONS = {'.h', '.hpp', '.hxx', '.hh'}

    # 构建系统标识
    BUILD_SYSTEMS = {
        'CMakeLists.txt': 'cmake',
        'Makefile': 'make',
        'configure.ac': 'autotools',
        'meson.build': 'meson',
        'BUILD': 'bazel',
        'WORKSPACE': 'bazel',
        'package.json': 'npm',
        'requirements.txt': 'python'
    }

    # 排除目录
    DEFAULT_EXCLUDES = {
        'node_modules', '.git', '.svn', '__pycache__',
        'build', 'dist', 'out', 'bin', 'obj',
        '.cache', 'venv', 'env', '.venv'
    }

    @property
    def name(self) -> str:
        return "analyze_project"

    @property
    def description(self) -> str:
        return """分析项目结构，支持大型开源项目。

功能:
- 扫描目录结构，识别源文件和头文件
- 分析头文件依赖关系
- 识别构建系统
- 查找或生成compile_commands.json
- 识别模块边界

对于大型项目，可以帮助理解项目结构，生成更精确的检测器。"""

    @property
    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "project_path": {
                    "type": "string",
                    "description": "项目根目录路径"
                },
                "max_depth": {
                    "type": "integer",
                    "default": 10,
                    "description": "最大扫描深度"
                },
                "exclude_patterns": {
                    "type": "array",
                    "items": {"type": "string"},
                    "default": [],
                    "description": "排除的目录模式"
                },
                "generate_compile_commands": {
                    "type": "boolean",
                    "default": False,
                    "description": "是否生成compile_commands.json"
                }
            },
            "required": ["project_path"]
        }

    def execute(
        self,
        project_path: str,
        max_depth: int = 10,
        exclude_patterns: List[str] = None,
        generate_compile_commands: bool = False
    ) -> ToolResult:
        """
        执行项目分析

        Args:
            project_path: 项目路径
            max_depth: 最大深度
            exclude_patterns: 排除模式
            generate_compile_commands: 是否生成compile_commands.json

        Returns:
            ToolResult
        """
        try:
            path = Path(project_path)
            if not path.exists():
                return ToolResult(
                    success=False,
                    output="",
                    error=f"项目路径不存在: {project_path}"
                )

            if not path.is_dir():
                return ToolResult(
                    success=False,
                    output="",
                    error=f"路径不是目录: {project_path}"
                )

            # 合并排除模式
            excludes = self.DEFAULT_EXCLUDES | set(exclude_patterns or [])

            # 扫描项目
            project_info = self._scan_project(path, max_depth, excludes)

            # 分析依赖
            dependencies = self._analyze_dependencies(project_info)

            # 查找compile_commands.json
            compile_commands_path = self._find_compile_commands(path)
            project_info.has_compile_commands = compile_commands_path is not None

            # 构建结果
            result = {
                "root_path": str(path.absolute()),
                "source_files": project_info.source_files,
                "header_files": project_info.header_files,
                "source_count": len(project_info.source_files),
                "header_count": len(project_info.header_files),
                "languages": list(project_info.languages),
                "build_system": project_info.build_system,
                "has_compile_commands": project_info.has_compile_commands,
                "compile_commands_path": str(compile_commands_path) if compile_commands_path else None,
                "dependencies": dependencies,
                "modules": self._identify_modules(project_info)
            }

            # 生成compile_commands.json
            if generate_compile_commands and not compile_commands_path:
                generated_path = self._generate_compile_commands(path, project_info)
                result["generated_compile_commands"] = str(generated_path) if generated_path else None

            # 格式化输出
            output = self._format_result(result)

            return ToolResult(
                success=True,
                output=output,
                metadata=result
            )

        except Exception as e:
            return ToolResult(
                success=False,
                output="",
                error=f"项目分析失败: {str(e)}"
            )

    def _scan_project(
        self,
        root: Path,
        max_depth: int,
        excludes: Set[str]
    ) -> ProjectInfo:
        """扫描项目目录"""
        source_files = []
        header_files = []
        languages = set()
        build_system = None

        for dirpath, dirnames, filenames in os.walk(root):
            # 检查深度
            rel_path = os.path.relpath(dirpath, root)
            depth = rel_path.count(os.sep) if rel_path != '.' else 0
            if depth >= max_depth:
                dirnames.clear()
                continue

            # 过滤排除目录
            dirnames[:] = [d for d in dirnames if d not in excludes and not d.startswith('.')]

            # 检查构建系统
            for filename in filenames:
                if filename in self.BUILD_SYSTEMS and build_system is None:
                    build_system = self.BUILD_SYSTEMS[filename]

            # 收集源文件和头文件
            for filename in filenames:
                ext = os.path.splitext(filename)[1].lower()

                if ext in self.SOURCE_EXTENSIONS:
                    full_path = os.path.join(dirpath, filename)
                    rel_file = os.path.relpath(full_path, root)
                    source_files.append(rel_file)

                    # 检测语言
                    if ext in {'.c'}:
                        languages.add('C')
                    elif ext in {'.cpp', '.cc', '.cxx'}:
                        languages.add('C++')
                    elif ext in {'.m'}:
                        languages.add('Objective-C')
                    elif ext in {'.mm'}:
                        languages.add('Objective-C++')

                elif ext in self.HEADER_EXTENSIONS:
                    full_path = os.path.join(dirpath, filename)
                    rel_file = os.path.relpath(full_path, root)
                    header_files.append(rel_file)

        return ProjectInfo(
            root_path=str(root),
            source_files=source_files,
            header_files=header_files,
            languages=languages,
            has_compile_commands=False,
            build_system=build_system,
            dependencies={}
        )

    def _analyze_dependencies(self, project_info: ProjectInfo) -> Dict[str, List[str]]:
        """分析头文件依赖"""
        dependencies = {}

        for source_file in project_info.source_files:
            includes = self._extract_includes(
                os.path.join(project_info.root_path, source_file)
            )
            dependencies[source_file] = includes

        return dependencies

    def _extract_includes(self, file_path: str) -> List[str]:
        """提取文件中的include"""
        includes = []

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            # 匹配 #include "xxx" 和 #include <xxx>
            pattern = re.compile(r'#include\s*[<"]([^>"]+)[>"]')
            matches = pattern.findall(content)
            includes = list(set(matches))

        except Exception:
            pass

        return includes

    def _find_compile_commands(self, root: Path) -> Optional[Path]:
        """查找compile_commands.json"""
        possible_paths = [
            root / 'compile_commands.json',
            root / '.patchweaver_env' / 'compile_commands.json',
            root / 'build' / 'compile_commands.json',
            root / 'cmake-build-debug' / 'compile_commands.json',
            root / 'cmake-build-release' / 'compile_commands.json',
            root / 'out' / 'compile_commands.json',
        ]

        for path in possible_paths:
            if path.exists():
                return path

        return None

    def _identify_modules(self, project_info: ProjectInfo) -> List[Dict[str, Any]]:
        """识别模块边界"""
        modules = {}

        for source_file in project_info.source_files:
            # 使用目录作为模块
            parts = source_file.split(os.sep)
            if len(parts) > 1:
                module_name = parts[0]
            else:
                module_name = 'root'

            if module_name not in modules:
                modules[module_name] = {
                    "name": module_name,
                    "source_files": [],
                    "header_files": []
                }

            modules[module_name]["source_files"].append(source_file)

        # 关联头文件
        for header_file in project_info.header_files:
            parts = header_file.split(os.sep)
            if len(parts) > 1:
                module_name = parts[0]
            else:
                module_name = 'root'

            if module_name in modules:
                modules[module_name]["header_files"].append(header_file)

        return list(modules.values())

    def _generate_compile_commands(
        self,
        root: Path,
        project_info: ProjectInfo
    ) -> Optional[Path]:
        """生成简单的compile_commands.json"""
        compile_commands = []

        for source_file in project_info.source_files:
            entry = {
                "directory": str(root.absolute()),
                "command": f"/usr/bin/gcc -c {source_file}",
                "file": source_file
            }
            compile_commands.append(entry)

        if compile_commands:
            output_path = root / 'compile_commands.json'
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(compile_commands, f, indent=2)
            return output_path

        return None

    def _format_result(self, result: Dict[str, Any]) -> str:
        """格式化结果"""
        lines = [
            "📂 项目分析结果",
            "=" * 50,
            "",
            f"📁 根目录: {result['root_path']}",
            f"🔧 构建系统: {result['build_system'] or '未识别'}",
            f"📝 语言: {', '.join(result['languages']) or '未知'}",
            "",
            f"📄 源文件: {result['source_count']}个",
            f"📑 头文件: {result['header_count']}个",
            f"📋 compile_commands.json: {'✅ 存在' if result['has_compile_commands'] else '❌ 不存在'}",
            ""
        ]

        # 显示模块
        if result['modules']:
            lines.append("📦 模块:")
            for module in result['modules'][:5]:
                lines.append(f"  - {module['name']}: {len(module['source_files'])}个源文件")

            if len(result['modules']) > 5:
                lines.append(f"  ... 还有 {len(result['modules']) - 5}个模块")

        lines.append("")

        # 显示主要依赖
        if result['dependencies']:
            lines.append("🔗 主要依赖 (前10个):")
            deps_count = {}
            for includes in result['dependencies'].values():
                for inc in includes:
                    deps_count[inc] = deps_count.get(inc, 0) + 1

            sorted_deps = sorted(deps_count.items(), key=lambda x: -x[1])[:10]
            for dep, count in sorted_deps:
                lines.append(f"  - {dep}: {count}次引用")

        return "\n".join(lines)
