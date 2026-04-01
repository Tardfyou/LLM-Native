"""
多文件操作工具 - 批量文件操作

提供:
- MultiFileOpsTool: 批量读写文件
"""

import os
import json
from typing import Dict, Any, List, Optional
from pathlib import Path

from ..agent.tools import Tool, ToolResult


class MultiFileOpsTool(Tool):
    """多文件操作工具"""

    @property
    def name(self) -> str:
        return "multi_file_ops"

    @property
    def description(self) -> str:
        return """批量文件操作，支持多文件读写。

操作类型:
- read_multiple: 批量读取多个文件
- write_multiple: 批量写入多个文件
- list_dir: 列出目录内容
- create_dir: 创建目录

适用于需要同时处理多个文件的场景，如项目级检测器生成。"""

    @property
    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "operation": {
                    "type": "string",
                    "enum": ["read_multiple", "write_multiple", "list_dir", "create_dir"],
                    "description": "操作类型"
                },
                "files": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "path": {"type": "string"},
                            "content": {"type": "string"}
                        },
                        "required": ["path"]
                    },
                    "description": "文件列表，read时只需要path，write时需要path和content"
                },
                "directory": {
                    "type": "string",
                    "description": "目录路径（用于list_dir和create_dir）"
                },
                "recursive": {
                    "type": "boolean",
                    "default": False,
                    "description": "是否递归（用于list_dir）"
                }
            },
            "required": ["operation"]
        }

    def execute(
        self,
        operation: str,
        files: List[Dict[str, str]] = None,
        directory: str = None,
        recursive: bool = False
    ) -> ToolResult:
        """
        执行操作

        Args:
            operation: 操作类型
            files: 文件列表
            directory: 目录路径
            recursive: 是否递归

        Returns:
            ToolResult
        """
        try:
            if operation == "read_multiple":
                return self._read_multiple(files or [])
            elif operation == "write_multiple":
                return self._write_multiple(files or [])
            elif operation == "list_dir":
                return self._list_dir(directory, recursive)
            elif operation == "create_dir":
                return self._create_dir(directory)
            else:
                return ToolResult(
                    success=False,
                    output="",
                    error=f"未知操作: {operation}"
                )

        except Exception as e:
            return ToolResult(
                success=False,
                output="",
                error=f"操作失败: {str(e)}"
            )

    def _read_multiple(self, files: List[Dict[str, str]]) -> ToolResult:
        """批量读取文件"""
        results = []
        success_count = 0
        error_count = 0

        for file_info in files:
            path = file_info.get("path")
            if not path:
                continue

            try:
                if not os.path.exists(path):
                    results.append({
                        "path": path,
                        "success": False,
                        "error": "文件不存在"
                    })
                    error_count += 1
                    continue

                with open(path, 'r', encoding='utf-8') as f:
                    content = f.read()

                results.append({
                    "path": path,
                    "success": True,
                    "content": content,
                    "length": len(content)
                })
                success_count += 1

            except Exception as e:
                results.append({
                    "path": path,
                    "success": False,
                    "error": str(e)
                })
                error_count += 1

        # 格式化输出
        output_lines = [
            f"📄 批量读取完成: 成功 {success_count}个, 失败 {error_count}个",
            ""
        ]

        for r in results:
            if r["success"]:
                output_lines.append(f"✅ {r['path']}: {r['length']}字符")
            else:
                output_lines.append(f"❌ {r['path']}: {r['error']}")

        return ToolResult(
            success=error_count == 0,
            output="\n".join(output_lines),
            metadata={
                "results": results,
                "success_count": success_count,
                "error_count": error_count
            }
        )

    def _write_multiple(self, files: List[Dict[str, str]]) -> ToolResult:
        """批量写入文件"""
        results = []
        success_count = 0
        error_count = 0

        for file_info in files:
            path = file_info.get("path")
            content = file_info.get("content", "")

            if not path:
                continue

            try:
                # 确保目录存在
                dir_path = os.path.dirname(path)
                if dir_path and not os.path.exists(dir_path):
                    os.makedirs(dir_path, exist_ok=True)

                with open(path, 'w', encoding='utf-8') as f:
                    f.write(content)

                results.append({
                    "path": path,
                    "success": True,
                    "length": len(content)
                })
                success_count += 1

            except Exception as e:
                results.append({
                    "path": path,
                    "success": False,
                    "error": str(e)
                })
                error_count += 1

        # 格式化输出
        output_lines = [
            f"📝 批量写入完成: 成功 {success_count}个, 失败 {error_count}个",
            ""
        ]

        for r in results:
            if r["success"]:
                output_lines.append(f"✅ {r['path']}: {r['length']}字符")
            else:
                output_lines.append(f"❌ {r['path']}: {r['error']}")

        return ToolResult(
            success=error_count == 0,
            output="\n".join(output_lines),
            metadata={
                "results": results,
                "success_count": success_count,
                "error_count": error_count
            }
        )

    def _list_dir(self, directory: str, recursive: bool) -> ToolResult:
        """列出目录内容"""
        if not directory:
            return ToolResult(
                success=False,
                output="",
                error="未指定目录"
            )

        if not os.path.exists(directory):
            return ToolResult(
                success=False,
                output="",
                error=f"目录不存在: {directory}"
            )

        if not os.path.isdir(directory):
            return ToolResult(
                success=False,
                output="",
                error=f"路径不是目录: {directory}"
            )

        items = []

        if recursive:
            for root, dirs, files in os.walk(directory):
                # 过滤隐藏目录
                dirs[:] = [d for d in dirs if not d.startswith('.')]

                for f in files:
                    full_path = os.path.join(root, f)
                    rel_path = os.path.relpath(full_path, directory)
                    items.append({
                        "path": rel_path,
                        "type": "file",
                        "size": os.path.getsize(full_path)
                    })

                for d in dirs:
                    full_path = os.path.join(root, d)
                    rel_path = os.path.relpath(full_path, directory)
                    items.append({
                        "path": rel_path,
                        "type": "directory"
                    })
        else:
            for item in os.listdir(directory):
                full_path = os.path.join(directory, item)
                if os.path.isfile(full_path):
                    items.append({
                        "path": item,
                        "type": "file",
                        "size": os.path.getsize(full_path)
                    })
                else:
                    items.append({
                        "path": item,
                        "type": "directory"
                    })

        # 排序
        items.sort(key=lambda x: (x["type"] == "file", x["path"]))

        # 格式化输出
        output_lines = [
            f"📂 目录内容: {directory}",
            f"{'递归' if recursive else '非递归'}, 共 {len(items)}项",
            ""
        ]

        for item in items[:50]:  # 最多显示50项
            if item["type"] == "directory":
                output_lines.append(f"📁 {item['path']}/")
            else:
                size = item.get("size", 0)
                size_str = self._format_size(size)
                output_lines.append(f"📄 {item['path']} ({size_str})")

        if len(items) > 50:
            output_lines.append(f"... 还有 {len(items) - 50}项")

        return ToolResult(
            success=True,
            output="\n".join(output_lines),
            metadata={
                "directory": directory,
                "recursive": recursive,
                "items": items,
                "total_count": len(items)
            }
        )

    def _create_dir(self, directory: str) -> ToolResult:
        """创建目录"""
        if not directory:
            return ToolResult(
                success=False,
                output="",
                error="未指定目录"
            )

        try:
            os.makedirs(directory, exist_ok=True)
            return ToolResult(
                success=True,
                output=f"✅ 目录已创建: {directory}",
                metadata={"directory": directory}
            )
        except Exception as e:
            return ToolResult(
                success=False,
                output="",
                error=f"创建目录失败: {str(e)}"
            )

    def _format_size(self, size: int) -> str:
        """格式化文件大小"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f"{size:.1f}{unit}"
            size /= 1024
        return f"{size:.1f}TB"
