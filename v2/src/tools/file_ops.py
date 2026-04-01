"""
文件操作工具

提供:
- ReadFileTool: 读取文件
- WriteFileTool: 写入文件（支持工作目录）
"""



import os
from typing import Dict, Any

from ..agent.tools import Tool, ToolResult


class ReadFileTool(Tool):
    """读取文件工具"""

    @property
    def name(self) -> str:
        return "read_file"

    @property
    def description(self) -> str:
        return """读取指定路径的文件内容。
适用于读取补丁文件、源代码文件、配置文件等。
返回文件的完整文本内容。"""

    @property
    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "文件路径 (相对或绝对路径)"
                }
            },
            "required": ["path"]
        }

    def execute(self, path: str) -> ToolResult:
        """执行读取文件"""
        try:
            # 支持相对路径
            if not os.path.isabs(path):
                # 尝试从当前工作目录读取
                pass

            if not os.path.exists(path):
                return ToolResult(
                    success=False,
                    output="",
                    error=f"文件不存在: {path}"
                )

            with open(path, 'r', encoding='utf-8') as f:
                content = f.read()

            return ToolResult(
                success=True,
                output=content,
                metadata={
                    "path": path,
                    "length": len(content),
                    "lines": content.count('\n') + 1
                }
            )

        except PermissionError:
            return ToolResult(
                success=False,
                output="",
                error=f"没有权限读取文件: {path}"
            )
        except UnicodeDecodeError:
            return ToolResult(
                success=False,
                output="",
                error=f"文件编码错误，无法以 UTF-8 读取: {path}"
            )
        except Exception as e:
            return ToolResult(
                success=False,
                output="",
                error=f"读取文件失败: {str(e)}"
            )


class WriteFileTool(Tool):
    """写入文件工具（支持工作目录和版本保存）"""

    def __init__(self, work_dir: str = None, save_versions: bool = True):
        """
        初始化

        Args:
            work_dir: 工作目录，如果提供，相对路径会相对于此目录
            save_versions: 是否保存中间版本
        """
        self.work_dir = work_dir
        self.save_versions = save_versions
        self._version_count = 0

    @property
    def name(self) -> str:
        return "write_file"

    @property
    def description(self) -> str:
        return """将内容写入指定路径的文件。
用于保存生成的检测器代码、中间结果等。
如果目录不存在会自动创建。
支持保存中间版本用于调试。"""

    @property
    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "文件路径 (相对或绝对路径)"
                },
                "content": {
                    "type": "string",
                    "description": "要写入的文件内容"
                },
                "is_final": {
                    "type": "boolean",
                    "default": False,
                    "description": "是否是最终版本（如果是，不保存版本号）"
                }
            },
            "required": ["path", "content"]
        }

    def set_work_dir(self, work_dir: str):
        """设置工作目录"""
        self.work_dir = work_dir

    def execute(self, path: str, content: str, is_final: bool = False) -> ToolResult:
        """执行写入文件"""
        try:
            # 处理路径
            if self.work_dir and not os.path.isabs(path):
                work_dir_abs = os.path.abspath(self.work_dir)
                path_norm = path.replace("\\", "/")

                # 如果 path 已经包含 work_dir 前缀，避免重复拼接
                if path_norm.startswith(work_dir_abs.replace("\\", "/")):
                    full_path = path
                elif path_norm.startswith("./") and os.path.abspath(path).startswith(work_dir_abs):
                    full_path = os.path.abspath(path)
                else:
                    full_path = os.path.join(self.work_dir, path)
            else:
                full_path = path

            # 确保目录存在
            dir_path = os.path.dirname(full_path)
            if dir_path and not os.path.exists(dir_path):
                os.makedirs(dir_path, exist_ok=True)

            # 保存中间版本
            version_path = None
            if self.save_versions and not is_final:
                version_path = self._save_version(full_path, content)

            # 写入主文件
            with open(full_path, 'w', encoding='utf-8') as f:
                f.write(content)

            output = f"文件已保存: {full_path} ({len(content)} 字符)"
            if version_path:
                output += f"\n版本备份: {version_path}"

            return ToolResult(
                success=True,
                output=output,
                metadata={
                    "path": full_path,
                    "length": len(content),
                    "lines": content.count('\n') + 1,
                    "version_path": version_path
                }
            )

        except PermissionError:
            return ToolResult(
                success=False,
                output="",
                error=f"没有权限写入文件: {path}"
            )
        except Exception as e:
            return ToolResult(
                success=False,
                output="",
                error=f"写入文件失败: {str(e)}"
            )

    def _save_version(self, path: str, content: str) -> str:
        """保存版本备份"""
        self._version_count += 1

        # 创建版本目录
        dir_path = os.path.dirname(path)
        versions_dir = os.path.join(dir_path, "versions")
        os.makedirs(versions_dir, exist_ok=True)

        # 生成版本文件名
        base_name = os.path.basename(path)
        name, ext = os.path.splitext(base_name)
        version_name = f"{name}_v{self._version_count:03d}{ext}"
        version_path = os.path.join(versions_dir, version_name)

        # 保存
        with open(version_path, 'w', encoding='utf-8') as f:
            f.write(content)

        return version_path
