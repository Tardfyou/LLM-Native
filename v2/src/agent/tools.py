"""
工具系统 - 智能体可调用的工具

提供:
- Tool 基类
- ToolRegistry 工具注册中心
- ToolResult 执行结果
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List


@dataclass
class ToolResult:
    """工具执行结果"""
    success: bool                              # 是否成功
    output: str                                # 输出内容
    error: Optional[str] = None                # 错误信息
    metadata: Dict[str, Any] = field(default_factory=dict)  # 额外元数据

    def __str__(self) -> str:
        if self.success:
            return f"[成功] {self.output[:200]}"
        else:
            return f"[失败] {self.error or self.output}"


class Tool(ABC):
    """工具基类"""

    @property
    @abstractmethod
    def name(self) -> str:
        """工具名称"""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """工具描述 (给LLM看的)"""
        pass

    @property
    @abstractmethod
    def parameters_schema(self) -> Dict[str, Any]:
        """参数 JSON Schema"""
        pass

    @abstractmethod
    def execute(self, **kwargs) -> ToolResult:
        """执行工具"""
        pass

    def to_openai_tool(self) -> Dict[str, Any]:
        """转换为 OpenAI 工具格式"""
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters_schema
            }
        }


class ToolRegistry:
    """工具注册中心"""

    def __init__(self):
        self._tools: Dict[str, Tool] = {}

    def register(self, tool: Tool):
        """注册工具"""
        self._tools[tool.name] = tool

    def unregister(self, name: str):
        """注销工具"""
        if name in self._tools:
            del self._tools[name]

    def get(self, name: str) -> Optional[Tool]:
        """获取工具"""
        return self._tools.get(name)

    def has(self, name: str) -> bool:
        """检查工具是否存在"""
        return name in self._tools

    def get_all_tools(self) -> List[Tool]:
        """获取所有工具"""
        return list(self._tools.values())

    def get_openai_tools(self) -> List[Dict[str, Any]]:
        """获取 OpenAI 格式的工具列表"""
        return [t.to_openai_tool() for t in self._tools.values()]

    def get_tool_names(self) -> List[str]:
        """获取所有工具名称"""
        return list(self._tools.keys())

    def __len__(self) -> int:
        return len(self._tools)

    def __contains__(self, name: str) -> bool:
        return name in self._tools
