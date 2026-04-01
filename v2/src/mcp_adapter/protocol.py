"""
MCP 协议数据结构（精简版）

对齐 MCP 常见结构:
- tools/list 返回 {name, description, inputSchema}
- tools/call 返回 {content: [{type: "text", text: "..."}], isError: bool}
"""

from dataclasses import dataclass, asdict
from typing import Dict, Any, List


@dataclass
class MCPToolDescriptor:
    """MCP 工具描述"""
    name: str
    description: str
    inputSchema: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class MCPTextContent:
    """MCP 文本内容块"""
    type: str = "text"
    text: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class MCPCallResponse:
    """MCP tools/call 响应"""
    content: List[MCPTextContent]
    isError: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "content": [item.to_dict() for item in self.content],
            "isError": self.isError,
        }
