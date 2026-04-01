"""
MCP 适配层

提供:
- MCPToolService: MCP 风格工具服务（tools/list, tools/call）
- MCPToolDescriptor: MCP 工具描述
- MCPCallResponse: MCP 调用响应
- build_default_mcp_service: 构建默认工具服务
"""

from .protocol import MCPToolDescriptor, MCPTextContent, MCPCallResponse
from .service import MCPToolService
from .default_service import build_default_mcp_service

__all__ = [
    "MCPToolDescriptor",
    "MCPTextContent",
    "MCPCallResponse",
    "MCPToolService",
    "build_default_mcp_service",
]
