"""
MCP 工具服务

将现有 ToolRegistry / Tool 对象标准化为 MCP 风格接口:
- list_tools()
- call_tool(name, arguments)
"""

import json
from typing import Dict, Any, List

from ..agent.tools import ToolRegistry, Tool, ToolResult
from .protocol import MCPToolDescriptor, MCPCallResponse, MCPTextContent


class MCPToolService:
    """MCP 风格工具服务（进程内）"""

    def __init__(self, tool_registry: ToolRegistry):
        self.tool_registry = tool_registry

    def list_tools(self) -> List[Dict[str, Any]]:
        """返回 MCP tools/list 格式"""
        descriptors: List[MCPToolDescriptor] = []
        for tool in self.tool_registry.get_all_tools():
            descriptors.append(
                MCPToolDescriptor(
                    name=tool.name,
                    description=tool.description,
                    inputSchema=tool.parameters_schema,
                )
            )
        return [item.to_dict() for item in descriptors]

    def call_tool(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """返回 MCP tools/call 格式"""
        tool = self.tool_registry.get(name)
        if not tool:
            resp = MCPCallResponse(
                content=[MCPTextContent(text=f"未知工具: {name}")],
                isError=True,
            )
            return resp.to_dict()

        try:
            result: ToolResult = tool.execute(**(arguments or {}))
            payload = {
                "success": result.success,
                "output": result.output,
                "error": result.error,
                "metadata": result.metadata,
            }
            text = json.dumps(payload, ensure_ascii=False, indent=2)
            resp = MCPCallResponse(
                content=[MCPTextContent(text=text)],
                isError=not result.success,
            )
            return resp.to_dict()
        except Exception as e:
            resp = MCPCallResponse(
                content=[MCPTextContent(text=f"工具调用异常: {e}")],
                isError=True,
            )
            return resp.to_dict()

    def export_manifest(self) -> Dict[str, Any]:
        """导出工具清单，便于外部 MCP 客户端/网关接入"""
        return {
            "version": "1.0",
            "protocol": "mcp-tools",
            "tools": self.list_tools(),
        }
