"""
默认 MCP 工具服务构建器

目标:
- 不影响现有生成流程
- 复用现有工具实现
- 提供可直接调用的 MCP 标准化接口
"""

from typing import Dict, Any

from ..agent.tools import ToolRegistry
from ..utils.config import load_config
from ..tools import ToolProviderOptions, build_tool_registry

from .service import MCPToolService


def build_default_mcp_service(config_path: str = None) -> MCPToolService:
    """
    构建默认 MCP 工具服务

    注意:
    - 为了保证不影响主流程，这里独立构建 ToolRegistry
    - LSP 依赖运行时客户端，默认不注册 lsp_validate（避免初始化 clangd 失败）
    """
    if config_path:
        config = load_config(config_path)
    else:
        config = load_config("config/config.yaml")

    registry = build_tool_registry(
        config=config,
        options=ToolProviderOptions(
            analyzer="auto",
            include_lsp=False,
            silent=True,
        ),
        tool_registry=ToolRegistry(),
    )
    return MCPToolService(registry)
