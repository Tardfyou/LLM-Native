"""
Agent compatibility exports plus shared tool primitives.
"""

from .core import CheckerAgent, AgentResult, AgentState
from .tools import Tool, ToolResult, ToolRegistry

__all__ = [
    "CheckerAgent",
    "AgentResult",
    "AgentState",
    "Tool",
    "ToolResult",
    "ToolRegistry",
]
