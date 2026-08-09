"""MCP 工具模块：YAML 定义的命令行安全工具集成。

从 CyberStrikeAI 移植的工具配方格式，让 Worker 按需调用 100+ 安全工具。
"""
from app.tools.mcp import mcp_registry
from app.tools.mcp.client import (
    execute_mcp_tool,
    format_tool_result,
    is_high_risk_tool,
)

__all__ = [
    "mcp_registry",
    "execute_mcp_tool",
    "format_tool_result",
    "is_high_risk_tool",
]
