"""MCP 工具模块：YAML 定义的命令行安全工具集成。

从 CyberStrikeAI 移植的工具配方格式，让 Worker 按需调用 100+ 安全工具。
"""
from app.tools.mcp.mcp_registry import (
    ToolDefinition,
    get_schemas,
    get_schemas_for_categories,
    get_tool,
    is_loaded,
    list_tool_names,
    list_tools,
    load_tools,
)
from app.tools.mcp.client import (
    execute_mcp_tool,
    format_tool_result,
    is_high_risk_tool,
)

__all__ = [
    "ToolDefinition",
    "load_tools",
    "get_tool",
    "list_tools",
    "list_tool_names",
    "get_schemas",
    "get_schemas_for_categories",
    "is_loaded",
    "execute_mcp_tool",
    "format_tool_result",
    "is_high_risk_tool",
]
