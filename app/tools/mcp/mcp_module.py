"""MCP 工具模块：YAML 定义的命令行安全工具集成 + 后台执行引擎。

自研的工具配置格式，让 Worker 按需调用 100+ 安全工具。
"""
from app.tools.mcp import mcp_registry
from app.tools.mcp.client import (
    execute_mcp_tool,
    execute_mcp_tool_async,
    format_tool_result,
    is_high_risk_tool,
)
from app.tools.mcp.execution import (
    EXECUTION_META_HANDLERS,
    EXECUTION_META_SCHEMAS,
    MCPExecution,
    cancel_tool_execution,
    get_execution_engine,
    get_tool_execution,
    wait_tool_execution,
)

__all__ = [
    "mcp_registry",
    "execute_mcp_tool",
    "execute_mcp_tool_async",
    "format_tool_result",
    "is_high_risk_tool",
    "MCPExecution",
    "get_execution_engine",
    "get_tool_execution",
    "wait_tool_execution",
    "cancel_tool_execution",
    "EXECUTION_META_SCHEMAS",
    "EXECUTION_META_HANDLERS",
]
