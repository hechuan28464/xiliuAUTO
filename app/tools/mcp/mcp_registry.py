"""MCP 工具注册表：从 YAML 加载工具定义，动态生成 function calling schema。

YAML 工具配置格式，让 Worker 按需调用 100+ 安全工具。
"""
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger("autohunter.mcp_registry")

# 工具 YAML 目录
_MCP_TOOL_DIR = Path(os.environ.get("MCP_TOOL_DIR", Path(__file__).resolve().parent.parent.parent.parent / "tools" / "mcp"))

# 单工具超时
_MCP_TOOL_TIMEOUT = int(os.environ.get("MCP_TOOL_TIMEOUT", "120"))
# 最大并发工具数
_MCP_MAX_CONCURRENT = int(os.environ.get("MCP_MAX_CONCURRENT", "2"))

# 高风险命令关键词：需要 HITL 审批
_HIGH_RISK_KEYWORDS = {
    "rm -rf", "mkfs", "dd if=", "shutdown", "reboot", "halt",
    ":(){:|:&};:", "fork bomb", "chmod 777 /",
}


class ToolDefinition:
    """单个工具定义。"""

    def __init__(self, data: dict):
        self.name: str = data.get("name", "")
        self.description: str = data.get("description", "")
        self.command: str = data.get("command", "")
        self.category: str = data.get("category", "general")
        self.timeout: int = min(data.get("timeout", _MCP_TOOL_TIMEOUT), _MCP_TOOL_TIMEOUT)
        self.parameters: list[dict] = data.get("parameters", [])
        self.tags: list[str] = data.get("tags", [])
        self.enabled: bool = data.get("enabled", True)
        self._raw = data

    def to_function_schema(self) -> dict:
        """转换为 OpenAI function calling schema。"""
        properties: dict[str, Any] = {}
        required: list[str] = []
        for param in self.parameters:
            pname = param.get("name", "")
            if not pname:
                continue
            properties[pname] = {
                "type": param.get("type", "string"),
                "description": param.get("description", ""),
            }
            if param.get("enum"):
                properties[pname]["enum"] = param["enum"]
            if param.get("default") is not None:
                properties[pname]["default"] = param["default"]
            if param.get("required", False):
                required.append(pname)

        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": f"[{self.category}] {self.description}",
                "parameters": {
                    "type": "object",
                    "properties": properties,
                    "required": required,
                },
            },
        }

    def build_command(self, args: dict) -> tuple[str, bool]:
        """用参数填充命令模板，返回 (完整命令, 是否高风险)。"""
        cmd = self.command
        for param in self.parameters:
            pname = param.get("name", "")
            val = args.get(pname, param.get("default", ""))
            if val is None or val == "":
                continue
            cmd = cmd.replace("{" + pname + "}", str(val))

        is_high_risk = any(kw in cmd.lower() for kw in _HIGH_RISK_KEYWORDS)
        return cmd, is_high_risk


# 全局工具注册表
_registry: dict[str, ToolDefinition] = {}


def load_tools(tool_dir: Path | None = None) -> int:
    """从 YAML 目录加载所有工具定义，返回加载数量。"""
    global _registry
    _registry.clear()
    search_dir = tool_dir or _MCP_TOOL_DIR
    if not search_dir.exists():
        logger.warning("MCP 工具目录不存在: %s", search_dir)
        return 0

    count = 0
    for yml_file in sorted(search_dir.glob("*.yaml")) + sorted(search_dir.glob("*.yml")):
        try:
            data = yaml.safe_load(yml_file.read_text(encoding="utf-8"))
            if not data:
                continue
            # 支持单文件多工具（list）或单工具（dict）
            tools = data if isinstance(data, list) else [data]
            for item in tools:
                td = ToolDefinition(item)
                if td.name and td.enabled:
                    _registry[td.name] = td
                    count += 1
        except Exception as e:
            logger.error("加载工具定义失败 %s: %s", yml_file, e)

    logger.info("MCP 工具注册表: 加载 %d 个工具 (从 %s)", count, search_dir)
    return count


def get_tool(name: str) -> ToolDefinition | None:
    """按名称获取工具定义。"""
    return _registry.get(name)


def list_tools() -> list[ToolDefinition]:
    """列出所有已注册工具。"""
    return list(_registry.values())


def list_tool_names() -> list[str]:
    """列出所有工具名。"""
    return list(_registry.keys())


def get_schemas() -> list[dict]:
    """获取所有工具的 function calling schema（用于注入 LLM）。"""
    return [td.to_function_schema() for td in _registry.values()]


def get_schemas_for_categories(categories: list[str] | None = None) -> list[dict]:
    """按分类过滤工具 schema。categories=None 表示全部。"""
    if categories is None:
        return get_schemas()
    cat_set = {c.lower() for c in categories}
    return [td.to_function_schema() for td in _registry.values() if td.category.lower() in cat_set]


def is_loaded() -> bool:
    return len(_registry) > 0
