"""MCP 工具注册表：从 YAML 加载工具定义，动态生成 function calling schema。

YAML 工具配置格式，让 Worker 按需调用 100+ 安全工具。
"""
from __future__ import annotations

import logging
import os
import threading
import time
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

# ===== 工具列表缓存（TTL 60 秒，并发去重）=====
# 缓存 _registry 的快照副本，避免频繁从 YAML 重新加载。
_tool_cache: dict[str, ToolDefinition] = {}
_tool_cache_time: float = 0.0
_TOOL_CACHE_TTL: float = float(os.environ.get("MCP_TOOL_CACHE_TTL", "60"))
_cache_lock = threading.Lock()

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
    global _registry, _tool_cache, _tool_cache_time
    _registry.clear()
    search_dir = tool_dir or _MCP_TOOL_DIR
    if not search_dir.exists():
        logger.warning("MCP 工具目录不存在: %s", search_dir)
        _tool_cache = {}
        _tool_cache_time = time.time()
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

    # 同步刷新缓存快照
    _tool_cache = dict(_registry)
    _tool_cache_time = time.time()
    logger.info("MCP 工具注册表: 加载 %d 个工具 (从 %s)", count, search_dir)
    return count


def get_tools() -> dict[str, "ToolDefinition"]:
    """获取工具表（缓存优先，TTL 60s，并发去重：同一时刻只加载一次）。

    缓存有效时直接返回快照副本，过期才重新从 YAML 加载。
    并发场景下通过 _cache_lock + double-check 保证只加载一次。
    """
    global _tool_cache, _tool_cache_time

    # 快速路径：缓存有效，直接返回
    now = time.time()
    if _tool_cache and (now - _tool_cache_time) < _TOOL_CACHE_TTL:
        return _tool_cache

    # 并发去重：获取锁后 double-check（可能在等锁期间已被其他线程加载）
    with _cache_lock:
        now = time.time()
        if _tool_cache and (now - _tool_cache_time) < _TOOL_CACHE_TTL:
            return _tool_cache

        # 缓存过期或不存在，重新从 YAML 加载
        load_tools()
        # load_tools 内部已刷新 _tool_cache，直接返回
        return _tool_cache


def get_tool(name: str) -> ToolDefinition | None:
    """按名称获取工具定义（走缓存）。"""
    return get_tools().get(name)


def list_tools() -> list[ToolDefinition]:
    """列出所有已注册工具（走缓存）。"""
    return list(get_tools().values())


def list_tool_names() -> list[str]:
    """列出所有工具名（走缓存）。"""
    return list(get_tools().keys())


def get_schemas() -> list[dict]:
    """获取所有工具的 function calling schema（用于注入 LLM，走缓存）。"""
    return [td.to_function_schema() for td in get_tools().values()]


def get_schemas_for_categories(categories: list[str] | None = None) -> list[dict]:
    """按分类过滤工具 schema。categories=None 表示全部（走缓存）。"""
    if categories is None:
        return get_schemas()
    cat_set = {c.lower() for c in categories}
    return [td.to_function_schema() for td in get_tools().values() if td.category.lower() in cat_set]


def is_loaded() -> bool:
    return len(_registry) > 0
