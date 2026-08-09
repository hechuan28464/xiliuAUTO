"""MCP 工具客户端：执行 YAML 定义的命令行安全工具。

Worker 通过 function calling 调用 → 本模块执行命令 → 返回截断输出。
2C4G 优化：按需执行，不常驻进程，并发限制。
"""
from __future__ import annotations

import logging
import os
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Optional

from app.config import worker_config
from app.tools.guard import CommandBlocked, check_command
from app.tools.mcp import mcp_registry

logger = logging.getLogger("autohunter.mcp_client")

# 并发信号量
_mcp_semaphore = threading.Semaphore(int(os.environ.get("MCP_MAX_CONCURRENT", "2")))


def _truncate(text: str, limit: int = 0) -> str:
    """截断输出。"""
    if limit <= 0:
        limit = worker_config.output_truncate
        if worker_config.llm_tool_output_truncate > 0:
            limit = min(limit, worker_config.llm_tool_output_truncate)
    if len(text) <= limit:
        return text
    head = text[: limit // 2]
    tail = text[-limit // 4 :]
    return f"{head}\n\n...[输出过长已截断]...\n\n{tail}"


def execute_mcp_tool(
    tool_name: str,
    args: dict[str, Any],
    work_dir: str | None = None,
    timeout: int | None = None,
) -> dict[str, Any]:
    """执行一个 MCP 工具，返回结构化结果。

    返回:
        {
            "tool": str,
            "command": str,
            "returncode": int,
            "stdout": str (截断),
            "stderr": str (截断),
            "duration": float,
            "error": str | None,
            "is_high_risk": bool,
        }
    """
    td = mcp_registry.get_tool(tool_name)
    if td is None:
        return {
            "tool": tool_name,
            "command": "",
            "returncode": -1,
            "stdout": "",
            "stderr": "",
            "duration": 0.0,
            "error": f"工具 '{tool_name}' 未注册",
            "is_high_risk": False,
        }

    # 构建命令
    cmd, is_high_risk = td.build_command(args)
    if not cmd:
        return {
            "tool": tool_name,
            "command": "",
            "returncode": -1,
            "stdout": "",
            "stderr": "",
            "duration": 0.0,
            "error": "命令构建失败（缺少必填参数？）",
            "is_high_risk": False,
        }

    # 安全检查：走 AutoHunter 现有 guard
    try:
        check_command(cmd)
    except CommandBlocked as e:
        return {
            "tool": tool_name,
            "command": cmd,
            "returncode": -1,
            "stdout": "",
            "stderr": str(e),
            "duration": 0.0,
            "error": f"命令被安全策略拦截: {e}",
            "is_high_risk": is_high_risk,
        }

    # 超时
    cmd_timeout = min(timeout or td.timeout, worker_config.shell_timeout_max)

    # 执行（带并发限制）
    start = time.time()
    stdout_data = ""
    stderr_data = ""
    returncode = -1
    error_msg: Optional[str] = None

    with _mcp_semaphore:
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=cmd_timeout,
                cwd=work_dir or worker_config.work_root,
                env={**os.environ},
            )
            stdout_data = result.stdout or ""
            stderr_data = result.stderr or ""
            returncode = result.returncode
        except subprocess.TimeoutExpired:
            error_msg = f"工具执行超时 ({cmd_timeout}s)"
            stderr_data = error_msg
        except Exception as e:
            error_msg = f"工具执行异常: {e}"
            stderr_data = str(e)

    duration = round(time.time() - start, 2)

    logger.info("MCP工具 %s 执行完成 rc=%d 耗时%.1fs", tool_name, returncode, duration)

    return {
        "tool": tool_name,
        "command": cmd,
        "returncode": returncode,
        "stdout": _truncate(stdout_data),
        "stderr": _truncate(stderr_data, 1024),
        "duration": duration,
        "error": error_msg,
        "is_high_risk": is_high_risk,
    }


def format_tool_result(result: dict[str, Any]) -> str:
    """把工具结果格式化为 LLM 可读的文本。"""
    parts = [f"[MCP工具: {result['tool']}]"]
    if result.get("error"):
        parts.append(f"错误: {result['error']}")

    stdout = result.get("stdout", "")
    if stdout:
        parts.append(f"输出:\n{stdout}")

    stderr = result.get("stderr", "")
    if stderr and stderr != result.get("error"):
        parts.append(f"stderr:\n{stderr}")

    parts.append(f"返回码: {result.get('returncode', -1)}, 耗时: {result.get('duration', 0)}s")
    return "\n".join(parts)


def is_high_risk_tool(tool_name: str, args: dict) -> bool:
    """预检查工具调用是否高风险（用于 HITL 审批）。"""
    td = mcp_registry.get_tool(tool_name)
    if td is None:
        return False
    _, is_high_risk = td.build_command(args)
    return is_high_risk
