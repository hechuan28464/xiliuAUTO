"""MCP 工具客户端：执行 YAML 定义的命令行安全工具。

Worker 通过 function calling 调用 → 本模块执行命令 → 返回截断/落盘输出。
2C4G 优化：按需执行，不常驻进程，并发限制 + 熔断。
"""
from __future__ import annotations

import asyncio
import logging
import os
import subprocess
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Optional

from app.config import worker_config
from app.tools.guard import CommandBlocked, check_command
from app.tools.mcp import mcp_registry

logger = logging.getLogger("autohunter.mcp_client")

# ===== 同步并发信号量（用于 execute_mcp_tool 同步路径）=====
_mcp_semaphore = threading.Semaphore(int(os.environ.get("MCP_MAX_CONCURRENT", "2")))

# ===== 异步并发信号量（用于 execute_mcp_tool_async 异步路径）=====
# 全局信号量：限制总并发 16
_global_async_sem: asyncio.Semaphore | None = None
# 每工具信号量：限制单工具并发 2
_per_tool_async_sems: dict[str, asyncio.Semaphore] = {}
_async_sem_lock = threading.Lock()

# ===== 超长输出落盘配置 =====
# 超过此阈值（字节）的输出完整落盘到文件，内存侧只保留提示
_SPILL_THRESHOLD = int(os.environ.get("MCP_SPILL_THRESHOLD", "12000"))
_SPILL_DIR = Path(os.environ.get("MCP_SPILL_DIR", "/work/tool_outputs"))


def _get_global_async_sem() -> asyncio.Semaphore:
    """懒初始化全局异步信号量。"""
    global _global_async_sem
    if _global_async_sem is None:
        _global_async_sem = asyncio.Semaphore(int(os.environ.get("MCP_GLOBAL_CONCURRENCY", "16")))
    return _global_async_sem


def _get_tool_async_sem(tool_name: str) -> asyncio.Semaphore:
    """懒初始化每工具异步信号量。"""
    with _async_sem_lock:
        sem = _per_tool_async_sems.get(tool_name)
        if sem is None:
            sem = asyncio.Semaphore(int(os.environ.get("MCP_PER_TOOL_CONCURRENCY", "2")))
            _per_tool_async_sems[tool_name] = sem
        return sem


class _CircuitBreaker:
    """每工具熔断器：连续失败 3 次触发熔断，cooldown 60 秒。

    熔断期间直接拒绝调用，避免对持续失败的工具无意义重试。
    """

    _FAILURE_THRESHOLD = int(os.environ.get("MCP_CB_FAILURE_THRESHOLD", "3"))
    _COOLDOWN = float(os.environ.get("MCP_CB_COOLDOWN", "60"))

    def __init__(self):
        # tool_name -> {"failures": int, "cooldown_until": float}
        self._states: dict[str, dict] = {}
        self._lock = threading.Lock()

    def is_tripped(self, tool_name: str) -> bool:
        """是否处于熔断状态。"""
        with self._lock:
            state = self._states.get(tool_name)
            if not state:
                return False
            if state["cooldown_until"] > time.time():
                return True
            # cooldown 已过，重置计数
            if state["cooldown_until"] > 0:
                state["failures"] = 0
                state["cooldown_until"] = 0.0
            return False

    def record_failure(self, tool_name: str) -> None:
        """记录一次失败，达到阈值则熔断。"""
        with self._lock:
            state = self._states.setdefault(tool_name, {"failures": 0, "cooldown_until": 0.0})
            state["failures"] += 1
            if state["failures"] >= self._FAILURE_THRESHOLD:
                state["cooldown_until"] = time.time() + self._COOLDOWN
                logger.warning(
                    "工具 %s 连续失败 %d 次，触发熔断，冷却 %.0fs",
                    tool_name, state["failures"], self._COOLDOWN,
                )

    def record_success(self, tool_name: str) -> None:
        """记录一次成功，重置失败计数。"""
        with self._lock:
            state = self._states.get(tool_name)
            if state:
                state["failures"] = 0
                state["cooldown_until"] = 0.0

    def cooldown_remaining(self, tool_name: str) -> float:
        """返回剩余冷却时间（秒），未熔断返回 0。"""
        with self._lock:
            state = self._states.get(tool_name)
            if not state:
                return 0.0
            remaining = state["cooldown_until"] - time.time()
            return max(0.0, remaining)


# 全局熔断器单例
_breaker = _CircuitBreaker()


def _spill_output(text: str, spill_id: str, limit: int = 0) -> str:
    """超长输出处理：截断或落盘。

    - 不超过 limit：原样返回
    - 超过 limit 但不超过 _SPILL_THRESHOLD：截断（head + tail）
    - 超过 _SPILL_THRESHOLD：完整落盘到 /work/tool_outputs/{spill_id}.txt，
      内存侧只保留 ``<persisted-output>`` 提示 + 少量预览
    """
    if limit <= 0:
        limit = worker_config.output_truncate
        if worker_config.llm_tool_output_truncate > 0:
            limit = min(limit, worker_config.llm_tool_output_truncate)

    text_len = len(text)

    # 不需要截断
    if text_len <= limit:
        return text

    # 需要截断但未到落盘阈值
    if text_len <= _SPILL_THRESHOLD:
        head = text[: limit // 2]
        tail = text[-limit // 4 :]
        return f"{head}\n\n...[输出过长已截断]...\n\n{tail}"

    # 超过落盘阈值：完整落盘
    try:
        _SPILL_DIR.mkdir(parents=True, exist_ok=True)
        spill_path = _SPILL_DIR / f"{spill_id}.txt"
        spill_path.write_text(text, encoding="utf-8")
        size_kb = text_len // 1024
        # 内存侧保留少量预览 + 落盘提示，模型需要时可读取全文
        preview = text[: min(limit, 2048)]
        return (
            f"{preview}\n\n"
            f"...[输出 {size_kb}KB 已完整落盘]...\n"
            f'<persisted-output path="{spill_path}">完整输出已持久化，可读取此路径获取全文</persisted-output>'
        )
    except Exception as e:
        logger.warning("输出落盘失败 %s: %s，降级为截断", spill_id, e)
        head = text[: limit // 2]
        tail = text[-limit // 4 :]
        return f"{head}\n\n...[输出过长已截断]...\n\n{tail}"


def _execute_raw(
    tool_name: str,
    args: dict[str, Any],
    work_dir: str | None,
    timeout: int | None,
    spill_id: str | None = None,
) -> dict[str, Any]:
    """核心执行逻辑（无信号量、无熔断，由调用方包裹）。

    构建 → guard.check_command → subprocess.run → _spill_output
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

    # 生成落盘 ID
    if spill_id is None:
        spill_id = f"{tool_name}_{uuid.uuid4().hex[:12]}"

    # 执行
    start = time.time()
    stdout_data = ""
    stderr_data = ""
    returncode = -1
    error_msg: Optional[str] = None

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
        "stdout": _spill_output(stdout_data, spill_id),
        "stderr": _spill_output(stderr_data, f"{spill_id}_err", 1024),
        "duration": duration,
        "error": error_msg,
        "is_high_risk": is_high_risk,
    }


def execute_mcp_tool(
    tool_name: str,
    args: dict[str, Any],
    work_dir: str | None = None,
    timeout: int | None = None,
) -> dict[str, Any]:
    """同步执行一个 MCP 工具（带 threading 信号量 + 熔断）。

    返回:
        {
            "tool": str,
            "command": str,
            "returncode": int,
            "stdout": str (截断/落盘提示),
            "stderr": str (截断/落盘提示),
            "duration": float,
            "error": str | None,
            "is_high_risk": bool,
        }
    """
    # 熔断检查
    if _breaker.is_tripped(tool_name):
        remaining = _breaker.cooldown_remaining(tool_name)
        return {
            "tool": tool_name,
            "command": "",
            "returncode": -1,
            "stdout": "",
            "stderr": "",
            "duration": 0.0,
            "error": f"工具 '{tool_name}' 熔断中，冷却剩余 {remaining:.0f}s",
            "is_high_risk": False,
        }

    # 执行（带同步并发限制）
    with _mcp_semaphore:
        result = _execute_raw(tool_name, args, work_dir, timeout)

    # 熔断器反馈
    if result.get("error"):
        _breaker.record_failure(tool_name)
    else:
        _breaker.record_success(tool_name)

    return result


async def execute_mcp_tool_async(
    tool_name: str,
    args: dict[str, Any],
    work_dir: str | None = None,
    timeout: int | None = None,
    spill_id: str | None = None,
) -> dict[str, Any]:
    """异步执行一个 MCP 工具（带 asyncio 信号量 + 熔断）。

    与 execute_mcp_tool 功能一致，但使用 asyncio 信号量限流：
    - 全局信号量限制总并发 16
    - 每工具信号量限制单工具并发 2
    """
    # 熔断检查
    if _breaker.is_tripped(tool_name):
        remaining = _breaker.cooldown_remaining(tool_name)
        return {
            "tool": tool_name,
            "command": "",
            "returncode": -1,
            "stdout": "",
            "stderr": "",
            "duration": 0.0,
            "error": f"工具 '{tool_name}' 熔断中，冷却剩余 {remaining:.0f}s",
            "is_high_risk": False,
        }

    # 异步信号量限流
    global_sem = _get_global_async_sem()
    tool_sem = _get_tool_async_sem(tool_name)

    async with global_sem:
        async with tool_sem:
            # 在线程池中执行同步的 _execute_raw
            result = await asyncio.to_thread(
                _execute_raw, tool_name, args, work_dir, timeout, spill_id,
            )

    # 熔断器反馈
    if result.get("error"):
        _breaker.record_failure(tool_name)
    else:
        _breaker.record_success(tool_name)

    return result


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
