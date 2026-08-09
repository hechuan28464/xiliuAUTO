"""MCP 后台执行引擎：Submit/Wait/Cancel 三件套 + 执行控制元工具。

- submit：返回 execution_id，后台 asyncio.create_task 独立运行，脱离调用方 ctx
- wait：有界等待，超时返回当前状态
- cancel：取消执行

状态机：queued → running → completed/failed/cancelled/hard_timeout
内置 panic recover（try/except 包裹）+ partial output（运行中尾部预览限 64KB）。
"""
from __future__ import annotations

import asyncio
import logging
import os
import subprocess
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from app.config import worker_config
from app.tools.guard import CommandBlocked, check_command
from app.tools.mcp import mcp_registry
from app.tools.mcp.client import (
    _breaker,
    _get_global_async_sem,
    _get_tool_async_sem,
    _spill_output,
)

logger = logging.getLogger("autohunter.mcp_execution")

# partial output 尾部预览上限
_PARTIAL_PREVIEW_LIMIT = 64 * 1024  # 64KB

# 终态集合
_TERMINAL_STATES = frozenset({"completed", "failed", "cancelled", "hard_timeout"})


@dataclass
class ExecutionState:
    """单次执行的状态机。"""

    execution_id: str
    tool_name: str
    args: dict
    timeout: float
    status: str = "queued"  # queued → running → completed/failed/cancelled/hard_timeout
    created_at: float = field(default_factory=time.time)
    started_at: float | None = None
    finished_at: float | None = None
    result: dict | None = None
    error: str | None = None
    partial_output: str = ""  # 运行中尾部预览（限 64KB）

    def to_dict(self) -> dict:
        """序列化为 dict（供 LLM 读取）。"""
        return {
            "execution_id": self.execution_id,
            "tool": self.tool_name,
            "status": self.status,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration": round(
                (self.finished_at or time.time()) - (self.started_at or self.created_at), 2
            ),
            "result": self.result,
            "error": self.error,
            "partial_output": self.partial_output[-_PARTIAL_PREVIEW_LIMIT:]
            if self.partial_output
            else "",
        }


class MCPExecution:
    """后台执行引擎：Submit/Wait/Cancel 三件套。

    - submit 返回 execution_id，通过 asyncio.create_task 独立运行，脱离调用方 ctx
    - wait 有界等待，超时返回当前状态（任务仍在后台运行）
    - cancel 取消执行

    内置 panic recover + partial output（运行中逐行读取 stdout，尾部预览限 64KB）。
    """

    def __init__(self):
        self._executions: dict[str, ExecutionState] = {}
        self._tasks: dict[str, asyncio.Task] = {}

    async def submit(self, tool_name: str, args: dict, timeout: float = 120) -> str:
        """提交后台执行，返回 execution_id。

        通过 asyncio.create_task 独立运行，脱离调用方 ctx。
        注意：必须在事件循环内调用（async 上下文），否则 create_task 报 RuntimeError。
        """
        execution_id = uuid.uuid4().hex[:16]
        state = ExecutionState(
            execution_id=execution_id,
            tool_name=tool_name,
            args=dict(args),
            timeout=timeout,
        )
        self._executions[execution_id] = state
        # asyncio.create_task 独立运行，脱离调用方 ctx
        task = asyncio.create_task(self._run(execution_id))
        self._tasks[execution_id] = task
        logger.info(
            "MCP 执行已提交: %s tool=%s timeout=%.0fs", execution_id, tool_name, timeout
        )
        return execution_id

    async def _run(self, execution_id: str) -> None:
        """实际执行协程（panic recover）。"""
        state = self._executions.get(execution_id)
        if state is None:
            return

        state.status = "running"
        state.started_at = time.time()

        try:
            result = await asyncio.wait_for(
                self._execute_streaming(execution_id),
                timeout=state.timeout + 30,  # 额外 30s 余量给信号量等待
            )
            state.result = result
            # 完成后更新 partial_output 为最终输出的尾部
            state.partial_output = (result.get("stdout") or "")[-_PARTIAL_PREVIEW_LIMIT:]
            state.status = "completed"
        except asyncio.TimeoutError:
            state.status = "hard_timeout"
            state.error = f"执行硬超时 ({state.timeout}s)"
            logger.warning("MCP 执行 %s 硬超时", execution_id)
        except asyncio.CancelledError:
            state.status = "cancelled"
            state.error = "执行被取消"
            logger.info("MCP 执行 %s 被取消", execution_id)
            raise
        except Exception as e:
            state.status = "failed"
            state.error = f"执行异常: {e}"
            logger.exception("MCP 执行 %s 异常", execution_id)
        finally:
            state.finished_at = time.time()
            self._tasks.pop(execution_id, None)

    async def _execute_streaming(self, execution_id: str) -> dict[str, Any]:
        """带流式 partial output 的异步执行。

        复用 client.py 的熔断器 + 异步信号量，但使用 Popen 逐行读取输出，
        实时更新 state.partial_output（尾部 64KB）。
        """
        state = self._executions[execution_id]
        tool_name = state.tool_name

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

        # 获取工具定义（走缓存）
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
        cmd, is_high_risk = td.build_command(state.args)
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

        # 安全检查：guard.check_command 在执行前调用
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

        cmd_timeout = min(int(state.timeout), worker_config.shell_timeout_max)
        spill_id = execution_id

        # 异步信号量限流（全局 16 + 每工具 2）
        global_sem = _get_global_async_sem()
        tool_sem = _get_tool_async_sem(tool_name)

        async with global_sem:
            async with tool_sem:
                # 在线程池中执行带流式输出的 subprocess
                result = await asyncio.to_thread(
                    self._run_subprocess_streaming,
                    execution_id,
                    cmd,
                    cmd_timeout,
                    spill_id,
                    is_high_risk,
                )

        # 熔断器反馈：有 error 视为失败
        if result.get("error"):
            _breaker.record_failure(tool_name)
        else:
            _breaker.record_success(tool_name)

        return result

    def _run_subprocess_streaming(
        self,
        execution_id: str,
        cmd: str,
        timeout: int,
        spill_id: str,
        is_high_risk: bool,
    ) -> dict[str, Any]:
        """在线程中执行子进程，逐行读取 stdout 实时更新 partial_output。"""
        state = self._executions[execution_id]
        tool_name = state.tool_name

        start = time.time()
        stdout_data = ""
        stderr_data = ""
        returncode = -1
        error_msg: str | None = None

        try:
            proc = subprocess.Popen(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=worker_config.work_root,
                env={**os.environ},
            )
            try:
                stdout_chunks: list[str] = []
                buf_len = 0
                assert proc.stdout is not None
                for line in proc.stdout:
                    stdout_chunks.append(line)
                    buf_len += len(line)
                    # 每积累约 64KB 更新一次 partial_output（尾部预览）
                    if buf_len >= _PARTIAL_PREVIEW_LIMIT:
                        state.partial_output = "".join(stdout_chunks)[
                            -_PARTIAL_PREVIEW_LIMIT:
                        ]
                        buf_len = 0
                stdout_data = "".join(stdout_chunks)
                # 最终更新 partial_output
                state.partial_output = stdout_data[-_PARTIAL_PREVIEW_LIMIT:]
                stderr_data = proc.stderr.read() if proc.stderr else ""
                proc.wait(timeout=timeout)
                returncode = proc.returncode
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
                error_msg = f"工具执行超时 ({timeout}s)"
                stderr_data = error_msg
            finally:
                # 确保进程终止
                if proc.poll() is None:
                    proc.kill()
                    proc.wait()
        except Exception as e:
            error_msg = f"工具执行异常: {e}"
            stderr_data = str(e)

        duration = round(time.time() - start, 2)
        logger.info(
            "MCP工具 %s 执行完成 rc=%d 耗时%.1fs", tool_name, returncode, duration
        )

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

    async def wait(self, execution_id: str, timeout: float = 60) -> dict:
        """有界等待，超时返回当前状态（任务仍在后台运行）。"""
        state = self._executions.get(execution_id)
        if state is None:
            return {"execution_id": execution_id, "status": "not_found"}

        # 已在终态，直接返回
        if state.status in _TERMINAL_STATES:
            return state.to_dict()

        task = self._tasks.get(execution_id)
        if task is None:
            return state.to_dict()

        try:
            # shield 防止 wait 超时取消实际执行任务
            await asyncio.wait_for(asyncio.shield(task), timeout=timeout)
        except asyncio.TimeoutError:
            # 等待超时，返回当前状态（任务仍在后台运行）
            pass

        # wait 完成后自动清理过期终态记录，避免内存泄漏
        self.cleanup()
        return state.to_dict()

    def cancel(self, execution_id: str) -> bool:
        """取消执行。"""
        state = self._executions.get(execution_id)
        if state is None:
            return False

        if state.status in _TERMINAL_STATES:
            return False

        task = self._tasks.get(execution_id)
        if task and not task.done():
            task.cancel()
            state.status = "cancelled"
            state.error = "用户取消"
            return True

        return False

    def get_state(self, execution_id: str) -> dict:
        """获取执行状态 + partial output。"""
        state = self._executions.get(execution_id)
        if state is None:
            return {"execution_id": execution_id, "status": "not_found"}
        return state.to_dict()

    def cleanup(self, max_age: float = 3600) -> None:
        """清理过期的执行记录（超过 max_age 秒的终态记录）。"""
        now = time.time()
        expired = [
            eid
            for eid, s in self._executions.items()
            if s.finished_at and (now - s.finished_at) > max_age
        ]
        for eid in expired:
            self._executions.pop(eid, None)
        if expired:
            logger.info("MCP 执行清理: 回收 %d 条过期记录", len(expired))


# ===== 全局单例 =====

_execution_engine = MCPExecution()


def get_execution_engine() -> MCPExecution:
    """获取全局执行引擎单例。"""
    return _execution_engine


# ===== 执行控制元工具（暴露给 LLM 的 function calling）=====


def get_tool_execution(execution_id: str) -> dict:
    """查询工具执行状态及 partial output。"""
    return _execution_engine.get_state(execution_id)


async def wait_tool_execution(execution_id: str, timeout: float = 60) -> dict:
    """有界等待工具执行完成，超时返回当前状态。"""
    return await _execution_engine.wait(execution_id, timeout)


def cancel_tool_execution(execution_id: str) -> dict:
    """取消工具执行。"""
    ok = _execution_engine.cancel(execution_id)
    return {"execution_id": execution_id, "cancelled": ok}


# 元工具的 function calling schema（注入 LLM 工具列表）
EXECUTION_META_SCHEMAS: list[dict] = [
    {
        "type": "function",
        "function": {
            "name": "get_tool_execution",
            "description": "查询 MCP 工具后台执行状态及 partial output（尾部预览）",
            "parameters": {
                "type": "object",
                "properties": {
                    "execution_id": {
                        "type": "string",
                        "description": "submit 返回的执行 ID",
                    },
                },
                "required": ["execution_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "wait_tool_execution",
            "description": "有界等待 MCP 工具后台执行完成，超时返回当前状态",
            "parameters": {
                "type": "object",
                "properties": {
                    "execution_id": {
                        "type": "string",
                        "description": "submit 返回的执行 ID",
                    },
                    "timeout": {
                        "type": "number",
                        "description": "等待超时秒数，默认 60",
                        "default": 60,
                    },
                },
                "required": ["execution_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "cancel_tool_execution",
            "description": "取消正在运行的 MCP 工具后台执行",
            "parameters": {
                "type": "object",
                "properties": {
                    "execution_id": {
                        "type": "string",
                        "description": "submit 返回的执行 ID",
                    },
                },
                "required": ["execution_id"],
            },
        },
    },
]


# 元工具名 → 处理函数映射（供 worker 分发调用）
EXECUTION_META_HANDLERS: dict[str, Any] = {
    "get_tool_execution": get_tool_execution,
    "wait_tool_execution": wait_tool_execution,
    "cancel_tool_execution": cancel_tool_execution,
}
