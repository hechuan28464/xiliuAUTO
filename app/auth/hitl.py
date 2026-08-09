"""HITL 人机协同审批模块（自研）— 持久化 + 阻塞等待 + 审计 Agent 升级版。

审核模式：
1. ai_auto: AI 初审 → 直接入库（原版模式）
2. ai_then_human: AI 初审 → 人工确认（推荐）
3. human_only: 跳过 AI，直接人工审核
4. audit_agent: AI 初审 + 审计 Agent 复核（AI 失败保守拒绝）

高危操作（run_shell 危险命令）触发审批。
所有中断记录持久化到 hitl_interrupts 表，进程重启可恢复。
启动时孤儿清理：残留 pending 记录保守拒绝（fail-safe）。

升级点：
- 阻塞等待（wait_approval）：用 asyncio.Future 替代轮询，resolve 时唤醒，超时自动拒绝。
- 审计 Agent（audit_agent_review）：构建审计 prompt + 注入认知上下文，LLM 裁决，异常保守拒绝。
- 白名单分层：全局白名单（HITL_TOOL_WHITELIST）+ 内置元工具豁免，白名单内工具无需审批。
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy import select, update

from app.db.models import HitlInterrupt, _now

logger = logging.getLogger("autohunter.hitl")

# 默认审核模式
_HITL_MODE = os.environ.get("HITL_MODE", "ai_then_human")

# 高危操作是否需要审批
_HITL_HIGH_RISK_REVIEW = os.environ.get("HITL_HIGH_RISK_REVIEW", "1").lower() in {"1", "true", "yes"}

# 审批超时（秒）：超时后自动拒绝
_HITL_TIMEOUT = int(os.environ.get("HITL_TIMEOUT", "300"))

# 高风险命令关键词
_HIGH_RISK_COMMANDS = {
    "rm -rf", "rm -fr", "mkfs", "dd if=", "shutdown", "reboot", "halt",
    "chmod 777", "chown -R", ":(){:|:&};:",
    "wget -O- | sh", "curl | bash", "curl | sh",
    "drop table", "delete from", "truncate",
}

# 全局工具白名单（从环境变量 HITL_TOOL_WHITELIST 读取，逗号分隔）
_TOOL_WHITELIST: set[str] = {
    name.strip()
    for name in os.environ.get("HITL_TOOL_WHITELIST", "").split(",")
    if name.strip()
}

# 内置元工具豁免（编排/辅助工具，低风险，无需人工审批）
_META_TOOL_EXEMPT: set[str] = {
    "http_request", "session_set", "session_get", "check_duplicate",
    "finish", "list_tools",
}

# 已决议标记（并发安全返回值）
ALREADY_RESOLVED = "already_resolved"


def is_high_risk_command(command: str) -> bool:
    """判断命令是否高风险。"""
    if not command:
        return False
    low = command.lower()
    return any(kw in low for kw in _HIGH_RISK_COMMANDS)


def should_review_command(command: str) -> bool:
    """高危命令是否需要审批。"""
    if not _HITL_HIGH_RISK_REVIEW:
        return False
    return is_high_risk_command(command)


def get_review_mode() -> str:
    """获取当前审核模式。"""
    return _HITL_MODE


def is_tool_whitelisted(tool_name: str) -> bool:
    """判断工具是否在白名单内（无需人工审批）。

    白名单分层：
    1. 全局白名单（HITL_TOOL_WHITELIST 环境变量，逗号分隔）
    2. 内置元工具豁免（http_request/session_set/check_duplicate 等编排工具）
    """
    if not tool_name:
        return False
    name = tool_name.strip()
    return name in _TOOL_WHITELIST or name in _META_TOOL_EXEMPT


def should_human_review(
    verdict: str,
    severity: str = "",
    ai_failed: bool = False,
    tool_name: str = "",
) -> bool:
    """根据审核模式判断是否需要人工确认。

    白名单分层：在白名单内（全局白名单 + 内置元工具豁免）的工具无需人工审批。
    audit_agent 模式下 AI 调用失败时保守拒绝（fail-safe）：
    返回 True 触发人工审批，无人审批时超时自动拒绝。
    """
    # 白名单分层：白名单内的工具无需人工审批
    if tool_name and is_tool_whitelisted(tool_name):
        return False
    if _HITL_MODE == "human_only":
        return True
    if _HITL_MODE == "ai_then_human":
        # 严重/高危需要人工确认，中低危可以 AI 自动处理
        return severity in ("严重", "高危")
    if _HITL_MODE == "audit_agent":
        # 审计 Agent 模式：AI 调用失败时必须人工确认（fail-safe）
        if ai_failed:
            return True
        # 严重漏洞需要人工最终确认
        return severity == "严重"
    return False  # ai_auto


# 内存缓存（快速查询，DB 是 source of truth）
_pending_approvals: dict[str, dict] = {}
_pending_lock = threading.Lock()

# 阻塞等待 Future 注册表：wait_approval 注册，resolve_approval 设置结果唤醒
_wait_futures: dict[str, asyncio.Future] = {}


def _wake_waiter(approval_id: str, result: dict) -> None:
    """唤醒阻塞等待方（wait_approval 注册的 Future）。

    asyncio.Future.set_result 不会同步执行回调（回调经 call_soon 调度），
    因此在线程锁内调用也安全，不会阻塞事件循环。
    """
    fut = _wait_futures.get(approval_id)
    if fut is not None and not fut.done():
        try:
            fut.set_result(result)
        except asyncio.InvalidStateError:
            # 已被并发设置，忽略
            pass


async def request_approval(
    approval_id: str,
    tool_name: str,
    args: dict,
    reason: str,
    *,
    conversation_id: str = "",
    tool_call_id: str = "",
    thinking: str | None = None,
    reasoning_chain: str | None = None,
    planning: str | None = None,
    user_message: str | None = None,
) -> dict:
    """提交审批请求（持久化到 hitl_interrupts 表）。

    认知上下文（thinking/reasoning_chain/planning/user_message）存入 payload，
    供审批方查看。持久化失败时保守拒绝（fail-safe）。
    """
    # 构造 payload（含认知上下文）
    payload: dict[str, Any] = {
        "args": args,
        "reason": reason,
    }
    if thinking is not None:
        payload["thinking"] = thinking
    if reasoning_chain is not None:
        payload["reasoning_chain"] = reasoning_chain
    if planning is not None:
        payload["planning"] = planning
    if user_message is not None:
        payload["user_message"] = user_message

    # 内存缓存
    with _pending_lock:
        _pending_approvals[approval_id] = {
            "tool": tool_name,
            "args": args,
            "reason": reason,
            "status": "pending",
            "created_at": time.time(),
            "payload": payload,
        }

    # 持久化到 DB
    try:
        from app.db.session import SessionLocal
        async with SessionLocal() as session:
            interrupt = HitlInterrupt(
                id=approval_id,
                conversation_id=conversation_id,
                tool_name=tool_name,
                tool_call_id=tool_call_id,
                payload=payload,
                status="pending",
            )
            session.add(interrupt)
            await session.commit()
    except Exception as e:
        logger.error("HITL 审批请求持久化失败，保守拒绝: %s", e)
        # fail-safe：持久化失败时默认拒绝
        with _pending_lock:
            _pending_approvals[approval_id] = {
                "tool": tool_name,
                "args": args,
                "reason": reason,
                "status": "rejected",
                "created_at": time.time(),
                "payload": payload,
                "error": f"persist_failed: {e}",
            }
        return {
            "status": "rejected",
            "approval_id": approval_id,
            "reason": reason,
            "error": f"persist_failed: {e}",
        }

    # 发送通知
    try:
        from app.notify import notify_hitl_pending
        notify_hitl_pending(tool_name, args, reason)
    except Exception:
        pass

    return {"status": "pending", "approval_id": approval_id, "reason": reason}


async def check_approval(approval_id: str) -> Optional[dict]:
    """查询审批状态（优先读内存缓存，回退 DB）。"""
    # 优先读内存
    with _pending_lock:
        cached = _pending_approvals.get(approval_id)
        if cached:
            return {**cached, "id": approval_id}

    # 回退 DB
    try:
        from app.db.session import SessionLocal
        async with SessionLocal() as session:
            row = (
                await session.execute(
                    select(HitlInterrupt).where(HitlInterrupt.id == approval_id)
                )
            ).scalar_one_or_none()
            if not row:
                return None
            return {
                "id": row.id,
                "tool": row.tool_name,
                "args": (row.payload or {}).get("args", {}),
                "reason": (row.payload or {}).get("reason", ""),
                "status": row.status,
                "decision": row.decision,
                "comment": row.decision_comment,
                "reviewer": row.decided_by,
                "payload": row.payload,
                "created_at": row.created_at,
                "resolved_at": row.decided_at,
            }
    except Exception:
        return None


async def resolve_approval(
    approval_id: str,
    approved: bool,
    reviewer: str = "",
    comment: str = "",
) -> str | bool:
    """审批决议（并发安全）。

    返回值：
    - True: 决议成功
    - ALREADY_RESOLVED ("already_resolved"): 该请求已被决议（并发安全）
    - False: 请求不存在
    """
    decision = "approve" if approved else "reject"
    decided_by = reviewer or "human"
    now = _now()

    # 内存层并发安全：CAS 检查
    with _pending_lock:
        cached = _pending_approvals.get(approval_id)
        if not cached:
            # 请求不存在：唤醒等待方（如有）并告知拒绝
            _wake_waiter(approval_id, {
                "status": "rejected",
                "decision": "reject",
                "approval_id": approval_id,
                "reason": "not_found",
            })
            return False
        if cached["status"] != "pending":
            # 已被决议：把既有决议回传给等待方
            prior = cached["status"]
            _wake_waiter(approval_id, {
                "status": prior,
                "decision": "approve" if prior == "approved" else "reject",
                "approval_id": approval_id,
                "reviewer": cached.get("reviewer", ""),
                "comment": cached.get("comment", ""),
                "reason": "already_resolved",
            })
            return ALREADY_RESOLVED
        # 先标记内存，防止并发二次决议
        cached["status"] = "approved" if approved else "rejected"
        cached["reviewer"] = reviewer
        cached["comment"] = comment
        cached["resolved_at"] = time.time()

    # DB 持久化（条件更新：只更新 pending 的记录，保证并发安全）
    try:
        from app.db.session import SessionLocal
        async with SessionLocal() as session:
            result = await session.execute(
                update(HitlInterrupt)
                .where(HitlInterrupt.id == approval_id)
                .where(HitlInterrupt.status == "pending")
                .values(
                    status="decided",
                    decision=decision,
                    decision_comment=comment,
                    decided_by=decided_by,
                    decided_at=now,
                )
            )
            await session.commit()
            if result.rowcount == 0:
                # DB 中已非 pending（可能另一进程/线程已决议）
                logger.warning("HITL 决议并发冲突: %s 已被处理", approval_id)
                _wake_waiter(approval_id, {
                    "status": "approved" if approved else "rejected",
                    "decision": decision,
                    "approval_id": approval_id,
                    "reviewer": decided_by,
                    "comment": comment,
                    "reason": "already_resolved",
                })
                return ALREADY_RESOLVED
    except Exception as e:
        logger.error("HITL 决议持久化失败: %s", e)
        # 内存已标记，DB 失败不回滚（fail-safe：宁可多拒不放过）

    # 唤醒阻塞等待方（wait_approval）
    _wake_waiter(approval_id, {
        "status": "approved" if approved else "rejected",
        "decision": decision,
        "approval_id": approval_id,
        "reviewer": decided_by,
        "comment": comment,
    })
    # 决议完成：从内存缓存删除（DB 是 source of truth，后续查询走 DB）
    with _pending_lock:
        _pending_approvals.pop(approval_id, None)
    return True


async def wait_approval(interrupt_id: str, timeout: float = 300.0) -> dict:
    """阻塞等待审批决议（替代轮询）。

    用 asyncio.Future 实现阻塞等待：resolve_approval 设置 Future 结果即唤醒。
    超时自动 reject 并回传（fail-safe）。若请求已被决议（resolve 在 wait 之前发生），
    立即返回既有决议。
    """
    loop = asyncio.get_running_loop()

    # 先检查是否已被决议（resolve 可能在 wait 之前发生）
    with _pending_lock:
        cached = _pending_approvals.get(interrupt_id)
        if cached and cached.get("status") != "pending":
            prior = cached["status"]
            return {
                "status": prior,
                "decision": "approve" if prior == "approved" else "reject",
                "approval_id": interrupt_id,
                "reviewer": cached.get("reviewer", ""),
                "comment": cached.get("comment", ""),
                "reason": "already_resolved",
            }

    # 获取或创建该中断对应的 Future（done 则重建，避免复用已完成的 Future）
    fut = _wait_futures.get(interrupt_id)
    if fut is None or fut.done():
        fut = loop.create_future()
        _wait_futures[interrupt_id] = fut

    try:
        # shield 保护内层 Future：wait_for 超时不会取消 Future 本身，
        # 便于后续 resolve_approval 仍可 set_result。
        return await asyncio.wait_for(asyncio.shield(fut), timeout=timeout)
    except asyncio.TimeoutError:
        # 超时自动拒绝（fail-safe）
        logger.warning("HITL 等待审批超时，自动拒绝: %s", interrupt_id)
        await resolve_approval(
            interrupt_id, approved=False, reviewer="system", comment="wait_timeout"
        )
        # resolve_approval 已设置 Future 结果，尝试取回
        if fut.done() and not fut.cancelled():
            try:
                return fut.result()
            except Exception:
                pass
        return {
            "status": "rejected",
            "decision": "reject",
            "approval_id": interrupt_id,
            "reason": "wait_timeout",
            "reviewer": "system",
        }
    finally:
        # 清理 Future 注册表，避免泄漏
        _wait_futures.pop(interrupt_id, None)


async def cleanup_expired() -> int:
    """清理超时审批请求（内存 + DB），返回清理数。

    超时请求保守拒绝（fail-safe）。
    """
    now_ts = time.time()
    expired_ids = []
    with _pending_lock:
        # 遍历快照，避免遍历中修改字典
        for aid, req in list(_pending_approvals.items()):
            if req["status"] == "pending" and (now_ts - req["created_at"]) > _HITL_TIMEOUT:
                req["status"] = "timeout"
                req["decision"] = "reject"
                expired_ids.append(aid)
                # 删除已超时条目，避免内存泄漏
                _pending_approvals.pop(aid, None)

    # DB 清理：超时 pending 记录标记为 timeout + reject
    try:
        from app.db.session import SessionLocal
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=_HITL_TIMEOUT)
        async with SessionLocal() as session:
            await session.execute(
                update(HitlInterrupt)
                .where(HitlInterrupt.status == "pending")
                .where(HitlInterrupt.created_at < cutoff)
                .values(
                    status="timeout",
                    decision="reject",
                    decided_by="system",
                    decided_at=_now(),
                )
            )
            await session.commit()
    except Exception as e:
        logger.error("HITL 超时清理 DB 失败: %s", e)

    return len(expired_ids)


async def list_pending() -> list[dict]:
    """列出所有待审批请求（内存优先，回退 DB）。"""
    with _pending_lock:
        mem_pending = [
            {**v, "id": k}
            for k, v in _pending_approvals.items()
            if v["status"] == "pending"
        ]
    if mem_pending:
        return mem_pending

    # 回退 DB
    try:
        from app.db.session import SessionLocal
        async with SessionLocal() as session:
            rows = (
                await session.execute(
                    select(HitlInterrupt)
                    .where(HitlInterrupt.status == "pending")
                    .order_by(HitlInterrupt.created_at)
                )
            ).scalars().all()
            return [
                {
                    "id": r.id,
                    "tool": r.tool_name,
                    "args": (r.payload or {}).get("args", {}),
                    "reason": (r.payload or {}).get("reason", ""),
                    "status": r.status,
                    "payload": r.payload,
                    "created_at": r.created_at,
                }
                for r in rows
            ]
    except Exception:
        return []


async def cleanup_orphans() -> int:
    """启动时孤儿清理：把所有 status=pending 的中断记录置为 cancelled/reject。

    进程重启后残留的 pending 记录已无人审批，保守拒绝（fail-safe）。
    返回清理数量。
    """
    # 内存清理
    with _pending_lock:
        for _aid, req in list(_pending_approvals.items()):
            if req["status"] == "pending":
                req["status"] = "cancelled"
                req["decision"] = "reject"
                # 删除已取消的孤儿条目，避免内存泄漏
                _pending_approvals.pop(_aid, None)

    # DB 清理
    try:
        from app.db.session import SessionLocal
        async with SessionLocal() as session:
            result = await session.execute(
                update(HitlInterrupt)
                .where(HitlInterrupt.status == "pending")
                .values(
                    status="cancelled",
                    decision="reject",
                    decided_by="system",
                    decided_at=_now(),
                )
            )
            await session.commit()
            count = result.rowcount
            if count:
                logger.info("HITL 孤儿清理：%d 条 pending 中断已取消", count)
            return count
    except Exception as e:
        logger.error("HITL 孤儿清理失败: %s", e)
        return 0


async def record_execution_result(interrupt_id: str, result: dict) -> bool:
    """记录执行回执（闭环）。

    在 payload 中追加 execution_result 子对象，供审计追踪。
    """
    # 同步内存缓存
    with _pending_lock:
        if interrupt_id in _pending_approvals:
            _pending_approvals[interrupt_id]["execution_result"] = result

    # DB 持久化
    try:
        from app.db.session import SessionLocal
        async with SessionLocal() as session:
            row = (
                await session.execute(
                    select(HitlInterrupt).where(HitlInterrupt.id == interrupt_id)
                )
            ).scalar_one_or_none()
            if not row:
                return False
            payload = dict(row.payload or {})
            payload["execution_result"] = result
            row.payload = payload
            await session.commit()
            return True
    except Exception as e:
        logger.error("HITL 执行回执记录失败: %s", e)
        return False


# ==================== 审计 Agent LLM 裁决 ====================

# 审计 Agent LLM 调用超时（秒）
_AUDIT_LLM_TIMEOUT = 90.0

# 审计裁决归一化关键词：命中即视为 approve
_APPROVE_KEYWORDS = ("approve", "通过", "批准", "允许", "同意", "accept", "yes")

# 审计 prompt 中可识别的裁决键名（多键名容错）
_DECISION_KEYS = ("decision", "Decision", "result", "action", "verdict")

# JSON 代码块 / 裸 JSON 提取正则
_AUDIT_FENCE_RE = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL)


def _first_json_object(text: str) -> str | None:
    """返回 text 中第一个大括号平衡的 JSON 对象子串（考虑字符串转义）。"""
    start = text.find("{")
    while start != -1:
        depth = 0
        in_str = False
        esc = False
        for i in range(start, len(text)):
            c = text[i]
            if in_str:
                if esc:
                    esc = False
                elif c == "\\":
                    esc = True
                elif c == '"':
                    in_str = False
            else:
                if c == '"':
                    in_str = True
                elif c == "{":
                    depth += 1
                elif c == "}":
                    depth -= 1
                    if depth == 0:
                        return text[start:i + 1]
        start = text.find("{", start + 1)
    return None


def _normalize_decision(value: str) -> str:
    """中英文裁决归一化为 approve/reject。

    approve/通过/批准/允许/同意/accept/yes → approve，其余 → reject。
    """
    low = (value or "").strip().lower()
    if any(k.lower() in low for k in _APPROVE_KEYWORDS):
        return "approve"
    return "reject"


def _parse_audit_decision(content: str) -> str:
    """解析 LLM 审计裁决，多键名容错 + 中英文归一化。

    容错键名：decision/Decision/result/action/verdict。
    任何解析失败默认 reject（fail-safe）。
    """
    if not content:
        return "reject"
    text = content.strip()

    # 优先从 JSON 代码块提取
    candidate = None
    m = _AUDIT_FENCE_RE.search(text)
    if m:
        candidate = m.group(1)
    else:
        candidate = _first_json_object(text)

    if candidate:
        try:
            obj = json.loads(candidate)
            if isinstance(obj, dict):
                for key in _DECISION_KEYS:
                    val = obj.get(key)
                    if val is not None:
                        return _normalize_decision(str(val))
        except (json.JSONDecodeError, TypeError):
            pass

    # 退化：直接在全文中匹配 approve 关键词
    low = text.lower()
    if any(k.lower() in low for k in _APPROVE_KEYWORDS):
        return "approve"
    return "reject"


async def audit_agent_review(interrupt_id: str, llm_config: dict) -> dict:
    """审计 Agent LLM 裁决。

    构建审计 prompt（system message），把认知上下文（thinking/reasoning_chain/
    planning/user_message）注入 LLM user message，调用 LLM 裁决。
    temperature=0.1, max_tokens=1024, 90 秒超时。
    LLM 响应解析：多键名容错 + 中英文归一化。
    任何异常默认 reject（fail-safe）。
    """
    # 取中断的认知上下文（内存优先，回退 DB）
    payload: dict[str, Any] = {}
    with _pending_lock:
        cached = _pending_approvals.get(interrupt_id)
        if cached:
            payload = dict(cached.get("payload") or {})
            if "tool" not in payload and cached.get("tool"):
                payload["tool"] = cached["tool"]

    if not payload:
        try:
            from app.db.session import SessionLocal
            async with SessionLocal() as session:
                row = (
                    await session.execute(
                        select(HitlInterrupt).where(HitlInterrupt.id == interrupt_id)
                    )
                ).scalar_one_or_none()
                if row:
                    payload = dict(row.payload or {})
                    if not payload.get("tool") and row.tool_name:
                        payload["tool"] = row.tool_name
        except Exception as e:
            logger.warning("HITL 审计 Agent 取上下文失败: %s", e)

    if not payload:
        # 取不到上下文，保守拒绝
        return {
            "decision": "reject",
            "reason": "context_unavailable",
            "reviewer": "audit_agent",
        }

    # 构建审计 prompt（system message）
    system_prompt = (
        "你是一名安全审计 Agent，负责复核即将执行的高危操作是否应该批准。\n"
        "请根据提供的认知上下文（Agent 思考链、推理过程、计划、用户原始指令）"
        "判断该操作是否合法、必要、风险可控。\n"
        "只输出 JSON：{\"decision\": \"approve\" 或 \"reject\", \"reason\": \"简要理由\"}。"
        "批准输出 approve，拒绝输出 reject。禁止输出 JSON 以外的内容。"
    )

    # 注入认知上下文到 user message
    context_parts: list[str] = []
    if payload.get("tool"):
        context_parts.append(f"工具: {payload.get('tool')}")
    args = payload.get("args")
    if args is not None:
        try:
            context_parts.append(f"参数: {json.dumps(args, ensure_ascii=False)}")
        except (TypeError, ValueError):
            context_parts.append(f"参数: {args}")
    if payload.get("reason"):
        context_parts.append(f"触发原因: {payload.get('reason')}")
    if payload.get("thinking"):
        context_parts.append(f"Agent 思考: {payload.get('thinking')}")
    if payload.get("reasoning_chain"):
        context_parts.append(f"推理链: {payload.get('reasoning_chain')}")
    if payload.get("planning"):
        context_parts.append(f"计划: {payload.get('planning')}")
    if payload.get("user_message"):
        context_parts.append(f"用户指令: {payload.get('user_message')}")
    user_message = "\n".join(context_parts) or "（无认知上下文）"

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_message},
    ]

    try:
        # 构造 LLM 客户端（按传入 config；为空则用全局默认配置）
        from app.llm.client import LLMClient
        from app.config import LLMConfig

        if llm_config:
            # 只取 LLMConfig 认可的字段，避免非法键报错
            valid_fields = {
                "base_url", "api_key", "model",
                "temperature", "protocol", "weight", "enabled",
            }
            filtered = {k: v for k, v in llm_config.items() if k in valid_fields}
            cfg = LLMConfig(**filtered)
        else:
            from app.config import llm_config as _default_cfg  # type: ignore
            cfg = _default_cfg  # type: ignore
        client = LLMClient(config=cfg)

        # 同步 LLM 调用包装为异步（90 秒超时）
        loop = asyncio.get_running_loop()
        msg = await asyncio.wait_for(
            loop.run_in_executor(
                None,
                lambda: client.chat(
                    messages, temperature=0.1, max_tokens=1024
                ),
            ),
            timeout=_AUDIT_LLM_TIMEOUT,
        )
        content = getattr(msg, "content", "") or ""
        decision = _parse_audit_decision(content)
        return {
            "decision": decision,
            "raw": content,
            "reviewer": "audit_agent",
        }
    except asyncio.TimeoutError:
        logger.warning("HITL 审计 Agent LLM 调用超时，保守拒绝: %s", interrupt_id)
        return {
            "decision": "reject",
            "reason": "llm_timeout",
            "reviewer": "audit_agent",
        }
    except Exception as e:
        logger.warning("HITL 审计 Agent LLM 调用异常，保守拒绝: %s", e)
        return {
            "decision": "reject",
            "reason": f"llm_error: {e}",
            "reviewer": "audit_agent",
        }
