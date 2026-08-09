"""HITL 人机协同审批模块（从 CyberStrikeAI 移植）。

审核模式：
1. ai_auto: AI 初审 → 直接入库（原版模式）
2. ai_then_human: AI 初审 → 人工确认（推荐）
3. human_only: 跳过 AI，直接人工审核
4. audit_agent: AI 初审 + 审计 Agent 复核

高危操作（run_shell 危险命令）触发审批。
"""
from __future__ import annotations

import logging
import os
import threading
from typing import Any, Optional

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


def should_human_review(verdict: str, severity: str = "") -> bool:
    """根据审核模式判断是否需要人工确认。"""
    if _HITL_MODE == "human_only":
        return True
    if _HITL_MODE == "ai_then_human":
        # 严重/高危需要人工确认，中低危可以 AI 自动处理
        return severity in ("严重", "高危")
    if _HITL_MODE == "audit_agent":
        # 审计 Agent 模式：严重漏洞需要人工最终确认
        return severity == "严重"
    return False  # ai_auto


# 审批请求队列（内存中，单进程内有效）
_pending_approvals: dict[str, dict] = {}
_pending_lock = threading.Lock()


def request_approval(approval_id: str, tool_name: str, args: dict, reason: str) -> dict:
    """提交审批请求。"""
    with _pending_lock:
        _pending_approvals[approval_id] = {
            "tool": tool_name,
            "args": args,
            "reason": reason,
            "status": "pending",
            "created_at": __import__("time").time(),
        }

    # 发送通知
    try:
        from app.notify import notify_hitl_pending
        notify_hitl_pending(tool_name, args, reason)
    except Exception:
        pass

    return {"status": "pending", "approval_id": approval_id, "reason": reason}


def check_approval(approval_id: str) -> Optional[dict]:
    """查询审批状态。"""
    with _pending_lock:
        return _pending_approvals.get(approval_id)


def resolve_approval(approval_id: str, approved: bool, reviewer: str = "", comment: str = "") -> bool:
    """审批决议。"""
    with _pending_lock:
        req = _pending_approvals.get(approval_id)
        if not req or req["status"] != "pending":
            return False
        req["status"] = "approved" if approved else "rejected"
        req["reviewer"] = reviewer
        req["comment"] = comment
        req["resolved_at"] = __import__("time").time()
        return True


def cleanup_expired() -> int:
    """清理超时审批请求，返回清理数。"""
    import time
    now = time.time()
    expired_ids = []
    with _pending_lock:
        for aid, req in _pending_approvals.items():
            if req["status"] == "pending" and (now - req["created_at"]) > _HITL_TIMEOUT:
                req["status"] = "timeout"
                expired_ids.append(aid)
    return len(expired_ids)


def list_pending() -> list[dict]:
    """列出所有待审批请求。"""
    with _pending_lock:
        return [
            {**v, "id": k}
            for k, v in _pending_approvals.items()
            if v["status"] == "pending"
        ]
