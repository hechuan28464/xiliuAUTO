"""审计日志模块：记录所有关键操作（从 CyberStrikeAI 移植）。

全部异步，与主项目 session 体系一致。
"""
from __future__ import annotations

import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.rbac import AuditLog

logger = logging.getLogger("autohunter.audit")

_RETENTION_DAYS = int(os.environ.get("AUDIT_RETENTION_DAYS", "15"))


async def log_action(
    session: AsyncSession,
    user_id: str = "",
    username: str = "",
    action: str = "",
    resource: str = "",
    detail: str = "",
    ip_address: str = "",
):
    """记录一条审计日志（异步）。"""
    try:
        log = AuditLog(
            id=uuid.uuid4().hex,
            user_id=user_id,
            username=username,
            action=action,
            resource=resource[:300],
            detail=detail[:8000],
            ip_address=ip_address[:64],
        )
        session.add(log)
        await session.commit()
    except Exception as e:
        logger.warning("审计日志写入失败: %s", e)


async def query_logs(
    session: AsyncSession,
    limit: int = 100,
    offset: int = 0,
    action_filter: str = "",
    username_filter: str = "",
) -> list[dict]:
    """查询审计日志（异步）。"""
    stmt = select(AuditLog).order_by(AuditLog.created_at.desc())
    if action_filter:
        stmt = stmt.where(AuditLog.action.like(f"%{action_filter}%"))
    if username_filter:
        stmt = stmt.where(AuditLog.username == username_filter)
    stmt = stmt.limit(limit).offset(offset)
    results = await session.execute(stmt)
    rows = results.scalars().all()
    return [
        {
            "id": r.id,
            "user_id": r.user_id,
            "username": r.username,
            "action": r.action,
            "resource": r.resource,
            "detail": r.detail[:500] if r.detail else "",
            "ip_address": r.ip_address,
            "created_at": r.created_at.isoformat() if r.created_at else "",
        }
        for r in rows
    ]


async def prune_old_logs(session: AsyncSession) -> int:
    """清理过期审计日志（异步），返回删除数。"""
    from datetime import timedelta
    cutoff = datetime.now(timezone.utc) - timedelta(days=_RETENTION_DAYS)
    if _RETENTION_DAYS <= 0:
        return 0
    try:
        old_logs = (await session.execute(
            select(AuditLog).where(AuditLog.created_at < cutoff)
        )).scalars().all()
        for log in old_logs:
            await session.delete(log)
        await session.commit()
        return len(old_logs)
    except Exception as e:
        logger.warning("清理审计日志失败: %s", e)
        return 0
