"""融合版新增 API 路由：审计日志。

从 CyberStrikeAI 移植审计日志能力。
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.rbac import AuditLog
from app.db.session import get_session
from app.db.models import to_cst_iso

router = APIRouter(prefix="/api/audit", tags=["audit"])


@router.get("")
async def list_audit_logs(
    session: AsyncSession = Depends(get_session),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    action: str = Query("", description="按操作类型筛选"),
    username: str = Query("", description="按用户名筛选"),
):
    """查询审计日志。"""
    stmt = select(AuditLog).order_by(AuditLog.created_at.desc())
    if action:
        stmt = stmt.where(AuditLog.action.like(f"%{action}%"))
    if username:
        stmt = stmt.where(AuditLog.username == username)
    stmt = stmt.limit(limit).offset(offset)
    results = await session.execute(stmt)
    logs = results.scalars().all()
    return {
        "items": [_log_dict(l) for l in logs],
        "total": len(logs),
    }


def _log_dict(l: AuditLog) -> dict:
    return {
        "id": l.id,
        "user_id": l.user_id,
        "username": l.username,
        "action": l.action,
        "resource": l.resource,
        "detail": (l.detail or "")[:500],
        "ip_address": l.ip_address,
        "created_at": to_cst_iso(l.created_at),
    }
