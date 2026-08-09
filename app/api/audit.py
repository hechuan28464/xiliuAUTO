"""融合版新增 API 路由：审计日志。

自研审计日志：支持多维度查询、统计聚合、CSV 导出。
"""
from __future__ import annotations

import csv
import io
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import count_logs, query_logs, query_stats
from app.db.session import get_session

router = APIRouter(prefix="/api/audit", tags=["audit"])


def _parse_dt(s: str) -> Optional[datetime]:
    """解析 ISO 格式日期时间字符串，无时区时按 UTC 处理，失败返回 None。"""
    if not s:
        return None
    try:
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        return None


@router.get("/stats")
async def audit_stats(session: AsyncSession = Depends(get_session)):
    """审计统计：按分类/结果/级别分组计数 + 按天时间趋势。"""
    return await query_stats(session)


@router.get("/export")
async def export_audit_logs(
    session: AsyncSession = Depends(get_session),
    limit: int = Query(1000, ge=1, le=10000),
    category: str = Query("", description="按分类筛选"),
    level: str = Query("", description="按级别筛选"),
    result: str = Query("", description="按结果筛选"),
    resource_type: str = Query("", description="按资源类型筛选（前缀匹配）"),
    resource_id: str = Query("", description="按资源 ID 筛选（模糊匹配）"),
    since: str = Query("", description="起始时间（ISO 格式）"),
    until: str = Query("", description="截止时间（ISO 格式）"),
    q: str = Query("", description="全文搜索"),
):
    """导出审计日志为 CSV（UTF-8 BOM，Excel 兼容）。"""
    since_dt = _parse_dt(since)
    until_dt = _parse_dt(until)
    logs = await query_logs(
        session,
        limit=limit,
        offset=0,
        category_filter=category,
        result_filter=result,
        level_filter=level,
        resource_type=resource_type,
        resource_id=resource_id,
        since=since_dt,
        until=until_dt,
        q=q,
        truncate_detail=False,
    )
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "id", "created_at", "user_id", "username", "action",
        "resource", "category", "level", "result",
        "ip_address", "user_agent", "detail",
    ])
    for log in logs:
        writer.writerow([
            log["id"], log["created_at"], log["user_id"], log["username"],
            log["action"], log["resource"], log["category"], log["level"],
            log["result"], log["ip_address"], log["user_agent"], log["detail"],
        ])
    # 加 UTF-8 BOM 头，让 Excel 正确识别编码
    csv_bytes = b"\xef\xbb\xbf" + output.getvalue().encode("utf-8")
    return Response(
        content=csv_bytes,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=audit_logs.csv"},
    )


@router.get("")
async def list_audit_logs(
    session: AsyncSession = Depends(get_session),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    action: str = Query("", description="按操作类型筛选（模糊匹配）"),
    username: str = Query("", description="按用户名筛选（精确匹配）"),
    category: str = Query("", description="按分类筛选：auth/task/vuln/config 等"),
    level: str = Query("", description="按级别筛选：info/warn/error"),
    result: str = Query("", description="按结果筛选：success/failure"),
    resource_type: str = Query("", description="按资源类型筛选（前缀匹配）"),
    resource_id: str = Query("", description="按资源 ID 筛选（模糊匹配）"),
    since: str = Query("", description="起始时间（ISO 格式）"),
    until: str = Query("", description="截止时间（ISO 格式）"),
    q: str = Query("", description="全文搜索（匹配 action/resource/detail/username）"),
):
    """多维度查询审计日志，支持分页，返回所有审计字段。"""
    since_dt = _parse_dt(since)
    until_dt = _parse_dt(until)
    logs = await query_logs(
        session,
        limit=limit,
        offset=offset,
        action_filter=action,
        username_filter=username,
        category_filter=category,
        result_filter=result,
        level_filter=level,
        resource_type=resource_type,
        resource_id=resource_id,
        since=since_dt,
        until=until_dt,
        q=q,
    )
    total = await count_logs(
        session,
        action_filter=action,
        username_filter=username,
        category_filter=category,
        result_filter=result,
        level_filter=level,
        resource_type=resource_type,
        resource_id=resource_id,
        since=since_dt,
        until=until_dt,
        q=q,
    )
    return {
        "items": logs,
        "total": total,
        "limit": limit,
        "offset": offset,
    }
