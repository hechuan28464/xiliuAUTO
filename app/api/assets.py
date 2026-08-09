"""融合版新增 API 路由：资产管理。

自研资产管理，Collector 产出的目标自动归档。
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Asset, Finding, to_cst_iso
from app.db.session import get_session

router = APIRouter(prefix="/api/assets", tags=["assets"])


@router.get("")
async def list_assets(
    session: AsyncSession = Depends(get_session),
    risk_level: str = Query("", description="按风险等级筛选"),
    status: str = Query("", description="按状态筛选"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    """列出资产，支持筛选和分页。"""
    stmt = select(Asset).order_by(Asset.created_at.desc())
    if risk_level:
        stmt = stmt.where(Asset.risk_level == risk_level)
    if status:
        stmt = stmt.where(Asset.status == status)
    stmt = stmt.limit(limit).offset(offset)
    results = await session.execute(stmt)
    assets = results.scalars().all()
    return {
        "items": [_asset_dict(a) for a in assets],
        "total": len(assets),
    }


@router.get("/stats")
async def asset_stats(session: AsyncSession = Depends(get_session)):
    """资产统计。"""
    total = await session.scalar(select(func.count(Asset.id)))
    high = await session.scalar(select(func.count(Asset.id)).where(Asset.risk_level.in_(["high", "critical"])))
    linked = await session.scalar(select(func.count(Asset.id)).where(Asset.linked_vulns > 0))
    return {
        "total": total or 0,
        "high_risk": high or 0,
        "linked_vulns": linked or 0,
    }


@router.get("/{asset_id}")
async def get_asset(asset_id: str, session: AsyncSession = Depends(get_session)):
    """获取单个资产详情。"""
    asset = await session.get(Asset, asset_id)
    if not asset:
        return {"error": "not found"}, 404
    return _asset_dict(asset)


def _asset_dict(a: Asset) -> dict:
    return {
        "id": a.id,
        "task_id": a.task_id or "",
        "host": a.host,
        "url": a.url,
        "ip": a.ip,
        "port": a.port,
        "service": a.service,
        "title": a.title,
        "tech_stack": a.tech_stack or [],
        "org": a.org,
        "is_edu": a.is_edu,
        "risk_level": a.risk_level,
        "status": a.status,
        "linked_vulns": a.linked_vulns,
        "notes": a.notes,
        "created_at": to_cst_iso(a.created_at),
        "updated_at": to_cst_iso(a.updated_at),
    }
