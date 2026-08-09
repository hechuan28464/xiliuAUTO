"""融合版新增 API 路由：漏洞生命周期管理。

在原有 vulns API 基础上增加漏洞生命周期流转。
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Finding, Review, VulnLifecycle, to_cst_iso
from app.db.session import get_session

router = APIRouter(prefix="/api/vulns/lifecycle", tags=["vuln-lifecycle"])


class UpdateLifecycleRequest(BaseModel):
    lifecycle_status: str  # submitted/reviewed/accepted/reported/fixed/closed/rejected
    report_url: str = ""
    note: str = ""


@router.get("")
async def list_lifecycles(
    session: AsyncSession = Depends(get_session),
    status: str = Query("", description="按生命周期状态筛选"),
    limit: int = Query(100, ge=1, le=500),
):
    """列出漏洞生命周期记录。"""
    stmt = select(VulnLifecycle, Finding).join(
        Finding, VulnLifecycle.finding_id == Finding.id
    ).order_by(VulnLifecycle.created_at.desc())
    if status:
        stmt = stmt.where(VulnLifecycle.lifecycle_status == status)
    stmt = stmt.limit(limit)
    results = await session.execute(stmt)
    items = []
    for lc, finding in results:
        items.append({
            "id": lc.id,
            "finding_id": lc.finding_id,
            "lifecycle_status": lc.lifecycle_status,
            "report_url": lc.report_url,
            "fix_verified": lc.fix_verified,
            "timeline": lc.timeline or [],
            "title": finding.title,
            "vuln_type": finding.vuln_type,
            "target_url": finding.target_url,
            "severity_claimed": finding.severity_claimed,
            "created_at": to_cst_iso(lc.created_at),
            "updated_at": to_cst_iso(lc.updated_at),
        })
    return {"items": items, "total": len(items)}


@router.get("/stats")
async def lifecycle_stats(session: AsyncSession = Depends(get_session)):
    """漏洞生命周期统计。"""
    # 按状态分组计数
    stmt = select(
        VulnLifecycle.lifecycle_status,
        func.count(VulnLifecycle.id)
    ).group_by(VulnLifecycle.lifecycle_status)
    results = await session.execute(stmt)
    status_counts = {row[0]: row[1] for row in results}

    # 按严重程度统计
    severity_stmt = select(
        Finding.severity_claimed,
        func.count(Finding.id)
    ).join(VulnLifecycle, VulnLifecycle.finding_id == Finding.id
    ).group_by(Finding.severity_claimed)
    sev_results = await session.execute(severity_stmt)
    severity_counts = {row[0]: row[1] for row in sev_results}

    return {
        "by_status": status_counts,
        "by_severity": severity_counts,
        "total": sum(status_counts.values()),
    }


@router.put("/{finding_id}")
async def update_lifecycle(
    finding_id: str,
    req: UpdateLifecycleRequest,
    session: AsyncSession = Depends(get_session),
):
    """更新漏洞生命周期状态。"""
    lc = await session.execute(
        select(VulnLifecycle).where(VulnLifecycle.finding_id == finding_id)
    )
    lifecycle = lc.scalar_one_or_none()
    if not lifecycle:
        # 自动创建
        lifecycle = VulnLifecycle(finding_id=finding_id, lifecycle_status=req.lifecycle_status)
        session.add(lifecycle)
    else:
        lifecycle.lifecycle_status = req.lifecycle_status
        if req.report_url:
            lifecycle.report_url = req.report_url
        if req.lifecycle_status == "fixed":
            from datetime import datetime, timezone
            lifecycle.fix_verified = True
            lifecycle.fix_verified_at = datetime.now(timezone.utc)

    # 添加时间线
    from datetime import datetime, timezone
    timeline = lifecycle.timeline or []
    timeline.append({
        "status": req.lifecycle_status,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "note": req.note,
    })
    lifecycle.timeline = timeline
    await session.commit()
    return {"ok": True, "lifecycle_status": req.lifecycle_status}
