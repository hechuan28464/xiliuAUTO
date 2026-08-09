"""融合版新增 API 路由：HITL 审批管理。

管理人机协同审批请求。
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from app.auth.hitl import list_pending, resolve_approval, check_approval
from app.security import token_from_headers
from app.auth.rbac import Permission, check_permission, get_current_user

router = APIRouter(prefix="/api/hitl", tags=["hitl"])


class ResolveRequest(BaseModel):
    approved: bool
    reviewer: str = ""
    comment: str = ""


@router.get("/pending")
async def get_pending_approvals():
    """获取待审批列表。"""
    return {"items": list_pending()}


@router.get("/{approval_id}")
async def get_approval_status(approval_id: str):
    """查询单个审批状态。"""
    req = check_approval(approval_id)
    if not req:
        raise HTTPException(404, "审批请求不存在")
    return {"id": approval_id, **req}


@router.post("/{approval_id}/resolve")
async def resolve_approval_api(approval_id: str, req: ResolveRequest, request: Request):
    """审批决议。"""
    token = token_from_headers(request.headers)
    current = await get_current_user(token)
    if not current or not check_permission(current, Permission.VULN_REVIEW):
        raise HTTPException(403, "需要漏洞复审权限")

    ok = resolve_approval(approval_id, req.approved, req.reviewer, req.comment)
    if not ok:
        raise HTTPException(404, "审批请求不存在或已处理")
    return {
        "ok": True,
        "status": "approved" if req.approved else "rejected",
        "approval_id": approval_id,
    }
