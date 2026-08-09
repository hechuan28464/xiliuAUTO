"""融合版新增 API 路由：用户管理（RBAC）。

从 CyberStrikeAI 移植用户管理能力。
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.rbac import (
    Permission,
    ROLE_PERMISSIONS,
    User,
    check_permission,
    create_user,
    get_current_user,
    hash_password,
)
from app.db.session import get_session
from app.db.models import to_cst_iso
from app.security import token_from_headers

router = APIRouter(prefix="/api/users", tags=["users"])


class CreateUserRequest(BaseModel):
    username: str
    password: str
    role: str = "viewer"


class UpdateRoleRequest(BaseModel):
    role: str


@router.get("")
async def list_users(session: AsyncSession = Depends(get_session)):
    """列出所有用户。"""
    results = await session.execute(select(User).order_by(User.created_at.desc()))
    users = results.scalars().all()
    return {
        "items": [_user_dict(u) for u in users],
        "roles": list(ROLE_PERMISSIONS.keys()),
    }


@router.post("")
async def create_user_api(req: CreateUserRequest, request: Request,
                          session: AsyncSession = Depends(get_session)):
    """创建用户。"""
    token = token_from_headers(request.headers)
    current = await get_current_user(token)
    if not current or not check_permission(current, Permission.USER_MANAGE):
        raise HTTPException(403, "需要用户管理权限")

    if req.role not in ROLE_PERMISSIONS:
        raise HTTPException(400, f"无效角色: {req.role}")

    user = await create_user(req.username, req.password, req.role)
    if not user:
        raise HTTPException(409, "用户名已存在")
    return {"ok": True, "user": _user_dict(user)}


@router.put("/{user_id}/role")
async def update_role(user_id: str, req: UpdateRoleRequest, request: Request,
                      session: AsyncSession = Depends(get_session)):
    """修改用户角色。"""
    token = token_from_headers(request.headers)
    current = await get_current_user(token)
    if not current or not check_permission(current, Permission.USER_MANAGE):
        raise HTTPException(403, "需要用户管理权限")

    if req.role not in ROLE_PERMISSIONS:
        raise HTTPException(400, f"无效角色: {req.role}")

    user = await session.get(User, user_id)
    if not user:
        raise HTTPException(404, "用户不存在")
    user.role = req.role
    await session.commit()
    return {"ok": True, "user": _user_dict(user)}


def _user_dict(u: User) -> dict:
    return {
        "id": u.id,
        "username": u.username,
        "role": u.role,
        "is_active": u.is_active,
        "created_at": to_cst_iso(u.created_at),
        "last_login": to_cst_iso(u.last_login) if u.last_login else "",
        "api_token": (u.api_token or "")[:16] + "..." if u.api_token else "",
    }
