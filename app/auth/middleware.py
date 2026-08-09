"""RBAC 集中式权限中间件。

作为 FastAPI HTTP 中间件运行，在请求到达路由处理器之前：
1. 通过 permission_for_request(method, path) 推导当前路由所需权限
2. 从请求头提取 token → 查询 RBAC 用户
3. 检查用户是否持有该权限
4. 拒绝时返回 403 并写入审计日志

与 app/security.py 中的 security_middleware 协作：
- 本中间件作为最外层先执行
- 如果 RBAC 用户认证通过，在 request.state 标记 rbac_user，
  security_middleware 检测到此标记后跳过旧 token 鉴权
- 如果未匹配到 RBAC 用户，放行给 security_middleware 处理旧 token 认证
  （向后兼容 AUTOHUNTER_API_TOKEN / READ_TOKEN / OBSERVER_TOKEN）
"""
from __future__ import annotations

import logging

from fastapi import Request
from fastapi.responses import JSONResponse

from app.auth.rbac import (
    User,
    check_permission,
    get_current_user,
    permission_for_request,
)
from app.security import auth_enabled, resolve_role, token_from_headers

logger = logging.getLogger("autohunter.rbac.middleware")


async def _log_denied(
    request: Request,
    user: User | None,
    permission: str,
) -> None:
    """权限拒绝时写入审计日志（best-effort，失败不影响主流程）。"""
    try:
        from app.db.session import SessionLocal
        from app.audit import record_fail

        ip = request.client.host if request.client else ""
        ua = request.headers.get("user-agent", "")
        resource = f"{request.method} {request.url.path}"

        async with SessionLocal() as session:
            await record_fail(
                session,
                user_id=user.id if user else "",
                username=user.username if user else "",
                action=f"rbac_denied:{permission}",
                resource=resource,
                detail=f"缺少权限: {permission}",
                ip_address=ip,
                category="rbac",
                user_agent=ua,
            )
    except Exception as exc:
        logger.warning("写入 RBAC 拒绝审计日志失败: %s", exc)


async def rbac_middleware(request: Request, call_next):
    """RBAC 集中式权限检查中间件。

    执行流程：
    1. 推导当前路由所需权限（permission_for_request）
    2. 公共路径（空权限）直接放行
    3. 提取 token → 查询 RBAC 用户
    4. RBAC 用户存在 → 检查权限 → 通过则标记 request.state.rbac_user 放行，
       不通过则返回 403 + 审计日志
    5. 无 RBAC 用户 → 放行给旧 security_middleware 处理（向后兼容）
    """
    # 推导所需权限
    permission = permission_for_request(request.method, request.url.path)

    # 公共路径不需要权限检查
    if not permission:
        return await call_next(request)

    # 提取 token → 查询 RBAC 用户
    token = token_from_headers(request.headers)
    user = await get_current_user(token)

    if user:
        # RBAC 用户：检查权限
        if check_permission(user, permission):
            # 标记已通过 RBAC 授权，security_middleware 据此跳过旧 token 检查
            request.state.rbac_user = user
            return await call_next(request)

        # 权限不足：返回 403 + 审计日志
        await _log_denied(request, user, permission)
        return JSONResponse(
            {"detail": f"权限不足，需要 {permission} 权限"},
            status_code=403,
        )

    # 无 RBAC 用户：检查是否为旧环境变量 token（向后兼容）
    # 如果旧 token 有效，放行给 security_middleware 做后续处理
    if auth_enabled():
        role = resolve_role(token)
        if role is not None:
            # 旧 token 认证有效，放行
            return await call_next(request)

    # 未认证：放行给 security_middleware 统一处理 401
    # （security_middleware 会在 auth_enabled() 时返回 401）
    return await call_next(request)
