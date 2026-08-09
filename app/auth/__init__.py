"""RBAC 权限模块：用户/角色/权限管理。

角色：
- admin: 全权限（创建/管理任务、复审漏洞、配置系统、管理用户）
- operator: 创建/管理任务、复审漏洞
- reviewer: 只能复审漏洞（不能创建任务/改配置）
- viewer: 只读看板

替代原版简单 Token 认证，保留 Token 向后兼容。
全部异步，与主项目 session 体系一致。
"""
from app.auth.rbac import (
    AuditLog,
    Permission,
    ROLE_PERMISSIONS,
    User,
    authenticate,
    check_permission,
    create_default_roles,
    create_user,
    get_current_user,
    hash_password,
    verify_password,
)

__all__ = [
    "AuditLog",
    "Permission",
    "ROLE_PERMISSIONS",
    "User",
    "authenticate",
    "check_permission",
    "create_default_roles",
    "create_user",
    "get_current_user",
    "hash_password",
    "verify_password",
]
