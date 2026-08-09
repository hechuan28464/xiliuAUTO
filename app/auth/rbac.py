"""RBAC 核心：用户/角色/权限数据模型与异步会话管理（自研）。

角色：
- admin: 全权限（创建/管理任务、复审漏洞、配置系统、管理用户）
- operator: 创建/管理任务、复审漏洞
- reviewer: 只能复审漏洞（不能创建任务/改配置）
- viewer: 只读看板

替代原版简单 Token 认证，保留 Token 向后兼容。
全部使用异步 AsyncSession，与主项目 session 体系一致。
"""
from __future__ import annotations

import hashlib
import os
import secrets
import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text, select
from sqlalchemy.orm import Mapped, mapped_column

from app.db.models import Base

# ---- 数据模型 ----

class User(Base):
    __tablename__ = "rbac_users"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    username: Mapped[str] = mapped_column(String(100), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), default="")
    role: Mapped[str] = mapped_column(String(50), default="viewer")  # admin/operator/reviewer/viewer
    api_token: Mapped[str] = mapped_column(String(64), unique=True, nullable=True, index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_login: Mapped[datetime] = mapped_column(DateTime, nullable=True)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    user_id: Mapped[str] = mapped_column(String(32), index=True)
    username: Mapped[str] = mapped_column(String(100), default="")
    action: Mapped[str] = mapped_column(String(200))
    resource: Mapped[str] = mapped_column(String(300), default="")
    detail: Mapped[str] = mapped_column(Text, default="")
    ip_address: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)


# ---- 权限定义 ----

class Permission:
    TASK_CREATE = "task.create"
    TASK_MANAGE = "task.manage"
    VULN_REVIEW = "vuln.review"
    VULN_VIEW = "vuln.view"
    CONFIG_UPDATE = "config.update"
    USER_MANAGE = "user.manage"
    AUDIT_VIEW = "audit.view"
    INTEL_MANAGE = "intel.manage"


ROLE_PERMISSIONS: dict[str, set[str]] = {
    "admin": {
        Permission.TASK_CREATE, Permission.TASK_MANAGE, Permission.VULN_REVIEW,
        Permission.VULN_VIEW, Permission.CONFIG_UPDATE, Permission.USER_MANAGE,
        Permission.AUDIT_VIEW, Permission.INTEL_MANAGE,
    },
    "operator": {
        Permission.TASK_CREATE, Permission.TASK_MANAGE, Permission.VULN_REVIEW,
        Permission.VULN_VIEW, Permission.INTEL_MANAGE,
    },
    "reviewer": {
        Permission.VULN_REVIEW, Permission.VULN_VIEW,
    },
    "viewer": {
        Permission.VULN_VIEW,
    },
}


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    hashed = hashlib.sha256(f"{salt}{password}".encode()).hexdigest()
    return f"{salt}${hashed}"


def verify_password(password: str, stored: str) -> bool:
    if "$" not in stored:
        return False
    salt, hashed = stored.split("$", 1)
    return hashlib.sha256(f"{salt}{password}".encode()).hexdigest() == hashed


def _uuid() -> str:
    return uuid.uuid4().hex


# ---- 异步用户管理 ----

async def create_user(username: str, password: str, role: str = "viewer") -> Optional[User]:
    """创建用户（异步）。"""
    from app.db.session import SessionLocal
    async with SessionLocal() as session:
        existing = (await session.execute(select(User).where(User.username == username))).scalar_one_or_none()
        if existing:
            return None
        user = User(
            id=_uuid(),
            username=username,
            password_hash=hash_password(password),
            role=role,
            api_token=secrets.token_hex(32),
            is_active=True,
        )
        session.add(user)
        await session.commit()
        return user


async def authenticate(username: str, password: str) -> Optional[User]:
    """用户名密码认证（异步）。"""
    from app.db.session import SessionLocal
    async with SessionLocal() as session:
        user = (await session.execute(select(User).where(User.username == username))).scalar_one_or_none()
        if not user or not user.is_active:
            return None
        if not verify_password(password, user.password_hash):
            return None
        user.last_login = datetime.now(timezone.utc)
        await session.commit()
        return user


async def get_current_user(token: str | None, username: str | None = None) -> Optional[User]:
    """通过 Token 或用户名获取用户（异步）。"""
    from app.db.session import SessionLocal
    async with SessionLocal() as session:
        if username:
            return (await session.execute(select(User).where(User.username == username))).scalar_one_or_none()
        if token:
            user = (await session.execute(select(User).where(User.api_token == token))).scalar_one_or_none()
            if user:
                return user
            env_token = os.environ.get("AUTOHUNTER_API_TOKEN", "")
            if token == env_token:
                admin = (await session.execute(select(User).where(User.role == "admin"))).scalar_one_or_none()
                if admin:
                    return admin
    return None


def check_permission(user: User | None, permission: str) -> bool:
    """检查用户是否有指定权限（纯内存操作，无需异步）。"""
    if not user:
        return False
    perms = ROLE_PERMISSIONS.get(user.role, set())
    return permission in perms


async def create_default_roles():
    """初始化默认角色和 admin 用户（异步，首次启动时调用）。"""
    from app.db.session import SessionLocal
    async with SessionLocal() as session:
        admin = (await session.execute(select(User).where(User.role == "admin"))).scalar_one_or_none()
        if admin:
            return
        admin_password = os.environ.get("XILIU_ADMIN_PASSWORD", "admin123")
        user = User(
            id=_uuid(),
            username="admin",
            password_hash=hash_password(admin_password),
            role="admin",
            api_token=os.environ.get("AUTOHUNTER_API_TOKEN") or secrets.token_hex(32),
            is_active=True,
        )
        session.add(user)
        await session.commit()
