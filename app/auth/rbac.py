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
import logging
import os
import secrets
import string
import uuid
from datetime import datetime, timezone
from typing import Optional

import bcrypt
from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text, select
from sqlalchemy.orm import Mapped, mapped_column

from app.db.models import Base

logger = logging.getLogger("autohunter.rbac")

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
    # 审计记录增强字段
    category: Mapped[str] = mapped_column(String(50), default="", index=True)  # 分类：auth/task/vuln/config 等
    level: Mapped[str] = mapped_column(String(20), default="info")  # 级别：info/warn/error
    result: Mapped[str] = mapped_column(String(20), default="success", index=True)  # 结果：success/failure
    user_agent: Mapped[str] = mapped_column(String(512), default="")  # 客户端 UA
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)


# ---- 权限定义 ----
#
# 权限命名格式：module:action（如 task:read、vuln:write）。
# 旧版使用 module.action 格式（如 task.create），通过 _LEGACY_PERMISSION_MAP
# 自动归一化，保证向后兼容。

class Permission:
    # ---- 旧权限名（module.action 格式，向后兼容别名）----
    TASK_CREATE = "task.create"
    TASK_MANAGE = "task.manage"
    VULN_REVIEW = "vuln.review"
    VULN_VIEW = "vuln.view"
    CONFIG_UPDATE = "config.update"
    USER_MANAGE = "user.manage"
    AUDIT_VIEW = "audit.view"
    INTEL_MANAGE = "intel.manage"

    # ---- 新权限名（module:action 格式）----
    # 任务模块
    TASK_READ = "task:read"
    TASK_WRITE = "task:write"
    TASK_DELETE = "task:delete"
    # 漏洞模块
    VULN_READ = "vuln:read"
    VULN_WRITE = "vuln:write"
    VULN_DELETE = "vuln:delete"
    # 资产模块
    ASSET_READ = "asset:read"
    ASSET_WRITE = "asset:write"
    ASSET_DELETE = "asset:delete"
    # 审计模块
    AUDIT_READ = "audit:read"
    AUDIT_WRITE = "audit:write"
    AUDIT_DELETE = "audit:delete"
    # 用户模块
    USER_READ = "user:read"
    USER_WRITE = "user:write"
    USER_DELETE = "user:delete"
    # 配置模块
    CONFIG_READ = "config:read"
    CONFIG_WRITE = "config:write"
    CONFIG_DELETE = "config:delete"
    # 情报模块
    INTEL_READ = "intel:read"
    INTEL_WRITE = "intel:write"
    INTEL_DELETE = "intel:delete"
    # 通知模块
    NOTIFY_READ = "notify:read"
    NOTIFY_WRITE = "notify:write"
    NOTIFY_DELETE = "notify:delete"
    # HITL 人机协同审批模块
    HITL_READ = "hitl:read"
    HITL_WRITE = "hitl:write"
    HITL_DELETE = "hitl:delete"
    # 清扫模块
    KILLSWEEP_READ = "killsweep:read"
    KILLSWEEP_WRITE = "killsweep:write"
    KILLSWEEP_DELETE = "killsweep:delete"
    # 漏洞发现项模块
    FINDING_READ = "finding:read"
    FINDING_WRITE = "finding:write"
    FINDING_DELETE = "finding:delete"


# 旧权限名 → 新权限名映射（module.action → module:action）
_LEGACY_PERMISSION_MAP: dict[str, str] = {
    "task.create": Permission.TASK_WRITE,
    "task.manage": Permission.TASK_WRITE,
    "vuln.review": Permission.VULN_WRITE,
    "vuln.view": Permission.VULN_READ,
    "config.update": Permission.CONFIG_WRITE,
    "user.manage": Permission.USER_WRITE,
    "audit.view": Permission.AUDIT_READ,
    "intel.manage": Permission.INTEL_WRITE,
}

# 未映射路由的哨兵权限：fail-closed 策略下，未在路径映射表中登记的
# /api/ 路由默认返回此权限，仅 admin 角色持有，其他角色一律拒绝。
_UNMAPPED_PERMISSION = "_unmapped"


def _normalize_permission(permission: str) -> str:
    """将旧格式权限名（module.action）归一化为新格式（module:action）。

    已是新格式或未知权限名则原样返回。
    """
    return _LEGACY_PERMISSION_MAP.get(permission, permission)


ROLE_PERMISSIONS: dict[str, set[str]] = {
    "admin": {
        # 任务
        Permission.TASK_READ, Permission.TASK_WRITE, Permission.TASK_DELETE,
        # 漏洞
        Permission.VULN_READ, Permission.VULN_WRITE, Permission.VULN_DELETE,
        # 资产
        Permission.ASSET_READ, Permission.ASSET_WRITE, Permission.ASSET_DELETE,
        # 审计
        Permission.AUDIT_READ, Permission.AUDIT_WRITE, Permission.AUDIT_DELETE,
        # 用户
        Permission.USER_READ, Permission.USER_WRITE, Permission.USER_DELETE,
        # 配置
        Permission.CONFIG_READ, Permission.CONFIG_WRITE, Permission.CONFIG_DELETE,
        # 情报
        Permission.INTEL_READ, Permission.INTEL_WRITE, Permission.INTEL_DELETE,
        # 通知
        Permission.NOTIFY_READ, Permission.NOTIFY_WRITE, Permission.NOTIFY_DELETE,
        # HITL
        Permission.HITL_READ, Permission.HITL_WRITE, Permission.HITL_DELETE,
        # 清扫
        Permission.KILLSWEEP_READ, Permission.KILLSWEEP_WRITE, Permission.KILLSWEEP_DELETE,
        # 漏洞发现项
        Permission.FINDING_READ, Permission.FINDING_WRITE, Permission.FINDING_DELETE,
        # 未映射路由（fail-closed：仅 admin 可访问未登记路由）
        _UNMAPPED_PERMISSION,
    },
    "operator": {
        # 任务：创建/管理/删除
        Permission.TASK_READ, Permission.TASK_WRITE, Permission.TASK_DELETE,
        # 漏洞：复审/查看
        Permission.VULN_READ, Permission.VULN_WRITE, Permission.VULN_DELETE,
        # 资产：只读
        Permission.ASSET_READ, Permission.ASSET_WRITE,
        # 审计：只读
        Permission.AUDIT_READ,
        # 用户：只读
        Permission.USER_READ,
        # 配置：只读
        Permission.CONFIG_READ,
        # 情报：管理
        Permission.INTEL_READ, Permission.INTEL_WRITE, Permission.INTEL_DELETE,
        # 通知：读写
        Permission.NOTIFY_READ, Permission.NOTIFY_WRITE,
        # HITL：读写
        Permission.HITL_READ, Permission.HITL_WRITE,
        # 清扫：读写
        Permission.KILLSWEEP_READ, Permission.KILLSWEEP_WRITE,
        # 漏洞发现项：读写
        Permission.FINDING_READ, Permission.FINDING_WRITE,
    },
    "reviewer": {
        # 任务：只读
        Permission.TASK_READ,
        # 漏洞：复审（读写）
        Permission.VULN_READ, Permission.VULN_WRITE,
        # 资产：只读
        Permission.ASSET_READ,
        # 审计：只读
        Permission.AUDIT_READ,
        # 用户：只读
        Permission.USER_READ,
        # HITL：读写（复审人员可处理审批）
        Permission.HITL_READ, Permission.HITL_WRITE,
        # 漏洞发现项：读写（复审核心数据）
        Permission.FINDING_READ, Permission.FINDING_WRITE,
        # 清扫：只读
        Permission.KILLSWEEP_READ,
    },
    "viewer": {
        # 任务：只读
        Permission.TASK_READ,
        # 漏洞：只读
        Permission.VULN_READ,
        # 资产：只读
        Permission.ASSET_READ,
        # 审计：只读
        Permission.AUDIT_READ,
        # 用户：只读
        Permission.USER_READ,
        # HITL：只读
        Permission.HITL_READ,
        # 漏洞发现项：只读
        Permission.FINDING_READ,
        # 清扫：只读
        Permission.KILLSWEEP_READ,
    },
}


# ---- CRUD 权限自动推导 ----

def crud_permission(method: str, module: str) -> str:
    """根据 HTTP 方法和模块名推导 CRUD 权限字符串。

    - GET / HEAD / OPTIONS → module:read
    - DELETE → module:delete
    - POST / PUT / PATCH → module:write
    """
    method_upper = method.upper()
    if method_upper in ("GET", "HEAD", "OPTIONS"):
        action = "read"
    elif method_upper == "DELETE":
        action = "delete"
    else:
        action = "write"
    return f"{module}:{action}"


# ---- 路由权限推导 ----

# 公共路径前缀和确切路径：不需要任何权限检查
_PUBLIC_PATH_PREFIXES: tuple[str, ...] = (
    "/api/auth/",
    "/api/about",
)
_PUBLIC_PATHS: frozenset[str] = frozenset({
    "/health",
    "/",
    "/favicon.svg",
    "/favicon.ico",
    "/api/auth/status",
    "/api/about",
    "/docs",
    "/redoc",
    "/openapi.json",
})

# /api/{segment} → 模块名映射
_SEGMENT_MODULE_MAP: dict[str, str] = {
    "tasks": "task",
    "vulns": "vuln",
    "assets": "asset",
    "audit": "audit",
    "users": "user",
    "settings": "config",
    "intel": "intel",
    "notify": "notify",
    "hitl": "hitl",
    "runtime-logs": "audit",   # 运行日志归入审计模块
    "update": "config",         # 系统更新归入配置模块
    "findings": "vuln",          # 漏洞发现项归入漏洞模块
    "results": "finding",        # /api/results/* 归入漏洞发现项模块
}


def _is_public_path(path: str) -> bool:
    """判断是否为公共路径（不需要权限检查）。"""
    if path in _PUBLIC_PATHS:
        return True
    for prefix in _PUBLIC_PATH_PREFIXES:
        if path.startswith(prefix):
            return True
    return False


def permission_for_request(method: str, path: str) -> str:
    """根据 HTTP 方法和请求路径自动推导所需权限。

    返回值：
    - 空字符串 ""：公共路径，不需要权限检查（放行）
    - "module:action"：已映射路由，需要对应权限
    - _UNMAPPED_PERMISSION：未映射的 /api/ 路由（fail-closed，仅 admin 可访问）
    """
    # 公共路径直接放行
    if _is_public_path(path):
        return ""

    # 非 /api/ 路径（静态资源等）放行
    if not path.startswith("/api/"):
        return ""

    # 解析路径段
    parts = [p for p in path.split("/") if p]
    if len(parts) < 2:
        return _UNMAPPED_PERMISSION  # /api/ 本身未映射

    segment = parts[1]  # /api/{segment}/...

    # 特殊子路径处理：tasks 下的 killsweeps / findings / escalations
    if segment == "tasks":
        if "killsweeps" in parts:
            module = "killsweep"
        elif "findings" in parts:
            module = "vuln"
        elif "escalations" in parts:
            module = "vuln"
        else:
            module = "task"
    elif segment == "vulns":
        # /api/vulns/lifecycle/* 仍归入漏洞模块
        module = "vuln"
    else:
        # 常规模块映射
        module = _SEGMENT_MODULE_MAP.get(segment)

    if module is None:
        # fail-closed：未映射路由返回哨兵权限，仅 admin 持有
        return _UNMAPPED_PERMISSION

    return crud_permission(method, module)


# ---- 密码哈希 ----

def hash_password(password: str) -> str:
    """使用 bcrypt 对密码进行哈希，返回格式为 $2b$... 的哈希字符串。"""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, stored: str) -> bool:
    """验证密码。

    优先使用 bcrypt 验证；如果 stored 是旧的 sha256+salt 格式（含 "$" 但不是 bcrypt 前缀），
    则回退到旧逻辑验证，保证向后兼容。
    """
    if not stored:
        return False
    # bcrypt 哈希以 $2a$ / $2b$ / $2y$ 开头
    if stored.startswith("$2a$") or stored.startswith("$2b$") or stored.startswith("$2y$"):
        try:
            return bcrypt.checkpw(password.encode("utf-8"), stored.encode("utf-8"))
        except (ValueError, TypeError):
            return False
    # 旧 sha256+salt 格式：{salt}${hash}
    if "$" in stored:
        salt, hashed = stored.split("$", 1)
        return hashlib.sha256(f"{salt}{password}".encode()).hexdigest() == hashed
    return False


def _generate_strong_password(length: int = 16) -> str:
    """生成指定位数的强随机密码（大小写字母+数字+特殊字符）。"""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*-_=+"
    return "".join(secrets.choice(alphabet) for _ in range(length))


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
    """检查用户是否有指定权限（纯内存操作，无需异步）。

    自动将旧格式权限名（module.action）归一化为新格式（module:action），
    保证向后兼容。
    """
    if not user:
        return False
    # 归一化旧权限名
    permission = _normalize_permission(permission)
    perms = ROLE_PERMISSIONS.get(user.role, set())
    return permission in perms


async def revoke_user_sessions(user: User) -> str:
    """使用户旧会话失效：重新生成 api_token 并返回新 token。

    当前认证体系基于 api_token，重新生成 token 后旧 token 立即失效。
    """
    from app.db.session import SessionLocal
    async with SessionLocal() as session:
        db_user = await session.get(User, user.id)
        if not db_user:
            return ""
        db_user.api_token = secrets.token_hex(32)
        await session.commit()
        return db_user.api_token


async def change_password(user: User, new_password: str) -> str:
    """修改用户密码并重新生成 api_token（旧 token 随之失效）。

    返回新的 api_token。
    """
    from app.db.session import SessionLocal
    async with SessionLocal() as session:
        db_user = await session.get(User, user.id)
        if not db_user:
            return ""
        db_user.password_hash = hash_password(new_password)
        db_user.api_token = secrets.token_hex(32)
        await session.commit()
        return db_user.api_token


async def create_default_roles():
    """初始化默认角色和 admin 用户（异步，首次启动时调用）。

    密码来源优先级：
    1. 环境变量 XILIU_ADMIN_PASSWORD
    2. 未设置时自动生成 16 位强随机密码并打印到日志
    """
    from app.db.session import SessionLocal
    async with SessionLocal() as session:
        admin = (await session.execute(select(User).where(User.role == "admin"))).scalar_one_or_none()
        if admin:
            return
        admin_password = os.environ.get("XILIU_ADMIN_PASSWORD", "").strip()
        if not admin_password:
            admin_password = _generate_strong_password(16)
            logger.warning(
                "未设置 XILIU_ADMIN_PASSWORD 环境变量，已为 admin 用户生成随机密码: %s", admin_password
            )
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
