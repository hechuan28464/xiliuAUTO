"""审计日志模块：记录所有关键操作（自研）。

全部异步，与主项目 session 体系一致。
提供敏感信息递归脱敏、失败审计节流、会话指纹、后台定时清理等能力。
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.rbac import AuditLog
from app.db.models import to_cst_iso

logger = logging.getLogger("autohunter.audit")

_RETENTION_DAYS = int(os.environ.get("AUDIT_RETENTION_DAYS", "15"))
# 失败审计默认冷却秒数
_AUTH_FAILURE_COOLDOWN = float(os.environ.get("AUDIT_AUTH_FAILURE_COOLDOWN", "60"))

# 敏感 key 子串：命中即脱敏（参考 CyberStrikeAI sanitize.go）
SENSITIVE_KEY_SUBSTRINGS = [
    "password", "api_key", "apikey", "secret", "token",
    "authorization", "credential", "private_key", "access_key",
]


# ==================== 敏感信息递归脱敏 ====================

def _is_sensitive_key(key: str) -> bool:
    """判断 key 是否包含敏感子串（大小写不敏感）。"""
    if not key:
        return False
    kl = key.lower()
    return any(sub in kl for sub in SENSITIVE_KEY_SUBSTRINGS)


def _sanitize_value(key: str, value: Any) -> Any:
    """递归脱敏：key 含敏感子串则值替换为 ***，否则递归处理 dict/list。"""
    if _is_sensitive_key(key):
        return "***"
    if isinstance(value, dict):
        return {k: _sanitize_value(k, v) for k, v in value.items()}
    if isinstance(value, list):
        return [_sanitize_value(key, v) for v in value]
    return value


def sanitize_detail(detail: dict, max_bytes: int = 8192) -> dict:
    """敏感信息递归脱敏并按字节截断。

    - 递归处理 dict/list，key 含敏感子串的值替换为 "***"
    - 序列化后超过 max_bytes 则返回 {"_truncated": True, "_preview": ...}
    """
    if not isinstance(detail, dict):
        return detail
    if max_bytes <= 0:
        max_bytes = 8192
    cleaned = _sanitize_value("", detail)
    if not isinstance(cleaned, dict):
        return {"value": cleaned}
    try:
        serialized = json.dumps(cleaned, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        return cleaned
    if len(serialized.encode("utf-8")) > max_bytes:
        return {"_truncated": True, "_preview": serialized[:max_bytes]}
    return cleaned


# ==================== 失败审计节流 ====================

class FailureThrottle:
    """失败审计节流器：对高频失败操作去重，避免日志爆炸。

    线程安全：threading.Lock 保护内部 dict。
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._last: dict[str, float] = {}

    def allow(self, key: str, cooldown: float = 60.0) -> bool:
        """判断该 key 是否允许写入。冷却期内返回 False。

        - key 为空或 cooldown<=0 时直接放行
        - 内部 dict 超 4096 条时清理过期条目
        """
        if not key or cooldown <= 0:
            return True
        now = time.monotonic()
        with self._lock:
            prev = self._last.get(key)
            if prev is not None and (now - prev) < cooldown:
                return False
            self._last[key] = now
            # 超 4096 条时清理过期条目（超过 cooldown*2 视为过期）
            if len(self._last) > 4096:
                cutoff = now - cooldown * 2
                stale = [k for k, ts in self._last.items() if ts < cutoff]
                for k in stale:
                    self._last.pop(k, None)
            return True


# 模块级单例
_failure_throttle = FailureThrottle()

# 需要节流的 auth 失败操作（参考 CyberStrikeAI throttle.go）
_THROTTLED_AUTH_ACTIONS = {"login", "change_password"}


def _is_auth_failure_throttled(category: str, action: str) -> bool:
    """是否对该 category/action 组合进行失败节流。"""
    if category != "auth":
        return False
    return action in _THROTTLED_AUTH_ACTIONS


def _auth_failure_key(category: str, action: str, ip_address: str) -> str:
    """构建按 IP 维度的失败节流 key。"""
    return f"{category}:{action}:{ip_address or 'unknown'}"


# ==================== 会话指纹 ====================

def session_hint(token: str) -> str:
    """返回 token 的 sha256 前 8 位作为会话指纹（不可逆）。"""
    if not token:
        return ""
    token = token.strip()
    if not token:
        return ""
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    return digest[:8]


# ==================== 审计记录 ====================

async def log_action(
    session: AsyncSession,
    user_id: str = "",
    username: str = "",
    action: str = "",
    resource: str = "",
    detail: str | dict = "",
    ip_address: str = "",
    category: str = "",
    level: str = "",
    result: str = "",
    user_agent: str = "",
) -> None:
    """记录一条审计日志（异步）。

    - result 为空默认 success
    - level 为空根据 result 推断（failure→warn, success→info）
    - detail 为 dict 时调用 sanitize_detail 脱敏后序列化为 JSON 字符串
    - auth 类别的 login/change_password 失败操作按 IP 节流
    """
    # 自动填充默认值
    if not result:
        result = "success"
    if not level:
        level = "warn" if result == "failure" else "info"

    # 失败节流：只对 auth 类别的 login/change_password 失败操作做节流
    if result == "failure" and _is_auth_failure_throttled(category, action):
        key = _auth_failure_key(category, action, ip_address)
        if not _failure_throttle.allow(key, _AUTH_FAILURE_COOLDOWN):
            logger.debug("审计失败日志被节流: %s", key)
            return

    # detail 脱敏：dict 时递归脱敏并序列化
    if isinstance(detail, dict):
        sanitized = sanitize_detail(detail)
        try:
            detail = json.dumps(sanitized, ensure_ascii=False, default=str)
        except (TypeError, ValueError):
            detail = str(sanitized)

    try:
        log = AuditLog(
            id=uuid.uuid4().hex,
            user_id=user_id,
            username=username,
            action=action,
            resource=(resource or "")[:300],
            detail=(detail or "")[:8000],
            ip_address=(ip_address or "")[:64],
            category=(category or "")[:50],
            level=(level or "info")[:20],
            result=(result or "success")[:20],
            user_agent=(user_agent or "")[:512],
        )
        session.add(log)
        await session.commit()
    except Exception as e:
        logger.warning("审计日志写入失败: %s", e)


async def record_ok(
    session: AsyncSession,
    user_id: str = "",
    username: str = "",
    action: str = "",
    resource: str = "",
    detail: str | dict = "",
    ip_address: str = "",
    category: str = "",
    user_agent: str = "",
) -> None:
    """记录成功审计日志的快捷方法。"""
    await log_action(
        session,
        user_id=user_id,
        username=username,
        action=action,
        resource=resource,
        detail=detail,
        ip_address=ip_address,
        category=category,
        result="success",
        level="info",
        user_agent=user_agent,
    )


async def record_fail(
    session: AsyncSession,
    user_id: str = "",
    username: str = "",
    action: str = "",
    resource: str = "",
    detail: str | dict = "",
    ip_address: str = "",
    category: str = "",
    level: str = "",
    user_agent: str = "",
) -> None:
    """记录失败审计日志的快捷方法（auth 类别 login/change_password 自动节流）。"""
    await log_action(
        session,
        user_id=user_id,
        username=username,
        action=action,
        resource=resource,
        detail=detail,
        ip_address=ip_address,
        category=category,
        result="failure",
        level=level or "warn",
        user_agent=user_agent,
    )


# ==================== 查询与清理 ====================

def _apply_filters(
    stmt,
    action_filter: str = "",
    username_filter: str = "",
    category_filter: str = "",
    result_filter: str = "",
    level_filter: str = "",
    resource_type: str = "",
    resource_id: str = "",
    since: datetime | None = None,
    until: datetime | None = None,
    q: str = "",
):
    """为查询语句追加多维度过滤条件（不含 limit/offset/order_by）。"""
    if action_filter:
        stmt = stmt.where(AuditLog.action.like(f"%{action_filter}%"))
    if username_filter:
        stmt = stmt.where(AuditLog.username == username_filter)
    if category_filter:
        stmt = stmt.where(AuditLog.category == category_filter)
    if result_filter:
        stmt = stmt.where(AuditLog.result == result_filter)
    if level_filter:
        stmt = stmt.where(AuditLog.level == level_filter)
    if resource_type:
        # 前缀匹配：resource_type="task" 可匹配 "task:abc123"
        stmt = stmt.where(AuditLog.resource.like(f"{resource_type}%"))
    if resource_id:
        # 子串匹配：在 resource 列中模糊查找 id
        stmt = stmt.where(AuditLog.resource.like(f"%{resource_id}%"))
    if since:
        stmt = stmt.where(AuditLog.created_at >= since)
    if until:
        stmt = stmt.where(AuditLog.created_at <= until)
    if q:
        # 全文搜索：在 action/resource/detail/username 四列中模糊匹配
        stmt = stmt.where(
            or_(
                AuditLog.action.like(f"%{q}%"),
                AuditLog.resource.like(f"%{q}%"),
                AuditLog.detail.like(f"%{q}%"),
                AuditLog.username.like(f"%{q}%"),
            )
        )
    return stmt


async def query_logs(
    session: AsyncSession,
    limit: int = 100,
    offset: int = 0,
    action_filter: str = "",
    username_filter: str = "",
    category_filter: str = "",
    result_filter: str = "",
    level_filter: str = "",
    resource_type: str = "",
    resource_id: str = "",
    since: datetime | None = None,
    until: datetime | None = None,
    q: str = "",
    truncate_detail: bool = True,
) -> list[dict]:
    """查询审计日志（异步），支持多维度过滤与分页。

    - truncate_detail=True 时 detail 截断到 500 字符（适合列表展示）
    - 时间统一通过 to_cst_iso 转为东八区 ISO 字符串
    """
    stmt = select(AuditLog).order_by(AuditLog.created_at.desc())
    stmt = _apply_filters(
        stmt,
        action_filter=action_filter,
        username_filter=username_filter,
        category_filter=category_filter,
        result_filter=result_filter,
        level_filter=level_filter,
        resource_type=resource_type,
        resource_id=resource_id,
        since=since,
        until=until,
        q=q,
    )
    stmt = stmt.limit(limit).offset(offset)
    results = await session.execute(stmt)
    rows = results.scalars().all()
    return [
        {
            "id": r.id,
            "user_id": r.user_id,
            "username": r.username,
            "action": r.action,
            "resource": r.resource,
            "detail": (r.detail or "")[:500] if truncate_detail else (r.detail or ""),
            "ip_address": r.ip_address,
            "category": r.category or "",
            "level": r.level or "",
            "result": r.result or "",
            "user_agent": r.user_agent or "",
            "created_at": to_cst_iso(r.created_at) or "",
        }
        for r in rows
    ]


async def count_logs(
    session: AsyncSession,
    action_filter: str = "",
    username_filter: str = "",
    category_filter: str = "",
    result_filter: str = "",
    level_filter: str = "",
    resource_type: str = "",
    resource_id: str = "",
    since: datetime | None = None,
    until: datetime | None = None,
    q: str = "",
) -> int:
    """统计满足过滤条件的审计日志总数（用于分页 total）。"""
    stmt = select(func.count(AuditLog.id))
    stmt = _apply_filters(
        stmt,
        action_filter=action_filter,
        username_filter=username_filter,
        category_filter=category_filter,
        result_filter=result_filter,
        level_filter=level_filter,
        resource_type=resource_type,
        resource_id=resource_id,
        since=since,
        until=until,
        q=q,
    )
    result = await session.execute(stmt)
    return result.scalar() or 0


async def query_stats(session: AsyncSession) -> dict:
    """审计统计聚合：按 category/result/level 分组计数 + 按天时间趋势。"""
    # 按 category 分组计数
    cat_rows = (
        await session.execute(
            select(AuditLog.category, func.count(AuditLog.id)).group_by(AuditLog.category)
        )
    ).all()
    by_category = {c or "未分类": n for c, n in cat_rows}

    # 按 result 分组计数
    res_rows = (
        await session.execute(
            select(AuditLog.result, func.count(AuditLog.id)).group_by(AuditLog.result)
        )
    ).all()
    by_result = {r or "未知": n for r, n in res_rows}

    # 按 level 分组计数
    lvl_rows = (
        await session.execute(
            select(AuditLog.level, func.count(AuditLog.id)).group_by(AuditLog.level)
        )
    ).all()
    by_level = {l or "未设置": n for l, n in lvl_rows}

    # 按天时间趋势（UTC date 分组，按时间正序）
    trend_rows = (
        await session.execute(
            select(func.date(AuditLog.created_at), func.count(AuditLog.id))
            .group_by(func.date(AuditLog.created_at))
            .order_by(func.date(AuditLog.created_at))
        )
    ).all()
    trend = [{"date": str(d), "count": n} for d, n in trend_rows]

    return {
        "by_category": by_category,
        "by_result": by_result,
        "by_level": by_level,
        "trend": trend,
    }


async def prune_old_logs(session: AsyncSession) -> int:
    """清理过期审计日志（异步），返回删除数。"""
    cutoff = datetime.now(timezone.utc) - timedelta(days=_RETENTION_DAYS)
    if _RETENTION_DAYS <= 0:
        return 0
    try:
        old_logs = (await session.execute(
            select(AuditLog).where(AuditLog.created_at < cutoff)
        )).scalars().all()
        for log in old_logs:
            await session.delete(log)
        await session.commit()
        return len(old_logs)
    except Exception as e:
        logger.warning("清理审计日志失败: %s", e)
        return 0


# ==================== 后台定时清理 ====================

async def start_retention_loop() -> None:
    """后台定时清理过期审计日志（每小时一次）。

    在 FastAPI lifespan 中通过 asyncio.create_task(start_retention_loop()) 启动。
    """
    from app.db.session import SessionLocal
    while True:
        try:
            await asyncio.sleep(3600)
            async with SessionLocal() as session:
                deleted = await prune_old_logs(session)
                if deleted > 0:
                    logger.info("定时清理过期审计日志: %d 条", deleted)
        except asyncio.CancelledError:
            # 应用关闭时退出循环
            break
        except Exception as e:
            logger.warning("审计日志定时清理异常: %s", e)
