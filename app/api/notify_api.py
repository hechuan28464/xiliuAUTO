"""融合版新增 API 路由：通知配置。

管理通知系统配置和测试发送。
"""
from __future__ import annotations

import os

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.notify import notify

router = APIRouter(prefix="/api/notify", tags=["notify"])


class NotifyConfig(BaseModel):
    enabled: bool = False
    webhook_url: str = ""
    dingtalk_token: str = ""
    wecom_key: str = ""
    lark_token: str = ""
    tg_bot_token: str = ""
    tg_chat_id: str = ""


class TestNotifyRequest(BaseModel):
    title: str = "测试通知"
    message: str = "这是一条来自 xiliuAUTO 的测试通知"
    channel: str = "webhook"


@router.get("/config")
async def get_notify_config():
    """获取通知配置。"""
    return {
        "enabled": os.environ.get("NOTIFY_ENABLED", "0").lower() in {"1", "true", "yes"},
        "webhook_url": os.environ.get("NOTIFY_WEBHOOK_URL", ""),
        "dingtalk_token": _mask(os.environ.get("NOTIFY_DINGTALK_TOKEN", "")),
        "wecom_key": _mask(os.environ.get("NOTIFY_WECOM_KEY", "")),
        "lark_token": _mask(os.environ.get("NOTIFY_LARK_TOKEN", "")),
        "tg_bot_token": _mask(os.environ.get("NOTIFY_TG_BOT_TOKEN", "")),
        "tg_chat_id": os.environ.get("NOTIFY_TG_CHAT_ID", ""),
    }


@router.put("/config")
async def update_notify_config(req: NotifyConfig):
    """更新通知配置（写入 .env 或返回指引）。

    注意：实际写入 .env 需要 root 权限，这里返回需手动修改的提示。
    生产环境建议通过控制台「设置」页或直接编辑 .env 配置。
    """
    return {
        "ok": True,
        "message": "通知配置需通过 .env 文件修改。请编辑以下环境变量后重启服务：",
        "env_vars": {
            "NOTIFY_ENABLED": "1" if req.enabled else "0",
            "NOTIFY_WEBHOOK_URL": req.webhook_url,
            "NOTIFY_DINGTALK_TOKEN": req.dingtalk_token,
            "NOTIFY_WECOM_KEY": req.wecom_key,
            "NOTIFY_LARK_TOKEN": req.lark_token,
            "NOTIFY_TG_BOT_TOKEN": req.tg_bot_token,
            "NOTIFY_TG_CHAT_ID": req.tg_chat_id,
        },
    }


@router.post("/test")
async def test_notify(req: TestNotifyRequest):
    """发送测试通知。"""
    if not os.environ.get("NOTIFY_ENABLED", "0").lower() in {"1", "true", "yes"}:
        raise HTTPException(400, "通知未开启，请先设置 NOTIFY_ENABLED=1")
    notify(req.title, req.message, priority="normal", channels=[req.channel])
    return {"ok": True, "message": f"测试通知已发送到 {req.channel}"}


def _mask(val: str) -> str:
    """脱敏显示。"""
    if not val or len(val) <= 8:
        return "***" if val else ""
    return val[:4] + "****" + val[-4:]
