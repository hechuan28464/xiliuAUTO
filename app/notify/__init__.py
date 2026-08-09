"""通知系统模块：多渠道通知（自研）。

事件 → 渠道映射：
- 出洞（finding submitted）→ 全渠道推送
- 审核通过（review accepted）→ IM 推送
- 审批请求（HITL pending）→ IM 推送
- 通杀确认（killsweep verified）→ 全渠道 + 高优先级
- 任务异常（worker error）→ Webhook
"""
from __future__ import annotations

import logging
import os
import threading
from typing import Any, Optional

import httpx

logger = logging.getLogger("autohunter.notify")

# 通知开关
_NOTIFY_ENABLED = os.environ.get("NOTIFY_ENABLED", "0").lower() in {"1", "true", "yes"}

# Webhook
_WEBHOOK_URL = os.environ.get("NOTIFY_WEBHOOK_URL", "")

# 钉钉机器人
_DINGTALK_TOKEN = os.environ.get("NOTIFY_DINGTALK_TOKEN", "")
_DINGTALK_SECRET = os.environ.get("NOTIFY_DINGTALK_SECRET", "")

# 企业微信机器人
_WECOM_KEY = os.environ.get("NOTIFY_WECOM_KEY", "")

# 飞书机器人
_LARK_TOKEN = os.environ.get("NOTIFY_LARK_TOKEN", "")

# Telegram Bot
_TG_BOT_TOKEN = os.environ.get("NOTIFY_TG_BOT_TOKEN", "")
_TG_CHAT_ID = os.environ.get("NOTIFY_TG_CHAT_ID", "")


def _send_webhook(title: str, message: str, priority: str = "normal"):
    """发送 Webhook 通知。"""
    if not _WEBHOOK_URL:
        return
    try:
        httpx.post(
            _WEBHOOK_URL,
            json={
                "title": title,
                "message": message,
                "priority": priority,
                "source": "xiliuAUTO",
            },
            timeout=10,
        )
    except Exception as e:
        logger.warning("Webhook 通知发送失败: %s", e)


def _send_dingtalk(title: str, message: str):
    """发送钉钉机器人通知。"""
    if not _DINGTALK_TOKEN:
        return
    try:
        url = f"https://oapi.dingtalk.com/robot/send?access_token={_DINGTALK_TOKEN}"
        httpx.post(
            url,
            json={
                "msgtype": "markdown",
                "markdown": {
                    "title": title,
                    "text": f"## {title}\n\n{message}",
                },
            },
            timeout=10,
        )
    except Exception as e:
        logger.warning("钉钉通知发送失败: %s", e)


def _send_wecom(title: str, message: str):
    """发送企业微信机器人通知。"""
    if not _WECOM_KEY:
        return
    try:
        url = f"https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key={_WECOM_KEY}"
        httpx.post(
            url,
            json={
                "msgtype": "markdown",
                "markdown": {
                    "content": f"## {title}\n\n{message}",
                },
            },
            timeout=10,
        )
    except Exception as e:
        logger.warning("企微通知发送失败: %s", e)


def _send_lark(title: str, message: str):
    """发送飞书机器人通知。"""
    if not _LARK_TOKEN:
        return
    try:
        url = f"https://open.feishu.cn/open-apis/bot/v2/hook/{_LARK_TOKEN}"
        httpx.post(
            url,
            json={
                "msg_type": "interactive",
                "card": {
                    "header": {"title": {"tag": "plain_text", "content": title}},
                    "elements": [{"tag": "div", "text": {"content": message}}],
                },
            },
            timeout=10,
        )
    except Exception as e:
        logger.warning("飞书通知发送失败: %s", e)


def _send_telegram(title: str, message: str):
    """发送 Telegram Bot 通知。"""
    if not _TG_BOT_TOKEN or not _TG_CHAT_ID:
        return
    try:
        url = f"https://api.telegram.org/bot{_TG_BOT_TOKEN}/sendMessage"
        httpx.post(
            url,
            json={
                "chat_id": _TG_CHAT_ID,
                "text": f"*{title}*\n\n{message}",
                "parse_mode": "Markdown",
            },
            timeout=10,
        )
    except Exception as e:
        logger.warning("Telegram 通知发送失败: %s", e)


def notify(title: str, message: str, priority: str = "normal", channels: list[str] | None = None):
    """发送通知到所有已配置渠道（异步线程，不阻塞主流程）。

    channels: 指定渠道列表；None = 全部已配置渠道。
    priority: low / normal / high / critical
    """
    if not _NOTIFY_ENABLED:
        return

    def _send():
        all_channels = {
            "webhook": lambda: _send_webhook(title, message, priority),
            "dingtalk": lambda: _send_dingtalk(title, message),
            "wecom": lambda: _send_wecom(title, message),
            "lark": lambda: _send_lark(title, message),
            "telegram": lambda: _send_telegram(title, message),
        }
        target = channels or list(all_channels.keys())
        for ch in target:
            if ch in all_channels:
                all_channels[ch]()

    threading.Thread(target=_send, daemon=True).start()


def notify_finding(finding: dict):
    """通知：发现漏洞。"""
    title = f"[出洞] {finding.get('vuln_type', '')} - {finding.get('title', '')}"
    msg = (
        f"**目标**: {finding.get('target_url', '')}\n"
        f"**等级**: {finding.get('severity_claimed', '')}\n"
        f"**类型**: {finding.get('vuln_type', '')}\n"
        f"**归属**: {finding.get('owner', '待确认')}\n"
        f"**PoC**: {(finding.get('poc', '') or '')[:200]}"
    )
    notify(title, msg, priority="high")


def notify_review_accepted(finding: dict, review: dict):
    """通知：漏洞审核通过。"""
    title = f"[审核通过] {finding.get('vuln_type', '')} - {finding.get('title', '')}"
    msg = (
        f"**目标**: {finding.get('target_url', '')}\n"
        f"**最终等级**: {review.get('severity_final', '')}\n"
        f"**评分**: {review.get('score', 0)}/10\n"
        f"**审核意见**: {review.get('reviewer_notes', '')[:200]}"
    )
    notify(title, msg, priority="normal")


def notify_killsweep(killsweep: dict):
    """通知：通杀确认。"""
    title = f"[通杀确认] {killsweep.get('product_name', '')}"
    msg = (
        f"**产品**: {killsweep.get('product_name', '')}\n"
        f"**全网规模**: {killsweep.get('asset_count', 0)}\n"
        f"**教育行业**: {killsweep.get('edu_count', 0)}\n"
        f"**已验证**: {'是' if killsweep.get('verified') else '否'}\n"
        f"**FOFA**: {killsweep.get('fofa_query', '')[:200]}"
    )
    notify(title, msg, priority="critical")


def notify_hitl_pending(tool_name: str, args: dict, reason: str):
    """通知：HITL 审批请求。"""
    title = f"[审批请求] 高危操作: {tool_name}"
    msg = (
        f"**工具**: {tool_name}\n"
        f"**原因**: {reason}\n"
        f"**参数**: {str(args)[:300]}\n"
        f"请前往控制台审批。"
    )
    notify(title, msg, priority="high", channels=["dingtalk", "wecom", "telegram"])


def notify_task_error(task_name: str, target: str, error: str):
    """通知：任务异常。"""
    title = f"[任务异常] {task_name}"
    msg = f"**目标**: {target}\n**错误**: {error[:300]}"
    notify(title, msg, priority="normal", channels=["webhook"])
