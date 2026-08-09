"""Embedding 生成：复用 LLM API 做 embedding。

支持 DeepSeek/OpenAI embedding 接口，零额外模型加载。
2C4G 优化：不加载本地 sentence-transformers（省 500MB 内存），走 API。

升级：批量嵌入 + 指数退避重试 + RPM 速率限制（滑动窗口）。
"""
from __future__ import annotations

import logging
import os
import time
from collections import deque
from typing import Optional

import httpx

logger = logging.getLogger("autohunter.embedder")

# Embedding 配置
_EMBEDDING_BASE_URL = os.environ.get("EMBEDDING_BASE_URL", os.environ.get("LLM_BASE_URL", "https://api.deepseek.com/v1"))
_EMBEDDING_API_KEY = os.environ.get("EMBEDDING_API_KEY", os.environ.get("LLM_API_KEY", ""))
_EMBEDDING_MODEL = os.environ.get("EMBEDDING_MODEL", "text-embedding-ada-002")
_EMBEDDING_TIMEOUT = int(os.environ.get("EMBEDDING_TIMEOUT", "30"))

# 重试配置
_MAX_RETRIES = int(os.environ.get("EMBEDDING_MAX_RETRIES", "3"))

# RPM 速率限制（滑动窗口）
_RPM_LIMIT = int(os.environ.get("EMBEDDING_RPM", "100"))
_request_timestamps: deque[float] = deque()

# 简易缓存（进程内，避免重复 embed 同样文本）
_cache: dict[str, list[float]] = {}
_cache_max = 500

# 可重试错误关键词（限流/5xx/超时/网络）
_RETRYABLE_KEYWORDS = (
    "429", "rate limit", "too many requests", "限流",
    "500", "502", "503", "504", "internal server error", "bad gateway",
    "service unavailable", "gateway timeout",
    "timeout", "timed out", "readtimeout", "connecttimeout", "超时",
    "connection", "network", "name resolution", "连接",
)


def _is_retryable(exc: Exception) -> bool:
    """判断是否为可重试错误（限流/5xx/超时/网络）。"""
    response = getattr(exc, "response", None)
    status = getattr(exc, "status_code", None) or getattr(response, "status_code", None)
    text = f"{status or ''} {exc}".lower()
    if status is not None:
        try:
            code = int(status)
            if code == 429 or code >= 500:
                return True
        except (TypeError, ValueError):
            pass
    return any(k in text for k in _RETRYABLE_KEYWORDS)


def _wait_for_rpm_slot() -> None:
    """滑动窗口 RPM 限速：确保每分钟请求数不超过 _RPM_LIMIT。"""
    if _RPM_LIMIT <= 0:
        return
    now = time.monotonic()
    # 清理 60 秒前的时间戳
    while _request_timestamps and _request_timestamps[0] < now - 60:
        _request_timestamps.popleft()
    if len(_request_timestamps) >= _RPM_LIMIT:
        sleep_time = 60 - (now - _request_timestamps[0])
        if sleep_time > 0:
            logger.debug("Embedding RPM 限速，等待 %.1f 秒", sleep_time)
            time.sleep(sleep_time)
        # 清理过期的
        now = time.monotonic()
        while _request_timestamps and _request_timestamps[0] < now - 60:
            _request_timestamps.popleft()
    _request_timestamps.append(time.monotonic())


def embed_text(text: str) -> Optional[list[float]]:
    """把文本 embed 成向量。失败返回 None。"""
    if not text or not _EMBEDDING_API_KEY:
        return None

    text = text.strip()[:8000]  # 截断超长文本
    cache_key = text[:200]  # 用前 200 字做缓存键
    if cache_key in _cache:
        return _cache[cache_key]

    try:
        _wait_for_rpm_slot()
        url = f"{_EMBEDDING_BASE_URL.rstrip('/')}/embeddings"
        resp = httpx.post(
            url,
            json={
                "model": _EMBEDDING_MODEL,
                "input": text,
            },
            headers={
                "Authorization": f"Bearer {_EMBEDDING_API_KEY}",
                "Content-Type": "application/json",
            },
            timeout=_EMBEDDING_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()
        embedding = data.get("data", [{}])[0].get("embedding", [])
        if embedding:
            if len(_cache) >= _cache_max:
                _cache.clear()
            _cache[cache_key] = embedding
            return embedding
    except Exception as e:
        logger.warning("Embedding 生成失败: %s", e)
        return None
    return None


def get_embeddings(texts: list[str]) -> list[Optional[list[float]]]:
    """批量 embed（旧接口，内部走批量 API）。"""
    embeddings = embed_texts(texts)
    return [emb if emb else None for emb in embeddings]


def embed_texts(texts: list[str]) -> list[list[float]]:
    """批量嵌入：一次 API 调用发送多条文本，带指数退避重试和 RPM 限速。

    Args:
        texts: 待嵌入的文本列表

    Returns:
        向量列表，与输入一一对应；单条失败时对应位置为空列表 []。
    """
    if not texts:
        return []
    if not _EMBEDDING_API_KEY:
        return [[] for _ in texts]

    # 先查缓存，减少 API 调用
    results: list[list[float]] = []
    to_fetch: list[int] = []  # 需要请求 API 的索引
    for i, t in enumerate(texts):
        t = (t or "").strip()[:8000]
        cache_key = t[:200]
        cached = _cache.get(cache_key)
        if cached is not None:
            results.append(cached)
        else:
            results.append([])
            to_fetch.append(i)

    if not to_fetch:
        return results

    # 批量请求需要 API 调用的文本
    fetch_texts = [(texts[i] or "").strip()[:8000] for i in to_fetch]
    embeddings = _batch_embed_with_retry(fetch_texts)

    # 回填结果并缓存
    for idx, emb in zip(to_fetch, embeddings):
        results[idx] = emb
        if emb:
            cache_key = (texts[idx] or "").strip()[:8000][:200]
            if len(_cache) >= _cache_max:
                _cache.clear()
            _cache[cache_key] = emb

    return results


def _batch_embed_with_retry(texts: list[str]) -> list[list[float]]:
    """批量嵌入带指数退避重试：整批失败后逐条降级。"""
    for attempt in range(_MAX_RETRIES + 1):
        try:
            _wait_for_rpm_slot()
            return _batch_embed_request(texts)
        except Exception as e:
            if attempt < _MAX_RETRIES and _is_retryable(e):
                # 指数退避：delay = 1 * (attempt+1)，即 1s, 2s, 3s
                delay = 1 * (attempt + 1)
                logger.info("Embedding 批量请求重试 %d/%d（%s，等待 %ds）",
                            attempt + 1, _MAX_RETRIES, type(e).__name__, delay)
                time.sleep(delay)
            elif attempt < _MAX_RETRIES:
                # 不可重试错误，直接跳出
                logger.warning("Embedding 批量请求不可重试错误: %s", e)
                break
            else:
                logger.warning("Embedding 批量请求 %d 次后仍失败，降级为逐条嵌入", _MAX_RETRIES)

    # 整批失败，降级为逐条嵌入
    results: list[list[float]] = []
    for t in texts:
        emb = embed_text(t)
        results.append(emb if emb else [])
    return results


def _batch_embed_request(texts: list[str]) -> list[list[float]]:
    """单次批量嵌入 API 调用。"""
    url = f"{_EMBEDDING_BASE_URL.rstrip('/')}/embeddings"
    resp = httpx.post(
        url,
        json={
            "model": _EMBEDDING_MODEL,
            "input": texts,
        },
        headers={
            "Authorization": f"Bearer {_EMBEDDING_API_KEY}",
            "Content-Type": "application/json",
        },
        timeout=_EMBEDDING_TIMEOUT,
    )
    resp.raise_for_status()
    data = resp.json()
    # OpenAI 兼容格式：data 是数组，每个元素含 index 和 embedding
    embeddings_data = data.get("data", [])
    # 按 index 对齐到输入顺序，缺失的位置返回空列表
    result: list[list[float]] = [[] for _ in texts]
    for item in embeddings_data:
        idx = item.get("index", 0)
        if 0 <= idx < len(texts):
            result[idx] = item.get("embedding", [])
    return result
