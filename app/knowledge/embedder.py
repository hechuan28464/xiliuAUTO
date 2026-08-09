"""Embedding 生成：复用 LLM API 做 embedding。

支持 DeepSeek/OpenAI embedding 接口，零额外模型加载。
2C4G 优化：不加载本地 sentence-transformers（省 500MB 内存），走 API。
"""
from __future__ import annotations

import logging
import os
from typing import Optional

import httpx

logger = logging.getLogger("autohunter.embedder")

# Embedding 配置
_EMBEDDING_BASE_URL = os.environ.get("EMBEDDING_BASE_URL", os.environ.get("LLM_BASE_URL", "https://api.deepseek.com/v1"))
_EMBEDDING_API_KEY = os.environ.get("EMBEDDING_API_KEY", os.environ.get("LLM_API_KEY", ""))
_EMBEDDING_MODEL = os.environ.get("EMBEDDING_MODEL", "text-embedding-ada-002")
_EMBEDDING_TIMEOUT = int(os.environ.get("EMBEDDING_TIMEOUT", "30"))

# 简易缓存（进程内，避免重复 embed 同样文本）
_cache: dict[str, list[float]] = {}
_cache_max = 500


def embed_text(text: str) -> Optional[list[float]]:
    """把文本 embed 成向量。失败返回 None。"""
    if not text or not _EMBEDDING_API_KEY:
        return None

    text = text.strip()[:8000]  # 截断超长文本
    cache_key = text[:200]  # 用前 200 字做缓存键
    if cache_key in _cache:
        return _cache[cache_key]

    try:
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
    """批量 embed。"""
    return [embed_text(t) for t in texts]
