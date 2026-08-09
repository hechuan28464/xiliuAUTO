"""HTTP Rerank 精排：调用 DashScope / Cohere rerank API 对检索结果重排序。

零额外依赖：直接用 httpx 调 HTTP API。
失败时降级返回原始顺序，不阻断检索流程。
"""
from __future__ import annotations

import logging
import os

import httpx

logger = logging.getLogger("autohunter.reranker")

# Rerank 配置（环境变量）
_RERANK_API_KEY = os.environ.get("RERANK_API_KEY", "")
_RERANK_BASE_URL = os.environ.get("RERANK_BASE_URL", "")
_RERANK_MODEL = os.environ.get("RERANK_MODEL", "gte-rerank")
_RERANK_TIMEOUT = int(os.environ.get("RERANK_TIMEOUT", "30"))

# DashScope rerank 端点
_DASHSCOPE_URL = "https://dashscope.aliyuncs.com/api/v1/services/rerank/text-rerank"
# Cohere rerank 端点
_COHERE_URL = "https://api.cohere.ai/v1/rerank"


def rerank(
    query: str,
    documents: list[str],
    provider: str = "dashscope",
    model: str = "gte-rerank",
    api_key: str = "",
    base_url: str = "",
) -> list[int]:
    """对文档列表按与 query 的相关性重排序。

    Args:
        query: 查询文本
        documents: 待重排的文档列表
        provider: rerank 服务商（dashscope / cohere）
        model: rerank 模型名
        api_key: API Key（空则用环境变量）
        base_url: 自定义端点 URL（含 dashscope 自动推断 provider）

    Returns:
        重排后的文档索引顺序；失败时返回原始顺序（降级）。
    """
    if not documents:
        return []
    if len(documents) == 1:
        return [0]

    # 解析参数：显式传入优先，其次环境变量
    key = api_key or _RERANK_API_KEY
    url = base_url or _RERANK_BASE_URL

    # 从 base_url 自动推断 provider
    if url and "dashscope" in url.lower():
        provider = "dashscope"
    elif url and "cohere" in url.lower():
        provider = "cohere"

    if not key:
        logger.debug("Rerank 跳过：未配置 API Key")
        return list(range(len(documents)))

    try:
        if provider == "cohere":
            return _rerank_cohere(query, documents, model, key, url or _COHERE_URL)
        else:
            return _rerank_dashscope(query, documents, model, key, url or _DASHSCOPE_URL)
    except Exception as e:
        logger.warning("Rerank 失败，降级为原始顺序: %s", e)
        return list(range(len(documents)))


def _rerank_dashscope(
    query: str, documents: list[str], model: str, api_key: str, url: str
) -> list[int]:
    """调用 DashScope rerank API。"""
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": model,
        "input": {
            "query": query,
            "documents": documents,
        },
        "parameters": {"return_documents": False, "top_n": len(documents)},
    }
    resp = httpx.post(url, headers=headers, json=payload, timeout=_RERANK_TIMEOUT)
    resp.raise_for_status()
    data = resp.json()
    # DashScope 返回 results 数组，每项含 index 和 relevance_score
    results = data.get("output", {}).get("results", [])
    if not results:
        results = data.get("results", [])
    # 提取重排后的索引顺序
    indices = [item.get("index", i) for i, item in enumerate(results)]
    return _ensure_complete(indices, len(documents))


def _rerank_cohere(
    query: str, documents: list[str], model: str, api_key: str, url: str
) -> list[int]:
    """调用 Cohere rerank API。"""
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": model,
        "query": query,
        "documents": documents,
        "top_n": len(documents),
    }
    resp = httpx.post(url, headers=headers, json=payload, timeout=_RERANK_TIMEOUT)
    resp.raise_for_status()
    data = resp.json()
    # Cohere 返回 results 数组，每项含 index
    results = data.get("results", [])
    indices = [item.get("index", i) for i, item in enumerate(results)]
    return _ensure_complete(indices, len(documents))


def _ensure_complete(indices: list[int], total: int) -> list[int]:
    """确保返回的索引覆盖所有文档（补全遗漏项）。"""
    seen = set(indices)
    complete = list(indices)
    for i in range(total):
        if i not in seen:
            complete.append(i)
    return complete
