"""知识检索器：统一入口，为 Worker/Reviewer/Killsweep 提供知识检索。

检索时机：
- Worker 初始化时查同类目标历史经验
- Reviewer 审核时查相似漏洞历史判定
- Killsweep 通杀分析时查同产品历史
"""
from __future__ import annotations

import hashlib
import logging
import os
from typing import Any, Optional

from app.knowledge.embedder import embed_text
from app.knowledge.vector_store import (
    COLLECTION_ATTACK_CHAIN,
    COLLECTION_BYPASS,
    COLLECTION_INTEL,
    COLLECTION_VULNS,
    VectorStore,
    get_vector_store,
)

logger = logging.getLogger("autohunter.retriever")

_MAX_RESULTS = int(os.environ.get("KNOWLEDGE_MAX_RESULTS", "5"))
_retriever_instance: Optional["KnowledgeRetriever"] = None


class KnowledgeRetriever:
    """知识检索器：封装向量检索 + 上下文格式化。"""

    def __init__(self, store: VectorStore | None = None):
        self._store = store or get_vector_store()

    def is_available(self) -> bool:
        return self._store.is_available()

    # ---- 写入 ----

    def index_finding(self, finding_id: str, vuln_type: str, title: str, target_url: str,
                      poc: str, severity: str, verdict: str = "", notes: str = ""):
        """索引一个漏洞 finding（供后续相似漏洞参考）。"""
        text = f"[{vuln_type}] {title}\n目标: {target_url}\n等级: {severity}\nPoC: {poc[:500]}"
        if notes:
            text += f"\n备注: {notes}"
        embedding = embed_text(f"{vuln_type} {title} {target_url}")
        self._store.add(
            COLLECTION_VULNS,
            doc_id=finding_id,
            text=text,
            metadata={
                "vuln_type": vuln_type,
                "title": title,
                "severity": severity,
                "verdict": verdict,
                "target": target_url,
            },
            embedding=embedding,
        )

    def index_intel(self, intel_id: str, kind: str, payload: dict, summary: str = "", verified: bool = False):
        """索引一条情报。"""
        text = f"[{kind}] {summary}\n{payload}"
        embedding = embed_text(f"{kind} {summary} {payload}")
        self._store.add(
            COLLECTION_INTEL,
            doc_id=intel_id,
            text=text,
            metadata={
                "kind": kind,
                "verified": verified,
                "summary": summary,
            },
            embedding=embedding,
        )

    def index_attack_chain(self, chain_id: str, target: str, vuln_type: str, steps: list[dict]):
        """索引一条攻击链路。"""
        text_parts = [f"[攻击链] {target} - {vuln_type}"]
        for step in steps:
            text_parts.append(f"  {step.get('method', '')}: {step.get('detail', '')}")
        text = "\n".join(text_parts)
        embedding = embed_text(f"{vuln_type} {target} {' '.join(s.get('method','') for s in steps)}")
        self._store.add(
            COLLECTION_ATTACK_CHAIN,
            doc_id=chain_id,
            text=text,
            metadata={"target": target, "vuln_type": vuln_type},
            embedding=embedding,
        )

    def index_bypass(self, bypass_id: str, waf_type: str, technique: str, payload: str):
        """索引一条 WAF 绕过技巧。"""
        text = f"[绕过] {waf_type}: {technique}\nPayload: {payload}"
        embedding = embed_text(f"{waf_type} {technique} {payload}")
        self._store.add(
            COLLECTION_BYPASS,
            doc_id=bypass_id,
            text=text,
            metadata={"waf_type": waf_type, "technique": technique},
            embedding=embedding,
        )

    # ---- 检索 ----

    def find_similar_vulns(self, vuln_type: str, target_url: str, title: str = "", n: int = 0) -> list[dict]:
        """查相似漏洞模式。"""
        n = n or _MAX_RESULTS
        query = f"{vuln_type} {title} {target_url}"
        embedding = embed_text(query)
        return self._store.query(COLLECTION_VULNS, query, embedding, n)

    def find_relevant_intel(self, target_url: str, host: str = "", n: int = 0) -> list[dict]:
        """查目标相关情报。"""
        n = n or _MAX_RESULTS
        query = f"{target_url} {host}"
        embedding = embed_text(query)
        return self._store.query(COLLECTION_INTEL, query, embedding, n)

    def find_similar_chains(self, target_url: str, vuln_type: str = "", n: int = 0) -> list[dict]:
        """查相似攻击链。"""
        n = n or _MAX_RESULTS
        query = f"{vuln_type} {target_url}"
        embedding = embed_text(query)
        return self._store.query(COLLECTION_ATTACK_CHAIN, query, embedding, n)

    def find_bypass_techniques(self, waf_type: str, n: int = 0) -> list[dict]:
        """查 WAF 绕过技巧。"""
        n = n or _MAX_RESULTS
        embedding = embed_text(waf_type)
        return self._store.query(COLLECTION_BYPASS, waf_type, embedding, n)

    # ---- 格式化 ----

    def format_worker_context(self, target_url: str, host: str = "", vuln_types: list[str] | None = None) -> str:
        """格式化 Worker 初始知识上下文。"""
        if not self.is_available():
            return ""

        parts: list[str] = []

        # 查相关情报
        intel = self.find_relevant_intel(target_url, host)
        if intel:
            parts.append("【知识库情报】")
            for item in intel[:3]:
                meta = item.get("metadata", {})
                parts.append(f"  - {item.get('text', '')[:200]}")

        # 查相似攻击链
        chains = self.find_similar_chains(target_url)
        if chains:
            parts.append("【相关攻击链参考】")
            for item in chains[:2]:
                parts.append(f"  - {item.get('text', '')[:300]}")

        # 查相似漏洞
        if vuln_types:
            for vt in vuln_types[:3]:
                vulns = self.find_similar_vulns(vt, target_url)
                if vulns:
                    parts.append(f"【{vt}历史漏洞参考】")
                    for item in vulns[:2]:
                        parts.append(f"  - {item.get('text', '')[:200]}")

        return "\n".join(parts) if parts else ""


def get_retriever() -> KnowledgeRetriever:
    """获取全局检索器实例。"""
    global _retriever_instance
    if _retriever_instance is None:
        _retriever_instance = KnowledgeRetriever()
    return _retriever_instance
