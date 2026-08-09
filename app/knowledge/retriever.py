"""知识检索器：统一入口，为 Worker/Reviewer/Killsweep 提供知识检索。

检索时机：
- Worker 初始化时查同类目标历史经验
- Reviewer 审核时查相似漏洞历史判定
- Killsweep 通杀分析时查同产品历史

升级：分块索引 + Rerank 精排 + 去重 + 嵌入输入格式化。
检索流程：向量检索 → Rerank 精排 → SHA256 去重 → TopK 截断
"""
from __future__ import annotations

import hashlib
import logging
import os
from typing import Any, Optional

from app.knowledge.chunker import split_document
from app.knowledge.embedder import embed_text, embed_texts
from app.knowledge.reranker import rerank
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
# 候选召回倍数：向量检索返回 n * 倍数 条候选，再精排截断
_CANDIDATE_MULTIPLIER = int(os.environ.get("KNOWLEDGE_CANDIDATE_MULTIPLIER", "3"))
_retriever_instance: Optional["KnowledgeRetriever"] = None


class KnowledgeRetriever:
    """知识检索器：封装向量检索 + Rerank 精排 + 上下文格式化。"""

    def __init__(self, store: VectorStore | None = None):
        self._store = store or get_vector_store()

    def is_available(self) -> bool:
        return self._store.is_available()

    # ---- 嵌入输入格式化 ----

    @staticmethod
    def _format_index_input(vuln_type: str, title: str, content: str) -> str:
        """索引时嵌入输入格式：[类型：{vuln_type}] [标题：{title}]\n{content}"""
        return f"[类型：{vuln_type}] [标题：{title}]\n{content}"

    @staticmethod
    def _format_query_input(risk_type: str, query: str) -> str:
        """查询时嵌入输入格式：[类型：{risk_type}] [标题：]\n{query}"""
        return f"[类型：{risk_type}] [标题：]\n{query}"

    # ---- 去重 ----

    @staticmethod
    def dedupe_by_content(docs: list[dict]) -> list[dict]:
        """SHA256 内容去重：按 text 字段的 SHA256 哈希去重。"""
        seen: set[str] = set()
        result: list[dict] = []
        for doc in docs:
            content = doc.get("text", "")
            h = hashlib.sha256(content.encode("utf-8")).hexdigest()
            if h not in seen:
                seen.add(h)
                result.append(doc)
        return result

    # ---- 检索后处理 ----

    def _retrieve_with_rerank(
        self,
        collection: str,
        query: str,
        embedding: list[float] | None,
        n: int,
        risk_type: str = "",
    ) -> list[dict]:
        """向量检索 → Rerank 精排 → 去重 → TopK 截断。"""
        # 多召回候选（上限 10，受 VectorStore.query 内部限制）
        candidate_count = min(n * _CANDIDATE_MULTIPLIER, 10)
        candidates = self._store.query(collection, query, embedding, candidate_count)
        if not candidates:
            return []

        # 去重
        candidates = self.dedupe_by_content(candidates)

        # Rerank 精排
        if len(candidates) > 1:
            docs = [c.get("text", "") for c in candidates]
            order = rerank(query, docs)
            candidates = [candidates[i] for i in order if i < len(candidates)]

        # TopK 截断
        return candidates[:n]

    # ---- 写入 ----

    def index_finding(self, finding_id: str, vuln_type: str, title: str, target_url: str,
                      poc: str, severity: str, verdict: str = "", notes: str = ""):
        """索引一个漏洞 finding（供后续相似漏洞参考）。

        集成分块：调用 chunker 分块后逐块嵌入。
        """
        # 构建完整文档
        text = f"[{vuln_type}] {title}\n目标: {target_url}\n等级: {severity}\nPoC: {poc[:500]}"
        if notes:
            text += f"\n备注: {notes}"

        # 分块
        chunks = split_document(text)
        if not chunks:
            chunks = [text]

        # 格式化嵌入输入：[类型：{vuln_type}] [标题：{title}]\n{content}
        embed_inputs = [
            self._format_index_input(vuln_type, title, chunk)
            for chunk in chunks
        ]
        # 批量嵌入
        embeddings = embed_texts(embed_inputs)

        # 逐块写入向量库
        for i, (chunk, embedding) in enumerate(zip(chunks, embeddings)):
            chunk_id = f"{finding_id}_chunk{i}" if len(chunks) > 1 else finding_id
            self._store.add(
                COLLECTION_VULNS,
                doc_id=chunk_id,
                text=chunk,
                metadata={
                    "vuln_type": vuln_type,
                    "title": title,
                    "severity": severity,
                    "verdict": verdict,
                    "target": target_url,
                    "finding_id": finding_id,
                    "chunk_index": i,
                },
                embedding=embedding or None,
            )

    def index_intel(self, intel_id: str, kind: str, payload: dict, summary: str = "", verified: bool = False):
        """索引一条情报。"""
        text = f"[{kind}] {summary}\n{payload}"
        # 格式化嵌入输入
        embed_input = self._format_index_input(kind, summary, text)
        embedding = embed_text(embed_input)
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
        # 格式化嵌入输入
        title = f"{target} - {vuln_type}"
        embed_input = self._format_index_input("攻击链", title, text)
        embedding = embed_text(embed_input)
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
        # 格式化嵌入输入
        embed_input = self._format_index_input(waf_type, technique, text)
        embedding = embed_text(embed_input)
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
        # 格式化查询嵌入输入
        query_fmt = self._format_query_input(vuln_type, query)
        embedding = embed_text(query_fmt)
        return self._retrieve_with_rerank(COLLECTION_VULNS, query, embedding, n, risk_type=vuln_type)

    def find_relevant_intel(self, target_url: str, host: str = "", n: int = 0) -> list[dict]:
        """查目标相关情报。"""
        n = n or _MAX_RESULTS
        query = f"{target_url} {host}"
        # 格式化查询嵌入输入
        query_fmt = self._format_query_input("情报", query)
        embedding = embed_text(query_fmt)
        return self._retrieve_with_rerank(COLLECTION_INTEL, query, embedding, n, risk_type="情报")

    def find_similar_chains(self, target_url: str, vuln_type: str = "", n: int = 0) -> list[dict]:
        """查相似攻击链。"""
        n = n or _MAX_RESULTS
        query = f"{vuln_type} {target_url}"
        # 格式化查询嵌入输入
        query_fmt = self._format_query_input("攻击链", query)
        embedding = embed_text(query_fmt)
        return self._retrieve_with_rerank(COLLECTION_ATTACK_CHAIN, query, embedding, n, risk_type="攻击链")

    def find_bypass_techniques(self, waf_type: str, n: int = 0) -> list[dict]:
        """查 WAF 绕过技巧。"""
        n = n or _MAX_RESULTS
        # 格式化查询嵌入输入
        query_fmt = self._format_query_input(waf_type, waf_type)
        embedding = embed_text(query_fmt)
        return self._retrieve_with_rerank(COLLECTION_BYPASS, waf_type, embedding, n, risk_type=waf_type)

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
