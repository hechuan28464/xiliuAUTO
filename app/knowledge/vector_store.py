"""ChromaDB 向量存储：进程内运行，零额外服务依赖。

2C4G 优化：ChromaDB 用 DuckDB 后端，内存占用可控。
持久化到磁盘，重启不丢。
"""
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger("autohunter.vector_store")

_DB_PATH = Path(os.environ.get("KNOWLEDGE_DB_PATH", Path(__file__).resolve().parent.parent.parent / "data" / "chroma"))

# 集合名
COLLECTION_VULNS = "vulnerabilities"      # 漏洞模式
COLLECTION_INTEL = "intel"                # 已验证情报
COLLECTION_ATTACK_CHAIN = "attack_chains" # 攻击链路
COLLECTION_BYPASS = "bypass_techniques"   # 绕过技巧

_store_instance: Optional["VectorStore"] = None


class VectorStore:
    """ChromaDB 向量存储封装。"""

    def __init__(self, db_path: Path | None = None):
        self._db_path = db_path or _DB_PATH
        self._client = None
        self._collections: dict[str, Any] = {}
        self._connected = False

    def _connect(self):
        """延迟初始化 ChromaDB（避免启动时就占内存）。"""
        if self._connected:
            return
        try:
            import chromadb
            self._db_path.mkdir(parents=True, exist_ok=True)
            self._client = chromadb.PersistentClient(path=str(self._db_path))
            for name in [COLLECTION_VULNS, COLLECTION_INTEL, COLLECTION_ATTACK_CHAIN, COLLECTION_BYPASS]:
                self._collections[name] = self._client.get_or_create_collection(
                    name=name,
                    metadata={"hnsw:space": "cosine"},
                )
            self._connected = True
            logger.info("ChromaDB 初始化成功: %s", self._db_path)
        except ImportError:
            logger.warning("chromadb 未安装，知识库功能降级（仅文本检索）")
            self._connected = False
        except Exception as e:
            logger.error("ChromaDB 初始化失败: %s", e)
            self._connected = False

    def add(self, collection: str, doc_id: str, text: str, metadata: dict | None = None, embedding: list[float] | None = None):
        """添加一条文档。"""
        self._connect()
        if not self._connected or collection not in self._collections:
            return
        try:
            coll = self._collections[collection]
            params = {
                "ids": [doc_id],
                "documents": [text],
                "metadatas": [metadata or {}],
            }
            if embedding:
                params["embeddings"] = [embedding]
            coll.add(**params)
        except Exception as e:
            # 已存在则更新
            if "already exists" in str(e).lower() or "duplicate" in str(e).lower():
                try:
                    params = {
                        "ids": [doc_id],
                        "documents": [text],
                        "metadatas": [metadata or {}],
                    }
                    if embedding:
                        params["embeddings"] = [embedding]
                    self._collections[collection].upsert(**params)
                except Exception:
                    pass
            else:
                logger.debug("向量存储写入失败: %s", e)

    def query(self, collection: str, query_text: str, query_embedding: list[float] | None = None, n_results: int = 5) -> list[dict]:
        """检索相似文档。"""
        self._connect()
        if not self._connected or collection not in self._collections:
            return []
        try:
            params: dict[str, Any] = {
                "n_results": min(n_results, 10),
            }
            if query_embedding:
                params["query_embeddings"] = [query_embedding]
            else:
                params["query_texts"] = [query_text]

            results = self._collections[collection].query(**params)

            docs = results.get("documents", [[]])[0]
            metas = results.get("metadatas", [[]])[0]
            dists = results.get("distances", [[]])[0]
            ids = results.get("ids", [[]])[0]

            return [
                {
                    "id": ids[i] if i < len(ids) else "",
                    "text": docs[i] if i < len(docs) else "",
                    "metadata": metas[i] if i < len(metas) else {},
                    "similarity": 1 - dists[i] if i < len(dists) else 0,
                }
                for i in range(len(docs))
            ]
        except Exception as e:
            logger.debug("向量检索失败: %s", e)
            return []

    def count(self, collection: str) -> int:
        """返回集合中文档数。"""
        self._connect()
        if not self._connected or collection not in self._collections:
            return 0
        try:
            return self._collections[collection].count()
        except Exception:
            return 0

    def is_available(self) -> bool:
        self._connect()
        return self._connected


def get_vector_store() -> VectorStore:
    """获取全局 VectorStore 实例。"""
    global _store_instance
    if _store_instance is None:
        _store_instance = VectorStore()
    return _store_instance
