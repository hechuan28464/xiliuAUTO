"""RAG 知识库模块：向量存储 + 检索 + 情报复用。

自研 RAG 知识库，用 ChromaDB 做进程内向量存储。
存储：历史漏洞模式、已验证情报、攻击链路、绕过技巧。

升级：文档分块 + 批量嵌入 + Rerank 精排 + 检索后处理。
"""
from app.knowledge.vector_store import VectorStore, get_vector_store
from app.knowledge.embedder import get_embeddings, embed_text, embed_texts
from app.knowledge.chunker import split_document
from app.knowledge.reranker import rerank
from app.knowledge.retriever import KnowledgeRetriever, get_retriever

__all__ = [
    "VectorStore",
    "get_vector_store",
    "get_embeddings",
    "embed_text",
    "embed_texts",
    "split_document",
    "rerank",
    "KnowledgeRetriever",
    "get_retriever",
]
