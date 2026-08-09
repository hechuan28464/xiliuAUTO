"""文档分块器：Markdown 标题切分 + 递归文本切分。

两阶段分块策略：
1. 按 Markdown 标题（#/##/###/####）切分为语义块
2. 对超长块递归按分隔符优先级切分，保持上下文重叠

简易 token 计数：len(text)//4 估算（不依赖 tiktoken）。
"""
from __future__ import annotations

import re

# 递归切分分隔符优先级（从粗到细）
_SEPARATORS = ["\n\n", "\n", "。", "！", "？", ". ", " "]


def _estimate_tokens(text: str) -> int:
    """简易 token 估算：4 字符约 1 token。"""
    return max(1, len(text) // 4)


def _split_by_markdown_headers(text: str) -> list[str]:
    """第一阶段：按 Markdown 标题（#/##/###/####）切分。"""
    pattern = re.compile(r'^(#{1,4})\s+', re.MULTILINE)
    sections: list[str] = []
    last_end = 0
    for m in pattern.finditer(text):
        if m.start() > last_end:
            section = text[last_end:m.start()].strip()
            if section:
                sections.append(section)
        last_end = m.start()
    if last_end < len(text):
        section = text[last_end:].strip()
        if section:
            sections.append(section)
    # 没有标题则整段返回
    return sections if sections else ([text] if text.strip() else [])


def _recursive_split(text: str, chunk_size: int, overlap: int) -> list[str]:
    """第二阶段：递归文本切分，按分隔符优先级逐层拆分。"""
    text = text.strip()
    if not text:
        return []
    if _estimate_tokens(text) <= chunk_size:
        return [text]

    for sep in _SEPARATORS:
        if sep not in text:
            continue
        parts = [p for p in (s.strip() for s in text.split(sep)) if p]
        if len(parts) <= 1:
            continue
        # 递归处理每个 piece，收集所有叶子块
        leaves: list[str] = []
        for piece in parts:
            if _estimate_tokens(piece) > chunk_size:
                leaves.extend(_recursive_split(piece, chunk_size, overlap))
            else:
                leaves.append(piece)
        # 合并相邻叶子块到目标大小，用 sep 连接，块间保留 overlap 上下文
        return _merge_with_overlap(leaves, sep, chunk_size, overlap)

    # 所有分隔符都没切动，按字符硬切兜底
    return _hard_split(text, chunk_size, overlap)


def _merge_with_overlap(pieces: list[str], sep: str, chunk_size: int, overlap: int) -> list[str]:
    """合并相邻小块到 chunk_size，块间保留 overlap 字符上下文。"""
    if not pieces:
        return []
    chunks: list[str] = []
    current = pieces[0]

    for piece in pieces[1:]:
        candidate = current + sep + piece
        if _estimate_tokens(candidate) <= chunk_size:
            current = candidate
        else:
            chunks.append(current)
            # 下一个块以当前块尾部 overlap 字符开头，保持上下文连贯
            tail = _tail_chars(current, overlap)
            current = (tail + sep + piece) if tail else piece
            # 若合并后仍超长（piece 本身很大），硬切兜底
            if _estimate_tokens(current) > chunk_size:
                chunks.append(current)
                current = ""
    if current:
        chunks.append(current)
    return chunks


def _tail_chars(text: str, overlap_tokens: int) -> str:
    """取文本尾部约 overlap_tokens 个 token 对应的字符。"""
    if overlap_tokens <= 0 or not text:
        return ""
    # 反向估算：1 token ≈ 4 字符
    chars = overlap_tokens * 4
    return text[-chars:] if chars < len(text) else text


def _hard_split(text: str, chunk_size: int, overlap: int) -> list[str]:
    """字符级硬切（兜底，所有分隔符都切不动时）。"""
    max_chars = chunk_size * 4
    overlap_chars = overlap * 4
    chunks: list[str] = []
    i = 0
    while i < len(text):
        chunk = text[i:i + max_chars]
        chunks.append(chunk)
        if i + max_chars >= len(text):
            break
        i += max(max_chars - overlap_chars, 1)
    return chunks


def split_document(text: str, chunk_size: int = 768, overlap: int = 50) -> list[str]:
    """文档分块：先按 Markdown 标题切分，再对超长段递归切分。

    Args:
        text: 原始文档文本
        chunk_size: 每块最大 token 数（估算）
        overlap: 块间重叠 token 数

    Returns:
        分块后的文本列表
    """
    if not text or not text.strip():
        return []
    # 第一阶段：按 Markdown 标题切分
    sections = _split_by_markdown_headers(text)
    # 第二阶段：对每个 section 递归切分
    chunks: list[str] = []
    for section in sections:
        chunks.extend(_recursive_split(section, chunk_size, overlap))
    return chunks
