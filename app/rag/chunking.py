from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any

DEFAULT_CHUNK_SIZE = 700
DEFAULT_CHUNK_OVERLAP = 100


@dataclass(frozen=True)
class ChunkPayload:
    chunk_text: str
    chunk_index: int
    metadata: dict[str, Any]


def _normalize_text(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def chunk_text(
    text: str,
    metadata: dict[str, Any],
    *,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    chunk_overlap: int = DEFAULT_CHUNK_OVERLAP,
) -> list[ChunkPayload]:
    normalized = _normalize_text(text)
    if not normalized:
        return []
    if chunk_overlap >= chunk_size:
        raise ValueError("chunk_overlap must be smaller than chunk_size")

    chunks: list[ChunkPayload] = []
    start = 0
    index = 0
    while start < len(normalized):
        end = min(len(normalized), start + chunk_size)
        if end < len(normalized):
            boundary = normalized.rfind(" ", start, end)
            if boundary > start + max(120, chunk_size // 2):
                end = boundary
        chunk = normalized[start:end].strip()
        if chunk:
            chunk_metadata = dict(metadata)
            chunk_metadata["chunk_index"] = index
            chunks.append(
                ChunkPayload(
                    chunk_text=chunk,
                    chunk_index=index,
                    metadata=chunk_metadata,
                )
            )
            index += 1
        if end >= len(normalized):
            break
        start = max(0, end - chunk_overlap)

    return chunks
