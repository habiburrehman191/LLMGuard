from __future__ import annotations

import importlib
import json
from pathlib import Path
from typing import Any

import numpy as np

from app.config import get_settings
from app.rag.embeddings import MODEL_NAME, embed_texts

INDEX_FILENAME = "university.faiss"
METADATA_FILENAME = "chunks.json"
MANIFEST_FILENAME = "manifest.json"


def vector_store_dir() -> Path:
    path = get_settings().data_dir / "vector_store"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _load_faiss():
    return importlib.import_module("faiss")


def _index_path(index_dir: Path | None = None) -> Path:
    return (index_dir or vector_store_dir()) / INDEX_FILENAME


def _metadata_path(index_dir: Path | None = None) -> Path:
    return (index_dir or vector_store_dir()) / METADATA_FILENAME


def _manifest_path(index_dir: Path | None = None) -> Path:
    return (index_dir or vector_store_dir()) / MANIFEST_FILENAME


def build_index(chunks: list[dict[str, Any]], *, index_dir: Path | None = None) -> dict[str, int]:
    target_dir = index_dir or vector_store_dir()
    target_dir.mkdir(parents=True, exist_ok=True)
    faiss = _load_faiss()

    texts = [str(chunk["chunk_text"]) for chunk in chunks]
    vectors = embed_texts(texts)
    if vectors.size == 0:
        index = faiss.IndexFlatIP(384)
        total = 0
    else:
        index = faiss.IndexFlatIP(int(vectors.shape[1]))
        index.add(np.asarray(vectors, dtype="float32"))
        total = int(vectors.shape[0])

    faiss.write_index(index, str(_index_path(target_dir)))
    _metadata_path(target_dir).write_text(json.dumps(chunks, indent=2), encoding="utf-8")
    _manifest_path(target_dir).write_text(
        json.dumps({"model_name": MODEL_NAME, "total_chunks": total}, indent=2),
        encoding="utf-8",
    )
    return {"total_chunks": total}


def load_metadata(*, index_dir: Path | None = None) -> list[dict[str, Any]]:
    path = _metadata_path(index_dir)
    if not path.exists():
        return []
    return json.loads(path.read_text(encoding="utf-8"))


def search(query: str, *, top_k: int = 5, index_dir: Path | None = None) -> list[dict[str, Any]]:
    faiss = _load_faiss()
    index_path = _index_path(index_dir)
    metadata = load_metadata(index_dir=index_dir)
    if not index_path.exists() or not metadata:
        return []

    index = faiss.read_index(str(index_path))
    query_vector = embed_texts([query])
    if query_vector.size == 0:
        return []

    limit = min(max(top_k, 1), len(metadata))
    scores, ids = index.search(np.asarray(query_vector, dtype="float32"), limit)
    results: list[dict[str, Any]] = []
    for raw_score, raw_index in zip(scores[0], ids[0], strict=False):
        if raw_index < 0 or raw_index >= len(metadata):
            continue
        item = dict(metadata[int(raw_index)])
        item["score"] = float(raw_score)
        item["vector_id"] = int(raw_index)
        results.append(item)
    return results
