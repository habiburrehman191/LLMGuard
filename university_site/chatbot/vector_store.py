from __future__ import annotations

import json
import os
from pathlib import Path

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from ..models import ChatKnowledgeChunk
from .ingestion_firewall import document_source_id_from_chunk_id
from .types import SourceReference


INDEX_DIR = Path(__file__).resolve().parents[1] / "demo_data" / "chat_vector_store"
_embedding_unavailable = False


def _allowed_statement(portal_context: str):
    if portal_context == "public":
        return select(ChatKnowledgeChunk).where(ChatKnowledgeChunk.portal_scope == "public")
    if portal_context == "student":
        return select(ChatKnowledgeChunk).where(ChatKnowledgeChunk.portal_scope.in_(["public", "student"]))
    return select(ChatKnowledgeChunk).where(ChatKnowledgeChunk.portal_scope.in_(["public", "student", "employee"]))


def _metadata(item: ChatKnowledgeChunk) -> dict[str, object]:
    document_source_id = document_source_id_from_chunk_id(item.source_id)
    return {
        "document_id": document_source_id,
        "chunk_id": item.source_id,
        "chunk_index": (
            int(item.source_id.rsplit("::chunk:", 1)[1])
            if "::chunk:" in item.source_id
            else 0
        ),
        "chunk_text": item.content,
        "title": item.title,
        "category": item.source_type,
        "classification": item.classification,
        "portal_scope": item.portal_scope,
        "allowed_roles": [part for part in item.role_scope.split(",") if part],
        "route": item.route,
        "source_id": item.source_id,
        "source_type": item.source_type,
        "is_synthetic": True,
    }


def rebuild_vector_indexes(session: Session) -> dict[str, object]:
    from app.rag.vector_store import build_index

    INDEX_DIR.mkdir(parents=True, exist_ok=True)
    results: dict[str, object] = {}
    for context in ("public", "student", "employee"):
        chunks = [_metadata(item) for item in session.scalars(_allowed_statement(context).order_by(ChatKnowledgeChunk.source_id))]
        results[context] = build_index(chunks, index_dir=INDEX_DIR / context)
    signature = {
        item.source_id: item.content_hash
        for item in session.scalars(select(ChatKnowledgeChunk).order_by(ChatKnowledgeChunk.source_id))
    }
    (INDEX_DIR / "source-manifest.json").write_text(json.dumps(signature, sort_keys=True), encoding="utf-8")
    return results


def _indexes_current(session: Session) -> bool:
    path = INDEX_DIR / "source-manifest.json"
    if not path.exists():
        return False
    try:
        stored = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    current = {
        item.source_id: item.content_hash
        for item in session.scalars(select(ChatKnowledgeChunk).order_by(ChatKnowledgeChunk.source_id))
    }
    return stored == current and all((INDEX_DIR / scope / "university.faiss").exists() for scope in ("public", "student", "employee"))


def _as_source(item: ChatKnowledgeChunk, score: float = 0.0) -> SourceReference:
    return SourceReference(
        source_type=item.source_type,
        source_id=document_source_id_from_chunk_id(item.source_id),
        title=item.title,
        route=item.route,
        classification=item.classification,
        portal_scope=item.portal_scope,
        content=item.content,
        role_scope=item.role_scope,
    )


def _role_can_read(item: ChatKnowledgeChunk, role_key: str | None) -> bool:
    if item.portal_scope != "employee" or not item.role_scope:
        return True
    return bool(role_key and role_key in {part for part in item.role_scope.split(",") if part})


def _sparse_search(session: Session, question: str, portal_context: str, top_k: int, role_key: str | None) -> list[SourceReference]:
    from sklearn.feature_extraction.text import TfidfVectorizer

    items = [
        item for item in session.scalars(_allowed_statement(portal_context).order_by(ChatKnowledgeChunk.source_id))
        if _role_can_read(item, role_key)
    ]
    if not items:
        return []
    corpus = [f"{item.title} {item.content}" for item in items]
    matrix = TfidfVectorizer(stop_words="english", ngram_range=(1, 2), max_features=12000).fit_transform(corpus + [question])
    scores = (matrix[:-1] @ matrix[-1].T).toarray().ravel()
    ranked = sorted(range(len(items)), key=lambda index: float(scores[index]), reverse=True)
    return [_as_source(items[index], float(scores[index])) for index in ranked[:top_k] if float(scores[index]) > 0.01]


def semantic_search(
    session: Session,
    question: str,
    portal_context: str,
    top_k: int = 4,
    role_key: str | None = None,
) -> list[SourceReference]:
    global _embedding_unavailable
    backend = os.getenv("UOH_CHAT_VECTOR_BACKEND", "auto").strip().lower()
    if backend != "tfidf" and not _embedding_unavailable:
        try:
            if not _indexes_current(session):
                rebuild_vector_indexes(session)
            from app.rag.vector_store import search

            raw = search(question, top_k=top_k, index_dir=INDEX_DIR / portal_context)
            ids = [str(item.get("source_id") or item.get("document_id")) for item in raw]
            if ids:
                by_id = {
                    item.source_id: item
                    for item in session.scalars(select(ChatKnowledgeChunk).where(ChatKnowledgeChunk.source_id.in_(ids)))
                    if _role_can_read(item, role_key)
                }
                return [_as_source(by_id[source_id]) for source_id in ids if source_id in by_id]
        except Exception:
            _embedding_unavailable = True
    return _sparse_search(session, question, portal_context, top_k, role_key)
