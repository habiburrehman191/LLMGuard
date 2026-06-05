from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.models import DataClassification, PortalScope, User, UserRole
from app.rag import vector_store
from app.rbac import can_access_classification, can_access_portal


@dataclass(frozen=True)
class RetrievalResult:
    chunk_id: str
    document_id: str
    chunk_text: str
    portal_scope: str
    classification: str
    owner_user_id: int | None
    allowed_roles: list[str]
    source_filename: str
    chunk_index: int
    score: float
    metadata: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {
            "chunk_id": self.chunk_id,
            "document_id": self.document_id,
            "chunk_text": self.chunk_text,
            "portal_scope": self.portal_scope,
            "classification": self.classification,
            "owner_user_id": self.owner_user_id,
            "allowed_roles": self.allowed_roles,
            "source_filename": self.source_filename,
            "chunk_index": self.chunk_index,
            "score": self.score,
            "metadata": self.metadata,
        }


def _enum_value(value: object) -> str:
    return getattr(value, "value", str(value))


def chunk_row_to_metadata(chunk) -> dict[str, Any]:
    portal_scope = _enum_value(chunk.portal_scope) if chunk.portal_scope is not None else ""
    classification = _enum_value(chunk.classification)
    return {
        "chunk_id": chunk.chunk_id,
        "document_id": chunk.document_id,
        "portal_scope": portal_scope,
        "classification": classification,
        "owner_user_id": chunk.owner_user_id,
        "allowed_roles": list(chunk.allowed_roles or []),
        "source_filename": chunk.source_filename or "",
        "chunk_index": chunk.chunk_index,
        "chunk_text": chunk.chunk_text,
        "title": chunk.title,
        "category": chunk.category,
        "source_path": chunk.source_path,
        "is_synthetic": bool(chunk.is_synthetic),
        "canary_markers": list(chunk.canary_markers or []),
    }


def _metadata_allowed_for_user(metadata: dict[str, Any], user: User) -> bool:
    classification = str(metadata.get("classification") or DataClassification.public.value)
    if classification == DataClassification.restricted_secret.value:
        return False

    scope = str(metadata.get("portal_scope") or "")
    if scope and not can_access_portal(user, scope):
        return False
    if not can_access_classification(user, classification):
        return False

    owner_user_id = metadata.get("owner_user_id")
    if user.role == UserRole.student and classification == DataClassification.student_private.value:
        return owner_user_id == user.id
    if user.role == UserRole.employee and classification == DataClassification.employee_private.value:
        return owner_user_id == user.id
    return True


def _synthetic_redteam_allowed(metadata: dict[str, Any]) -> bool:
    return (
        bool(metadata.get("is_synthetic", True))
        and str(metadata.get("classification")) != DataClassification.restricted_secret.value
    )


def _to_result(metadata: dict[str, Any]) -> RetrievalResult:
    return RetrievalResult(
        chunk_id=str(metadata.get("chunk_id") or ""),
        document_id=str(metadata.get("document_id") or ""),
        chunk_text=str(metadata.get("chunk_text") or ""),
        portal_scope=str(metadata.get("portal_scope") or ""),
        classification=str(metadata.get("classification") or DataClassification.public.value),
        owner_user_id=metadata.get("owner_user_id"),
        allowed_roles=list(metadata.get("allowed_roles") or []),
        source_filename=str(metadata.get("source_filename") or ""),
        chunk_index=int(metadata.get("chunk_index") or 0),
        score=float(metadata.get("score") or 0.0),
        metadata=metadata,
    )


def retrieve(
    query: str,
    user: User,
    top_k: int = 5,
    *,
    vulnerable_mode: bool = False,
) -> list[RetrievalResult]:
    candidates = vector_store.search(query, top_k=max(top_k * 8, top_k))
    results: list[RetrievalResult] = []
    for candidate in candidates:
        if vulnerable_mode:
            if not _synthetic_redteam_allowed(candidate):
                continue
        elif not _metadata_allowed_for_user(candidate, user):
            continue
        results.append(_to_result(candidate))
        if len(results) >= top_k:
            break
    return results
