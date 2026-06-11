from __future__ import annotations

import base64
import binascii
from pathlib import Path

from fastapi import HTTPException, status
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import (
    AIInteraction,
    DataClassification,
    Document,
    PortalRecord,
    PortalScope,
    SecurityAction,
    ThreatLabel,
    User,
    UserRole,
)
from app.ai.gateway import process_ai_request
from app.rag.ingestion import InMemoryUpload, ingest_uploaded_file
from app.rag.retriever import retrieve as retrieve_rag_chunks
from app.rbac import can_access_classification, can_access_portal, enforce_portal_boundary, explain_denial

BASE_DIR = Path(__file__).resolve().parents[2]
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
ASSET_VERSION = "15"
FIREWALL_ACTIVE = True


class PortalAskRequest(BaseModel):
    prompt: str
    firewall_active: bool = FIREWALL_ACTIVE
    session_id: str | None = None


class PortalDocumentUploadRequest(BaseModel):
    title: str
    filename: str
    content: str = ""
    content_base64: str | None = None
    classification: DataClassification | None = None


def portal_role_for_pipeline(user: User) -> str:
    if user.role == UserRole.student:
        return "student"
    if user.role == UserRole.employee:
        return "staff"
    return "super_admin"


def require_portal(user: User, scope: PortalScope) -> None:
    enforce_portal_boundary(user, scope)


def accessible_records(db: Session, user: User, scope: PortalScope | None = None) -> list[PortalRecord]:
    query = select(PortalRecord)
    if scope is not None:
        query = query.where(PortalRecord.portal_scope == scope)
    rows = db.scalars(query.order_by(PortalRecord.created_at.desc())).all()
    records: list[PortalRecord] = []
    for record in rows:
        if not can_access_portal(user, record.portal_scope):
            continue
        if not can_access_classification(user, record.classification):
            continue
        if user.role == UserRole.student and record.classification == DataClassification.student_private:
            if record.owner_user_id != user.id:
                continue
        if user.role == UserRole.employee and record.classification == DataClassification.employee_private:
            if record.owner_user_id != user.id:
                continue
        records.append(record)
    return records


def render_context(
    user: User,
    portal_scope: PortalScope,
    records: list[PortalRecord],
    *,
    recent_interactions: list[AIInteraction] | None = None,
) -> dict[str, object]:
    settings = get_settings()
    boundaries = {
        PortalScope.student: {
            "allowed": ["Own synthetic student records", "Student portal documents", "Public university policies"],
            "blocked": ["Employee records", "Admin data", "Finance and contracts", "restricted_secret"],
        },
        PortalScope.employee: {
            "allowed": ["Own synthetic employee records", "Staff documents", "Public university policies"],
            "blocked": ["Student records", "Admin data", "Finance and contracts", "restricted_secret"],
        },
        PortalScope.admin: {
            "allowed": ["Synthetic student records", "Synthetic employee records", "Admin, finance, exam, and contract data"],
            "blocked": ["restricted_secret is never sent to Qwen"],
        },
    }[portal_scope]
    return {
        "asset_version": ASSET_VERSION,
        "firewall_active": settings.firewall_active,
        "redteam_enabled": settings.redteam_mode or settings.app_env == "local_redteam",
        "user": user,
        "portal_scope": portal_scope.value,
        "records": records,
        "recent_interactions": recent_interactions or [],
        "allowed_data": boundaries["allowed"],
        "blocked_data": boundaries["blocked"],
    }


class PortalRagAdapter:
    def __init__(self, user: User, *, vulnerable_mode: bool = False) -> None:
        self.user = user
        self.vulnerable_mode = vulnerable_mode

    def retrieve(self, query: str, top_k: int | None = None) -> dict[str, object] | None:
        results = retrieve_rag_chunks(
            query,
            self.user,
            top_k=top_k or 4,
            vulnerable_mode=self.vulnerable_mode,
        )
        if not results:
            return None

        chunks = [
            {
                "document_id": result.document_id,
                "title": str(result.metadata.get("title") or result.source_filename),
                "category": str(result.metadata.get("category") or "portal_upload"),
                "classification": result.classification,
                "allowed_roles": result.allowed_roles,
                "is_synthetic": bool(result.metadata.get("is_synthetic", True)),
                "canary_markers": list(result.metadata.get("canary_markers") or []),
                "document_name": result.source_filename,
                "source_path": str(result.metadata.get("source_path") or result.source_filename),
                "source_set": "controlled_upload",
                "is_poisoned": False,
                "chunk_id": result.chunk_id,
                "chunk_index": result.chunk_index,
                "text": result.chunk_text,
                "chunk_text": result.chunk_text,
                "score": result.score,
                "raw_score": result.score,
            }
            for result in results
        ]
        return {
            "filename": ", ".join(dict.fromkeys(chunk["document_name"] for chunk in chunks)),
            "content": "\n\n".join(str(chunk["text"]) for chunk in chunks),
            "score": chunks[0]["score"],
            "source_paths": list(dict.fromkeys(str(chunk["source_path"]) for chunk in chunks)),
            "chunks": chunks,
        }


def _extractive_portal_answer(prompt: str) -> str:
    marker = "Policy context:"
    question_marker = "User question:"
    context = prompt
    if marker in prompt:
        context = prompt.split(marker, 1)[1]
    if question_marker in context:
        context = context.split(question_marker, 1)[0]
    sentences = [sentence.strip() for sentence in context.replace("\n", " ").split(".") if sentence.strip()]
    return ". ".join(sentences[:2]) + ("." if sentences else "")


def ask_portal_ai(user: User, request: PortalAskRequest, portal_scope: PortalScope, db: Session) -> dict[str, object]:
    require_portal(user, portal_scope)
    result = process_ai_request(
        user,
        request.prompt,
        portal_scope,
        user_role=portal_role_for_pipeline(user),
        user_id=user.synthetic_ref or str(user.id),
        session_id=request.session_id,
        firewall_active=request.firewall_active,
        db=db,
    )
    return result.model_dump()


def create_document_record(
    db: Session,
    *,
    user: User,
    portal_scope: PortalScope,
    request: PortalDocumentUploadRequest,
) -> Document:
    require_portal(user, portal_scope)
    classification = request.classification or (
        DataClassification.student_private
        if portal_scope == PortalScope.student
        else DataClassification.employee_private
        if portal_scope == PortalScope.employee
        else DataClassification.admin_internal
    )
    if classification == DataClassification.restricted_secret or not can_access_classification(user, classification):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=explain_denial(user, portal_scope, classification),
        )

    if request.content_base64:
        try:
            upload_content = base64.b64decode(request.content_base64, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise HTTPException(status_code=400, detail="Invalid base64 upload payload.") from exc
    else:
        upload_content = request.content.encode("utf-8")

    document = ingest_uploaded_file(
        InMemoryUpload(
            filename=request.filename,
            content=upload_content,
        ),
        user,
        portal_scope,
        classification,
        db=db,
        title=request.title,
    )
    return document


def log_ai_interaction(
    db: Session,
    *,
    user: User,
    portal_scope: PortalScope,
    prompt: str,
    payload: dict[str, object],
) -> None:
    action_value = str(payload.get("action") or "allow")
    label_value = str(payload.get("label") or "safe")
    db.add(
        AIInteraction(
            user_id=user.id,
            user_role=user.role.value,
            portal_scope=portal_scope.value,
            prompt=prompt,
            response_preview=str(payload.get("response") or "")[:500],
            action=SecurityAction(action_value) if action_value in SecurityAction._value2member_map_ else SecurityAction.allow,
            label=ThreatLabel(label_value) if label_value in ThreatLabel._value2member_map_ else ThreatLabel.safe,
            risk_score=float(payload.get("risk_score") or 0.0),
            qwen_called=bool(payload.get("qwen_called")),
            retrieved_chunk_ids=[
                str(chunk.get("chunk_id"))
                for chunk in payload.get("retrieved_chunks", [])
                if isinstance(chunk, dict) and chunk.get("chunk_id")
            ],
            unauthorized_chunk_ids=[
                str(chunk.get("chunk_id"))
                for chunk in payload.get("unauthorized_retrievals", [])
                if isinstance(chunk, dict) and chunk.get("chunk_id")
            ],
        )
    )
    db.commit()
