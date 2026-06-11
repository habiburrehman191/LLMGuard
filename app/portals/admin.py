from __future__ import annotations

import base64
import binascii

from fastapi import APIRouter, Depends, Request
from fastapi import HTTPException, status
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.ai.gateway import process_ai_request
from app.auth import get_current_user
from app.config import get_settings
from app.database import get_db
from app.models import (
    AIInteraction,
    AuditLog,
    DataClassification,
    Document,
    DocumentChunk,
    FirewallEvent,
    PortalRecord,
    PortalScope,
    RedteamCase,
    ToolCall,
    User,
    UserRole,
)
from app.portals.common import (
    ASSET_VERSION,
    PortalAskRequest,
    PortalDocumentUploadRequest,
    accessible_records,
    ask_portal_ai,
    create_document_record,
    log_ai_interaction,
    render_context,
    require_portal,
    templates,
)
from app.rag.ingestion import InMemoryUpload, ingest_uploaded_file
from app.rag.retriever import chunk_row_to_metadata
from app.rag.vector_store import build_index

router = APIRouter(prefix="/admin", tags=["super-admin-portal"])


def _admin_ui_context(user: User) -> dict[str, object]:
    settings = get_settings()
    return {
        "asset_version": ASSET_VERSION,
        "user": user,
        "portal_scope": "admin",
        "firewall_active": settings.firewall_active,
        "redteam_enabled": settings.redteam_mode or settings.app_env == "local_redteam",
    }


class CompareRequest(BaseModel):
    prompt: str
    user_role: str = "student"
    portal_scope: str = "student"
    user_id: str | None = None


class AdminDocumentUploadRequest(BaseModel):
    title: str
    filename: str
    content_base64: str
    portal_scope: PortalScope
    classification: DataClassification


@router.get("/dashboard", response_class=HTMLResponse)
def admin_dashboard(
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    require_portal(user, PortalScope.admin)
    records = accessible_records(db, user)
    interactions = db.scalars(
        select(AIInteraction).order_by(AIInteraction.created_at.desc()).limit(8)
    ).all()
    record_summary = {
        "student": sum(record.portal_scope == PortalScope.student for record in records),
        "employee": sum(record.portal_scope == PortalScope.employee for record in records),
        "admin": sum(record.portal_scope == PortalScope.admin for record in records),
    }
    context = render_context(
        user,
        PortalScope.admin,
        records,
        recent_interactions=interactions,
    )
    context["record_summary"] = record_summary
    return templates.TemplateResponse(
        request=request,
        name="admin_dashboard.html",
        context=context,
    )


@router.get("/compare", response_class=HTMLResponse)
def compare_page(
    request: Request,
    user: User = Depends(get_current_user),
) -> HTMLResponse:
    require_portal(user, PortalScope.admin)
    return templates.TemplateResponse(
        request=request,
        name="compare.html",
        context=_admin_ui_context(user),
    )


@router.post("/compare/run", response_class=JSONResponse)
def compare_run(
    payload: CompareRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> JSONResponse:
    require_portal(user, PortalScope.admin)
    role_map = {
        "student": UserRole.student,
        "employee": UserRole.employee,
        "super_admin": UserRole.super_admin,
    }
    target_role = role_map.get(payload.user_role, UserRole.student)
    simulated_user = db.scalar(select(User).where(User.role == target_role))
    if simulated_user is None:
        raise HTTPException(status_code=404, detail="Synthetic comparison user is not seeded.")
    try:
        target_scope = PortalScope(payload.portal_scope)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid portal scope.") from exc

    vulnerable = process_ai_request(
        simulated_user,
        payload.prompt,
        target_scope,
        payload.user_role,
        user_id=payload.user_id or simulated_user.synthetic_ref,
        firewall_active=False,
        db=db,
    )
    protected = process_ai_request(
        simulated_user,
        payload.prompt,
        target_scope,
        payload.user_role,
        user_id=payload.user_id or simulated_user.synthetic_ref,
        firewall_active=True,
        db=db,
    )
    verdict = (
        "LLMGuard blocked the protected request while vulnerable mode allowed it."
        if protected.blocked and not vulnerable.blocked
        else "Review both outcomes and security metadata."
    )
    return JSONResponse(
        {
            "vulnerable": vulnerable.model_dump(),
            "protected": protected.model_dump(),
            "verdict": verdict,
        }
    )


@router.get("/documents", response_class=HTMLResponse)
def document_manager(
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    require_portal(user, PortalScope.admin)
    documents = db.scalars(select(Document).order_by(Document.created_at.desc())).all()
    return templates.TemplateResponse(
        request=request,
        name="documents.html",
        context={**_admin_ui_context(user), "documents": documents},
    )


@router.post("/documents/upload-manager", response_class=JSONResponse)
def document_manager_upload(
    payload: AdminDocumentUploadRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> JSONResponse:
    require_portal(user, PortalScope.admin)
    try:
        content = base64.b64decode(payload.content_base64, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise HTTPException(status_code=400, detail="Invalid base64 upload payload.") from exc
    document = ingest_uploaded_file(
        InMemoryUpload(filename=payload.filename, content=content),
        user,
        payload.portal_scope,
        payload.classification,
        db=db,
        title=payload.title,
    )
    return JSONResponse(
        {
            "document_id": document.document_id,
            "classification": document.classification.value,
            "portal_scope": document.portal_scope.value if document.portal_scope else None,
            "chunks": len(document.chunks),
        }
    )


@router.post("/documents/rebuild", response_class=JSONResponse)
def rebuild_document_index(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> JSONResponse:
    require_portal(user, PortalScope.admin)
    chunks = db.scalars(select(DocumentChunk).order_by(DocumentChunk.id)).all()
    result = build_index([chunk_row_to_metadata(chunk) for chunk in chunks])
    return JSONResponse(result)


@router.delete("/documents/{document_id}", response_class=JSONResponse)
def delete_document(
    document_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> JSONResponse:
    require_portal(user, PortalScope.admin)
    document = db.scalar(select(Document).where(Document.document_id == document_id))
    if document is None:
        raise HTTPException(status_code=404, detail="Document not found.")
    if document.classification == DataClassification.restricted_secret:
        raise HTTPException(status_code=403, detail="restricted_secret documents cannot be managed through the AI repository.")
    db.add(
        AuditLog(
            actor_user_id=user.id,
            actor_role=user.role.value,
            event_type="document_deleted",
            entity_type="document",
            entity_id=document.document_id,
            summary=f"Deleted controlled synthetic document {document.title}.",
            metadata_json={"source_filename": document.source_filename},
        )
    )
    db.delete(document)
    db.commit()
    return JSONResponse({"deleted": True, "document_id": document_id})


@router.get("/redteam", response_class=HTMLResponse)
def redteam_dashboard(
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    require_portal(user, PortalScope.admin)
    cases = db.scalars(select(RedteamCase).order_by(RedteamCase.severity.desc(), RedteamCase.case_id)).all()
    return templates.TemplateResponse(
        request=request,
        name="redteam_dashboard.html",
        context={
            **_admin_ui_context(user),
            "cases": cases,
            "runner_available": False,
        },
    )


@router.post("/redteam/run", response_class=JSONResponse)
def redteam_run_stub(user: User = Depends(get_current_user)) -> JSONResponse:
    require_portal(user, PortalScope.admin)
    return JSONResponse(
        {
            "available": False,
            "detail": "No reusable red-team runner is installed. No results were fabricated.",
        },
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
    )


@router.get("/redteam/export", response_class=JSONResponse)
def redteam_export(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> JSONResponse:
    require_portal(user, PortalScope.admin)
    cases = db.scalars(select(RedteamCase).order_by(RedteamCase.case_id)).all()
    return JSONResponse(
        {
            "runner_available": False,
            "results": [],
            "cases": [
                {
                    "case_id": case.case_id,
                    "name": case.name,
                    "attack_type": case.attack_type,
                    "severity": case.severity,
                    "expected_action": case.expected_action,
                }
                for case in cases
            ],
        }
    )


@router.get("/audit", response_class=HTMLResponse)
def audit_page(
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    require_portal(user, PortalScope.admin)
    interactions = db.scalars(select(AIInteraction).order_by(AIInteraction.created_at.desc()).limit(100)).all()
    events = db.scalars(select(FirewallEvent).order_by(FirewallEvent.created_at.desc()).limit(100)).all()
    tools = db.scalars(select(ToolCall).order_by(ToolCall.created_at.desc()).limit(100)).all()
    audits = db.scalars(select(AuditLog).order_by(AuditLog.created_at.desc()).limit(100)).all()
    return templates.TemplateResponse(
        request=request,
        name="audit.html",
        context={
            **_admin_ui_context(user),
            "interactions": interactions,
            "events": events,
            "tools": tools,
            "audits": audits,
        },
    )


@router.get("/all-records", response_class=JSONResponse)
def admin_all_records(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> JSONResponse:
    require_portal(user, PortalScope.admin)
    records = accessible_records(db, user)
    return JSONResponse({"records": [_record_payload(record) for record in records]})


@router.post("/ai/ask", response_class=JSONResponse)
def admin_ai_ask(
    request: PortalAskRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> JSONResponse:
    payload = ask_portal_ai(user, request, PortalScope.admin, db)
    return JSONResponse(payload)


@router.post("/documents/upload", response_class=JSONResponse)
def admin_upload_document(
    request: PortalDocumentUploadRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> JSONResponse:
    document = create_document_record(db, user=user, portal_scope=PortalScope.admin, request=request)
    return JSONResponse(
        {
            "document_id": document.document_id,
            "classification": document.classification.value,
            "chunks": len(document.chunks),
            "source_filename": document.source_filename,
        }
    )


@router.get("/security/events", response_class=JSONResponse)
def admin_security_events(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> JSONResponse:
    require_portal(user, PortalScope.admin)
    events = db.scalars(select(FirewallEvent).order_by(FirewallEvent.created_at.desc()).limit(50)).all()
    audit_logs = db.scalars(select(AuditLog).order_by(AuditLog.created_at.desc()).limit(50)).all()
    return JSONResponse(
        {
            "firewall_events": [
                {
                    "id": event.id,
                    "ai_interaction_id": event.ai_interaction_id,
                    "detector": event.detector,
                    "action": event.action.value,
                    "label": event.label.value,
                    "score": event.score,
                    "reason": event.reason,
                    "source": event.source,
                    "metadata": event.metadata_json,
                    "created_at": event.created_at.isoformat(),
                }
                for event in events
            ],
            "audit_logs": [
                {
                    "id": log.id,
                    "event_type": log.event_type,
                    "summary": log.summary,
                    "actor_role": log.actor_role,
                    "entity_type": log.entity_type,
                    "entity_id": log.entity_id,
                    "metadata": log.metadata_json,
                    "created_at": log.created_at.isoformat(),
                }
                for log in audit_logs
            ],
        }
    )


@router.get("/redteam/cases", response_class=JSONResponse)
def admin_redteam_cases(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> JSONResponse:
    require_portal(user, PortalScope.admin)
    cases = db.scalars(select(RedteamCase).order_by(RedteamCase.created_at.desc()).limit(100)).all()
    return JSONResponse(
        {
            "cases": [
                {
                    "case_id": case.case_id,
                    "name": case.name,
                    "attack_type": case.attack_type,
                    "severity": case.severity,
                    "expected_action": case.expected_action,
                    "user_role": case.user_role,
                }
                for case in cases
            ]
        }
    )


def _record_payload(record: PortalRecord) -> dict[str, object]:
    return {
        "record_id": record.record_id,
        "title": record.title,
        "portal_scope": record.portal_scope.value,
        "classification": record.classification.value,
        "content": record.content,
        "is_synthetic": record.is_synthetic,
    }
