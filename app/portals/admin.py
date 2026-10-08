from __future__ import annotations

import base64
import binascii
from pathlib import Path

from fastapi import APIRouter, Depends, Query, Request
from fastapi import HTTPException, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.ai.gateway import process_ai_request
from app.application_credentials import (
    create_credential,
    list_credentials,
    revoke_credential,
)
from app.application_registry import get_application, list_applications
from app.auth import get_current_user
from app.benchmark_presentation import load_benchmark_presentation
from app.comparison_presentation import load_comparison_presentation
from app.config import get_settings
from app.database import get_db
from app.db import fetch_dashboard_metrics
from app.integration_health import integration_status_for, integration_statuses_for
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
    require_portal,
    templates,
)
from app.protection_control import list_protection_audit, set_protection_enabled
from app.rag.ingestion import InMemoryUpload, ingest_uploaded_file
from app.rag.retriever import chunk_row_to_metadata
from app.rag.vector_store import build_index
from app.security_events import get_security_overview

router = APIRouter(prefix="/admin", tags=["super-admin-portal"])
EVALUATION_DATASET = (
    Path(__file__).resolve().parents[2]
    / "evaluation"
    / "datasets"
    / "security_cases.jsonl"
)


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


class ProtectionUpdateRequest(BaseModel):
    protection_enabled: bool
    reason: str | None = None


@router.get("/dashboard", response_class=HTMLResponse)
def admin_dashboard(
    request: Request,
    application_id: str | None = Query(default=None, max_length=160),
    user: User = Depends(get_current_user),
) -> HTMLResponse:
    require_portal(user, PortalScope.admin)
    metrics = fetch_dashboard_metrics(limit=8)
    application_integrations = integration_statuses_for(list_applications())
    selected_integration = next(
        (
            integration
            for integration in application_integrations
            if integration.application.application_id == application_id
        ),
        application_integrations[0] if application_integrations else None,
    )
    selected_application_id = (
        selected_integration.application.application_id
        if selected_integration is not None
        else None
    )
    security_overview = get_security_overview(
        application_id=selected_application_id,
        recent_limit=6,
    )
    context = {
        **_admin_ui_context(user),
        "metrics": metrics,
        "security_overview": security_overview,
        "application_integrations": application_integrations,
        "selected_integration": selected_integration,
    }
    return templates.TemplateResponse(
        request=request,
        name="admin_dashboard.html",
        context=context,
    )


@router.get("/applications", response_class=HTMLResponse)
def applications_page(
    request: Request,
    user: User = Depends(get_current_user),
) -> HTMLResponse:
    require_portal(user, PortalScope.admin)
    return templates.TemplateResponse(
        request=request,
        name="applications.html",
        context={
            **_admin_ui_context(user),
            "application_integrations": integration_statuses_for(list_applications()),
        },
    )


@router.get("/applications/{application_id}", response_class=HTMLResponse)
def application_detail_page(
    application_id: str,
    request: Request,
    user: User = Depends(get_current_user),
) -> HTMLResponse:
    require_portal(user, PortalScope.admin)
    return _render_application_detail(request, user, application_id)


@router.post("/applications/{application_id}/credentials", response_class=HTMLResponse)
def create_application_credential(
    application_id: str,
    request: Request,
    user: User = Depends(get_current_user),
) -> HTMLResponse:
    require_portal(user, PortalScope.admin)
    application = get_application(application_id)
    if application is None:
        raise HTTPException(status_code=404, detail="Application not found.")
    created_credential = create_credential(application_id)
    return templates.TemplateResponse(
        request=request,
        name="application_detail.html",
        context={
            **_admin_ui_context(user),
            "application": application,
            "integration": integration_status_for(application),
            "credentials": list_credentials(application_id),
            "created_credential": created_credential,
            "protection_audit": list_protection_audit(application_id),
        },
        status_code=status.HTTP_201_CREATED,
        headers={"Cache-Control": "no-store"},
    )


@router.post("/applications/{application_id}/credentials/{key_id}/revoke")
def revoke_application_credential(
    application_id: str,
    key_id: str,
    user: User = Depends(get_current_user),
) -> RedirectResponse:
    require_portal(user, PortalScope.admin)
    if get_application(application_id) is None:
        raise HTTPException(status_code=404, detail="Application not found.")
    if not any(
        credential.key_id == key_id
        for credential in list_credentials(application_id)
    ):
        raise HTTPException(status_code=404, detail="Credential not found.")
    revoke_credential(application_id, key_id)
    return RedirectResponse(
        url=f"/admin/applications/{application_id}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.post("/applications/{application_id}/protection", response_class=JSONResponse)
def update_application_protection(
    application_id: str,
    payload: ProtectionUpdateRequest,
    user: User = Depends(get_current_user),
) -> JSONResponse:
    require_portal(user, PortalScope.admin)
    if user.role != UserRole.super_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only a Super Admin may change application protection.",
        )
    application = get_application(application_id)
    if application is None:
        raise HTTPException(status_code=404, detail="Application not found.")
    try:
        protection = set_protection_enabled(
            application_id,
            enabled=payload.protection_enabled,
            actor=user.username,
            reason=payload.reason,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc
    integration = integration_status_for(application)
    return JSONResponse(
        {
            "application_id": application_id,
            "protection_enabled": protection.protection_enabled,
            "connection_state": integration.connection_state,
            "runtime_state": integration.runtime_state,
            "updated_at": protection.updated_at,
            "updated_by": protection.updated_by,
        }
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
        context={**_admin_ui_context(user),
                 "comparison_report": load_comparison_presentation(EVALUATION_DATASET)},
    )


@router.get("/evaluation", response_class=HTMLResponse)
def evaluation_page(
    request: Request,
    user: User = Depends(get_current_user),
) -> HTMLResponse:
    require_portal(user, PortalScope.admin)
    case_count = 0
    if EVALUATION_DATASET.exists():
        with EVALUATION_DATASET.open("r", encoding="utf-8") as dataset:
            case_count = sum(1 for line in dataset if line.strip())
    return templates.TemplateResponse(
        request=request,
        name="evaluation.html",
        context={
            **_admin_ui_context(user),
            "benchmark_case_count": case_count,
            "benchmark_report": load_benchmark_presentation(EVALUATION_DATASET),
        },
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


def _render_application_detail(
    request: Request,
    user: User,
    application_id: str,
) -> HTMLResponse:
    application = get_application(application_id)
    if application is None:
        raise HTTPException(status_code=404, detail="Application not found.")
    return templates.TemplateResponse(
        request=request,
        name="application_detail.html",
        context={
            **_admin_ui_context(user),
            "application": application,
            "integration": integration_status_for(application),
            "credentials": list_credentials(application_id),
            "created_credential": None,
            "protection_audit": list_protection_audit(application_id),
        },
    )
