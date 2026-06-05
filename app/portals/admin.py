from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth import get_current_user
from app.database import get_db
from app.models import AuditLog, FirewallEvent, PortalRecord, PortalScope, RedteamCase, User
from app.portals.common import (
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

router = APIRouter(prefix="/admin", tags=["super-admin-portal"])


@router.get("/dashboard", response_class=HTMLResponse)
def admin_dashboard(
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    require_portal(user, PortalScope.admin)
    records = accessible_records(db, user)
    return templates.TemplateResponse(
        request=request,
        name="admin_dashboard.html",
        context=render_context(user, PortalScope.admin, records),
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
                    "detector": event.detector,
                    "action": event.action.value,
                    "label": event.label.value,
                    "score": event.score,
                    "reason": event.reason,
                    "created_at": event.created_at.isoformat(),
                }
                for event in events
            ],
            "audit_logs": [
                {
                    "event_type": log.event_type,
                    "summary": log.summary,
                    "actor_role": log.actor_role,
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
