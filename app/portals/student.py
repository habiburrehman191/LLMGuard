from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy.orm import Session

from app.auth import get_current_user
from app.database import get_db
from app.models import PortalScope, User
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

router = APIRouter(prefix="/student", tags=["student-portal"])


@router.get("/dashboard", response_class=HTMLResponse)
def student_dashboard(
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    require_portal(user, PortalScope.student)
    records = accessible_records(db, user, PortalScope.student)
    return templates.TemplateResponse(
        request=request,
        name="student_dashboard.html",
        context=render_context(user, PortalScope.student, records),
    )


@router.get("/records", response_class=JSONResponse)
def student_records(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> JSONResponse:
    require_portal(user, PortalScope.student)
    records = accessible_records(db, user, PortalScope.student)
    return JSONResponse({"records": [_record_payload(record) for record in records]})


@router.post("/ai/ask", response_class=JSONResponse)
def student_ai_ask(
    request: PortalAskRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> JSONResponse:
    payload = ask_portal_ai(user, request, PortalScope.student, db)
    return JSONResponse(payload)


@router.post("/documents/upload", response_class=JSONResponse)
def student_upload_document(
    request: PortalDocumentUploadRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> JSONResponse:
    document = create_document_record(db, user=user, portal_scope=PortalScope.student, request=request)
    return JSONResponse(
        {
            "document_id": document.document_id,
            "classification": document.classification.value,
            "chunks": len(document.chunks),
            "source_filename": document.source_filename,
        }
    )


def _record_payload(record) -> dict[str, object]:
    return {
        "record_id": record.record_id,
        "title": record.title,
        "portal_scope": record.portal_scope.value,
        "classification": record.classification.value,
        "content": record.content,
        "is_synthetic": record.is_synthetic,
    }
