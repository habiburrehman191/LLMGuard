from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from sqlalchemy import select
from urllib.parse import urlsplit

from ..database import SessionLocal
from ..models import ChatConversation, ChatMessage
from .context import PUBLIC_CHAT_COOKIE, resolve_identity
from .schemas import ChatRequest, ConversationRequest, FeedbackRequest
from .service import (
    ask,
    conversation_detail,
    create_conversation,
    delete_conversation,
    list_conversations,
    record_feedback,
)


router = APIRouter(tags=["University AI Assistant"])
VALID_CONTEXTS = {"public", "student", "employee"}


def _authoritative_page(request: Request, portal_context: str) -> tuple[str, str]:
    """Derive assistant page context from the browser request, never request JSON."""
    referer = request.headers.get("referer", "")
    path = urlsplit(referer).path if referer else ""
    if portal_context == "student":
        path = path if path.startswith("/portal/student/") else "/portal/student/dashboard"
    elif portal_context == "employee":
        path = path if path.startswith("/portal/employee/") else "/portal/employee/dashboard"
    elif path.startswith("/portal/student/") or path.startswith("/portal/employee/"):
        path = "/"
    elif not path:
        path = "/"
    titles = {
        "/": "University of Haripur",
        "/portal/student/dashboard": "Student Dashboard",
        "/portal/student/results": "Student Results",
        "/portal/student/attendance": "Student Attendance",
        "/portal/student/fees": "Student Fees",
        "/portal/student/timetable": "Student Timetable",
        "/portal/employee/dashboard": "Employee Dashboard",
        "/portal/employee/policies": "University Policies",
        "/portal/employee/directory": "Employee Directory",
        "/portal/employee/controlled-records": "Controlled Records",
        "/university/admissions/eligibility": "Admission Eligibility",
        "/university/admissions/fee": "Fee Structure",
        "/university/admissions/schedule": "Admission Schedule",
        "/university/admissions/bs-programs": "BS Programs",
    }
    return path, titles.get(path, path.rstrip("/").rsplit("/", 1)[-1].replace("-", " ").title() or "University of Haripur")


def _response(payload: object, public_token: str | None = None, status_code: int = 200) -> JSONResponse:
    response = JSONResponse(payload, status_code=status_code)
    if public_token:
        response.set_cookie(
            PUBLIC_CHAT_COOKIE, public_token, max_age=30 * 24 * 60 * 60,
            httponly=True, samesite="lax", secure=False, path="/",
        )
    return response


def _validate_context(portal_context: str) -> None:
    if portal_context not in VALID_CONTEXTS:
        raise HTTPException(status_code=404, detail="Unknown assistant context.")


@router.post("/api/university/chat/{portal_context}")
def chat(portal_context: str, payload: ChatRequest, request: Request) -> JSONResponse:
    _validate_context(portal_context)
    with SessionLocal() as session:
        identity, public_token = resolve_identity(request, session, portal_context)
        current_page, page_title = _authoritative_page(request, identity.portal_context)
        try:
            result = ask(session, identity, payload.question, payload.conversation_id, current_page, page_title)
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
    return _response(result, public_token)


@router.post("/api/university/chat/{portal_context}/conversations")
def new_conversation(portal_context: str, payload: ConversationRequest, request: Request) -> JSONResponse:
    _validate_context(portal_context)
    with SessionLocal() as session:
        identity, public_token = resolve_identity(request, session, portal_context)
        conversation = create_conversation(session, identity, payload.title)
        result = {"id": conversation.id, "title": conversation.title, "portal_context": portal_context}
    return _response(result, public_token, 201)


@router.get("/api/university/chat/{portal_context}/conversations")
def conversations(portal_context: str, request: Request) -> JSONResponse:
    _validate_context(portal_context)
    with SessionLocal() as session:
        identity, public_token = resolve_identity(request, session, portal_context)
        result = list_conversations(session, identity)
    return _response({"conversations": result, "portal_context": portal_context}, public_token)


@router.get("/api/university/chat/{portal_context}/conversations/{conversation_id}")
def get_conversation(portal_context: str, conversation_id: int, request: Request) -> JSONResponse:
    _validate_context(portal_context)
    with SessionLocal() as session:
        identity, public_token = resolve_identity(request, session, portal_context)
        try:
            result = conversation_detail(session, identity, conversation_id)
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
    return _response(result, public_token)


@router.delete("/api/university/chat/{portal_context}/conversations/{conversation_id}")
def remove_conversation(portal_context: str, conversation_id: int, request: Request) -> JSONResponse:
    _validate_context(portal_context)
    with SessionLocal() as session:
        identity, public_token = resolve_identity(request, session, portal_context)
        if not delete_conversation(session, identity, conversation_id):
            raise HTTPException(status_code=403, detail="Conversation is not available to this user.")
    return _response({"deleted": True, "conversation_id": conversation_id}, public_token)


@router.post("/api/university/chat/messages/{message_id}/feedback")
def feedback(message_id: int, payload: FeedbackRequest, request: Request) -> JSONResponse:
    with SessionLocal() as session:
        portal_context = session.scalar(
            select(ChatConversation.portal_context).join(ChatMessage).where(ChatMessage.id == message_id)
        )
        if portal_context not in VALID_CONTEXTS:
            raise HTTPException(status_code=404, detail="Assistant message was not found.")
        identity, public_token = resolve_identity(request, session, str(portal_context))
        try:
            stored = record_feedback(session, identity, message_id, payload.rating, payload.reason, payload.comment)
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
    return _response({"recorded": True, "feedback_id": stored.id, "message": "Thank you. Your feedback has been recorded."}, public_token)
