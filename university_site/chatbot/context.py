from __future__ import annotations

import base64
import hashlib
import hmac
import secrets

from fastapi import HTTPException, Request
from sqlalchemy.orm import Session

from ..auth import SESSION_COOKIE, SESSION_SECRET, read_session
from ..repository import get_employee, get_student
from .types import ChatIdentity


PUBLIC_CHAT_COOKIE = "uoh_public_chat"


def create_public_token(owner_id: str) -> str:
    raw = owner_id.encode("ascii")
    signature = hmac.new(SESSION_SECRET, b"public-chat:" + raw, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(raw + b"." + signature).decode("ascii").rstrip("=")


def read_public_token(token: str | None) -> str | None:
    if not token:
        return None
    try:
        decoded = base64.urlsafe_b64decode(token.encode("ascii") + b"=" * (-len(token) % 4))
        raw, signature = decoded.split(b".", 1)
        expected = hmac.new(SESSION_SECRET, b"public-chat:" + raw, hashlib.sha256).digest()
        owner = raw.decode("ascii")
        if hmac.compare_digest(signature, expected) and len(owner) == 32:
            return owner
    except (ValueError, UnicodeDecodeError):
        return None
    return None


def resolve_identity(request: Request, session: Session, portal_context: str) -> tuple[ChatIdentity, str | None]:
    if portal_context == "public":
        public_id = read_public_token(request.cookies.get(PUBLIC_CHAT_COOKIE))
        new_token = None
        if public_id is None:
            public_id = secrets.token_hex(16)
            new_token = create_public_token(public_id)
        return ChatIdentity("public", f"public:{public_id}"), new_token

    payload = read_session(request.cookies.get(SESSION_COOKIE))
    if not payload:
        raise HTTPException(status_code=401, detail=f"{portal_context.title()} Portal authentication is required.")
    if payload.get("portal") != portal_context or payload.get("role") != portal_context:
        raise HTTPException(status_code=403, detail="This session is not authorized for the requested assistant.")
    user_id = int(payload["user_id"])
    username = str(payload["username"])
    if portal_context == "student":
        student = get_student(session, user_id, username)
        if student is None:
            raise HTTPException(status_code=401, detail="Student Portal session is no longer valid.")
        return ChatIdentity("student", f"student:{student.id}", student.id, student=student), None
    if portal_context == "employee":
        employee = get_employee(session, user_id, username)
        if employee is None:
            raise HTTPException(status_code=401, detail="Employee Portal session is no longer valid.")
        return ChatIdentity("employee", f"employee:{employee.id}", employee.id, employee=employee), None
    raise HTTPException(status_code=404, detail="Unknown assistant context.")
