from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import os
import secrets

from fastapi import APIRouter, Cookie, Depends, Header, HTTPException, Response, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import PortalScope, User, UserRole

router = APIRouter(prefix="/auth", tags=["auth"])


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    username: str
    role: str
    portal_scope: str


def _secret_key() -> bytes:
    return os.getenv("LLMGUARD_AUTH_SECRET", "llmguard-local-development-secret").encode("utf-8")


def hash_password(password: str, *, salt: str | None = None) -> str:
    active_salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        active_salt.encode("utf-8"),
        120_000,
    ).hex()
    return f"pbkdf2_sha256${active_salt}${digest}"


def verify_password(password: str, password_hash: str) -> bool:
    try:
        algorithm, salt, expected = password_hash.split("$", 2)
    except ValueError:
        return False
    if algorithm != "pbkdf2_sha256":
        return False
    candidate = hash_password(password, salt=salt).split("$", 2)[2]
    return hmac.compare_digest(candidate, expected)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _unb64url(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def create_access_token(user: User, *, expires_delta: timedelta | None = None) -> str:
    expires_at = datetime.now(timezone.utc) + (expires_delta or timedelta(hours=8))
    payload = {
        "sub": user.username,
        "uid": user.id,
        "role": user.role.value,
        "exp": int(expires_at.timestamp()),
    }
    body = _b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signature = hmac.new(_secret_key(), body.encode("ascii"), hashlib.sha256).digest()
    return f"{body}.{_b64url(signature)}"


def decode_access_token(token: str) -> dict[str, object]:
    try:
        body, signature = token.split(".", 1)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token") from exc
    expected = _b64url(hmac.new(_secret_key(), body.encode("ascii"), hashlib.sha256).digest())
    if not hmac.compare_digest(signature, expected):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token signature")
    payload = json.loads(_unb64url(body))
    if int(payload.get("exp", 0)) < int(datetime.now(timezone.utc).timestamp()):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")
    return payload


def get_current_user(
    authorization: str | None = Header(default=None),
    llmguard_token: str | None = Cookie(default=None),
    db: Session = Depends(get_db),
) -> User:
    token = None
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1].strip()
    elif llmguard_token:
        token = llmguard_token
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing bearer token")
    payload = decode_access_token(token)
    user = db.scalar(select(User).where(User.username == str(payload["sub"])))
    if user is None or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found or inactive")
    return user


def seed_development_users(db: Session) -> list[User]:
    seed_specs = (
        ("student1", "Student@123", UserRole.student, PortalScope.student, "DEMO-STUDENT-001"),
        ("employee1", "Employee@123", UserRole.employee, PortalScope.employee, "DEMO-EMPLOYEE-001"),
        ("admin1", "Admin@123", UserRole.super_admin, PortalScope.admin, "DEMO-ADMIN-001"),
    )
    users: list[User] = []
    for username, password, role, scope, synthetic_ref in seed_specs:
        user = db.scalar(select(User).where(User.username == username))
        if user is None:
            user = User(
                username=username,
                password_hash=hash_password(password),
                role=role,
                portal_scope=scope,
                synthetic_ref=synthetic_ref,
                is_active=True,
            )
            db.add(user)
            db.flush()
        users.append(user)
    db.commit()
    return users


@router.post("/login", response_model=LoginResponse)
def login(request: LoginRequest, response: Response, db: Session = Depends(get_db)) -> LoginResponse:
    user = db.scalar(select(User).where(User.username == request.username))
    if user is None or not verify_password(request.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password")
    token = create_access_token(user)
    response.set_cookie(
        key="llmguard_token",
        value=token,
        httponly=True,
        samesite="lax",
        secure=False,
        max_age=8 * 60 * 60,
    )
    return LoginResponse(
        access_token=token,
        username=user.username,
        role=user.role.value,
        portal_scope=user.portal_scope.value,
    )


@router.post("/logout")
def logout(response: Response) -> dict[str, bool]:
    response.delete_cookie("llmguard_token")
    return {"logged_out": True}


@router.get("/me")
def current_user(user: User = Depends(get_current_user)) -> dict[str, object]:
    return {
        "username": user.username,
        "role": user.role.value,
        "portal_scope": user.portal_scope.value,
        "synthetic_ref": user.synthetic_ref,
    }
