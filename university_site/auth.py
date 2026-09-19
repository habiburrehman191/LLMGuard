from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass


SESSION_COOKIE = "uoh_demo_session"
SESSION_TTL_SECONDS = 8 * 60 * 60
PBKDF2_ITERATIONS = 260_000
SESSION_SECRET = os.environ.get(
    "UOH_DEMO_SESSION_SECRET",
    "local-uoh-academic-demo-only-change-before-shared-deployment",
).encode("utf-8")


@dataclass(frozen=True)
class AuthenticatedUser:
    user_id: int
    username: str
    role: str
    portal: str
    display_name: str


def hash_password(salt_key: str, password: str) -> str:
    salt = f"uoh-controlled-demo::{salt_key.lower()}"
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"), PBKDF2_ITERATIONS
    ).hex()
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt}${digest}"


def verify_password(_username: str, password: str, encoded: str) -> bool:
    try:
        algorithm, iterations, salt, expected = encoded.split("$", 3)
        if algorithm != "pbkdf2_sha256" or int(iterations) != PBKDF2_ITERATIONS:
            return False
        if not salt.startswith("uoh-controlled-demo::"):
            return False
        candidate = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt.encode("utf-8"), PBKDF2_ITERATIONS
        ).hex()
        return hmac.compare_digest(candidate, expected)
    except (TypeError, ValueError):
        return False


def create_session(user: AuthenticatedUser) -> str:
    payload = {
        "user_id": user.user_id,
        "username": user.username,
        "role": user.role,
        "portal": user.portal,
        "display_name": user.display_name,
        "issued_at": int(time.time()),
    }
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    encoded = base64.urlsafe_b64encode(raw).rstrip(b"=")
    signature = hmac.new(SESSION_SECRET, encoded, hashlib.sha256).digest()
    signed = encoded + b"." + base64.urlsafe_b64encode(signature).rstrip(b"=")
    return signed.decode("ascii")


def read_session(token: str | None) -> dict[str, object] | None:
    if not token or "." not in token:
        return None
    try:
        payload_part, signature_part = token.encode("ascii").split(b".", 1)
        expected = hmac.new(SESSION_SECRET, payload_part, hashlib.sha256).digest()
        supplied = base64.urlsafe_b64decode(signature_part + b"=" * (-len(signature_part) % 4))
        if not hmac.compare_digest(expected, supplied):
            return None
        raw = base64.urlsafe_b64decode(payload_part + b"=" * (-len(payload_part) % 4))
        payload = json.loads(raw.decode("utf-8"))
        issued_at = int(payload.get("issued_at", 0))
        if issued_at <= 0 or time.time() - issued_at > SESSION_TTL_SECONDS:
            return None
        if payload.get("portal") not in {"student", "employee", "administration"}:
            return None
        if not isinstance(payload.get("user_id"), int):
            return None
        return payload
    except (ValueError, TypeError, json.JSONDecodeError, UnicodeDecodeError):
        return None
