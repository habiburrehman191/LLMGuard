from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import hmac
import secrets
import sqlite3

from app.application_registry import get_application
from app.db import get_connection


ACTIVE_STATUS = "ACTIVE"
REVOKED_STATUS = "REVOKED"
_DUMMY_SECRET_HASH = "sha256$" + ("0" * 64)


@dataclass(frozen=True, slots=True)
class CredentialRecord:
    id: int
    application_id: str
    key_id: str
    status: str
    created_at: str
    expires_at: str | None
    revoked_at: str | None
    last_used_at: str | None

    @property
    def effective_status(self) -> str:
        if self.status == ACTIVE_STATUS and _timestamp_has_passed(self.expires_at):
            return "EXPIRED"
        return self.status


@dataclass(frozen=True, slots=True)
class CreatedCredential:
    credential: CredentialRecord
    secret: str = field(repr=False)


def create_credential(
    application_id: str,
    *,
    expires_at: datetime | None = None,
) -> CreatedCredential:
    """Create a credential, returning its plaintext secret only in this result."""
    normalized_application_id = application_id.strip()
    if get_application(normalized_application_id) is None:
        raise ValueError("Application is not registered")

    normalized_expiry = _normalize_expiry(expires_at)
    created_at = _serialize_timestamp(_utc_now())
    secret = f"llmg_secret_{secrets.token_urlsafe(32)}"
    secret_hash = _hash_secret(secret)

    conn = get_connection()
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        for _ in range(5):
            key_id = f"llmg_key_{secrets.token_urlsafe(12)}"
            try:
                with conn:
                    cursor = conn.execute(
                        """
                        INSERT INTO api_credentials (
                            application_id,
                            key_id,
                            secret_hash,
                            status,
                            created_at,
                            expires_at
                        )
                        VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (
                            normalized_application_id,
                            key_id,
                            secret_hash,
                            ACTIVE_STATUS,
                            created_at,
                            normalized_expiry,
                        ),
                    )
                credential_id = int(cursor.lastrowid)
                break
            except sqlite3.IntegrityError as exc:
                if "key_id" not in str(exc).lower():
                    raise
        else:
            raise RuntimeError("Unable to generate a unique credential key ID")
    finally:
        conn.close()

    credential = _get_credential(normalized_application_id, key_id)
    if credential is None or credential.id != credential_id:
        raise RuntimeError("Created credential could not be loaded")
    return CreatedCredential(credential=credential, secret=secret)


def verify_credential(application_id: str, key_id: str, secret: str) -> bool:
    """Verify an active, unexpired credential and record its successful use."""
    candidate_hash = _hash_secret(secret)
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    try:
        with conn:
            row = conn.execute(
                """
                SELECT id, secret_hash, status, expires_at, revoked_at
                FROM api_credentials
                WHERE application_id = ? AND key_id = ?
                """,
                (application_id, key_id),
            ).fetchone()
            stored_hash = row["secret_hash"] if row is not None else _DUMMY_SECRET_HASH
            secret_matches = hmac.compare_digest(candidate_hash, stored_hash)
            if (
                row is None
                or not secret_matches
                or row["status"] != ACTIVE_STATUS
                or row["revoked_at"] is not None
                or _timestamp_has_passed(row["expires_at"])
            ):
                return False

            used_at = _serialize_timestamp(_utc_now())
            cursor = conn.execute(
                """
                UPDATE api_credentials
                SET last_used_at = ?
                WHERE id = ? AND status = ? AND revoked_at IS NULL
                """,
                (used_at, row["id"], ACTIVE_STATUS),
            )
            return cursor.rowcount == 1
    finally:
        conn.close()


def list_credentials(application_id: str) -> list[CredentialRecord]:
    """List credential metadata without returning secret hashes or plaintext."""
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            """
            SELECT
                id,
                application_id,
                key_id,
                status,
                created_at,
                expires_at,
                revoked_at,
                last_used_at
            FROM api_credentials
            WHERE application_id = ?
            ORDER BY id DESC
            """,
            (application_id,),
        ).fetchall()
    finally:
        conn.close()
    return [_credential_from_row(row) for row in rows]


def revoke_credential(application_id: str, key_id: str) -> bool:
    """Revoke an active credential within its owning application."""
    revoked_at = _serialize_timestamp(_utc_now())
    conn = get_connection()
    try:
        with conn:
            cursor = conn.execute(
                """
                UPDATE api_credentials
                SET status = ?, revoked_at = ?
                WHERE application_id = ?
                  AND key_id = ?
                  AND status = ?
                  AND revoked_at IS NULL
                """,
                (
                    REVOKED_STATUS,
                    revoked_at,
                    application_id,
                    key_id,
                    ACTIVE_STATUS,
                ),
            )
            return cursor.rowcount == 1
    finally:
        conn.close()


def _get_credential(application_id: str, key_id: str) -> CredentialRecord | None:
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute(
            """
            SELECT
                id,
                application_id,
                key_id,
                status,
                created_at,
                expires_at,
                revoked_at,
                last_used_at
            FROM api_credentials
            WHERE application_id = ? AND key_id = ?
            """,
            (application_id, key_id),
        ).fetchone()
    finally:
        conn.close()
    return _credential_from_row(row) if row is not None else None


def _credential_from_row(row: sqlite3.Row) -> CredentialRecord:
    return CredentialRecord(
        id=row["id"],
        application_id=row["application_id"],
        key_id=row["key_id"],
        status=row["status"],
        created_at=row["created_at"],
        expires_at=row["expires_at"],
        revoked_at=row["revoked_at"],
        last_used_at=row["last_used_at"],
    )


def _hash_secret(secret: str) -> str:
    digest = hashlib.sha256(secret.encode("utf-8")).hexdigest()
    return f"sha256${digest}"


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _serialize_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds")


def _normalize_expiry(expires_at: datetime | None) -> str | None:
    if expires_at is None:
        return None
    normalized = (
        expires_at.replace(tzinfo=timezone.utc)
        if expires_at.tzinfo is None
        else expires_at.astimezone(timezone.utc)
    )
    if normalized <= _utc_now():
        raise ValueError("Credential expiry must be in the future")
    return _serialize_timestamp(normalized)


def _timestamp_has_passed(value: str | None) -> bool:
    if value is None:
        return False
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc) <= _utc_now()
