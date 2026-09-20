from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import hashlib
import hmac
import sqlite3
from typing import Any, Literal

from app.config import get_settings
from app.db import get_connection


RiskState = Literal["SAFE", "SUSPICIOUS", "MALICIOUS"]
GuardClassification = Literal["safe", "suspicious", "malicious"]
GuardStage = Literal["input", "context", "output", "ingestion"]

_RISK_STATE_RANK: dict[str, int] = {
    "SAFE": 0,
    "SUSPICIOUS": 1,
    "MALICIOUS": 2,
}


@dataclass(frozen=True, slots=True)
class SecuritySessionRecord:
    id: int
    application_id: str
    channel: str
    session_hash: str
    first_seen: str
    last_seen: str
    request_count: int
    suspicious_event_count: int
    malicious_event_count: int
    latest_risk_score: float | None
    max_risk_score: float | None
    risk_state: RiskState


@dataclass(frozen=True, slots=True)
class SecuritySessionEventRecord:
    id: int
    security_session_id: int
    request_id: str
    stage: GuardStage
    classification: GuardClassification
    risk_score: float | None
    action: str
    created_at: str


def record_session_risk_event(
    *,
    application_id: str,
    channel: str,
    request_id: str,
    stage: GuardStage,
    classification: GuardClassification,
    risk_score: float | None,
    action: str,
    security_context: Mapping[str, Any] | None = None,
) -> SecuritySessionRecord | None:
    """Record non-content guard evidence without affecting the guard decision."""
    _validate_event(stage, classification, risk_score)
    session_hash = _session_hash_from_context(
        application_id,
        channel,
        security_context,
    )

    conn = get_connection()
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        with conn:
            session_row = None
            if session_hash is None:
                session_row = conn.execute(
                    """
                    SELECT s.*
                    FROM security_sessions AS s
                    JOIN security_session_events AS e
                      ON e.security_session_id = s.id
                    WHERE s.application_id = ?
                      AND s.channel = ?
                      AND e.request_id = ?
                    ORDER BY e.id
                    LIMIT 1
                    """,
                    (application_id, channel, request_id),
                ).fetchone()
                if session_row is None:
                    return None
                session_hash = str(session_row["session_hash"])

            conn.execute(
                """
                INSERT OR IGNORE INTO security_sessions (
                    application_id,
                    channel,
                    session_hash
                )
                VALUES (?, ?, ?)
                """,
                (application_id, channel, session_hash),
            )
            session_row = conn.execute(
                """
                SELECT *
                FROM security_sessions
                WHERE application_id = ? AND channel = ? AND session_hash = ?
                """,
                (application_id, channel, session_hash),
            ).fetchone()
            if session_row is None:
                raise RuntimeError("Security session could not be initialized")

            prior_request = conn.execute(
                """
                SELECT 1
                FROM security_session_events
                WHERE security_session_id = ? AND request_id = ?
                LIMIT 1
                """,
                (session_row["id"], request_id),
            ).fetchone()
            cursor = conn.execute(
                """
                INSERT OR IGNORE INTO security_session_events (
                    security_session_id,
                    request_id,
                    stage,
                    classification,
                    risk_score,
                    action
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    session_row["id"],
                    request_id,
                    stage,
                    classification,
                    risk_score,
                    action,
                ),
            )
            if cursor.rowcount:
                new_state = _higher_risk_state(
                    str(session_row["risk_state"]),
                    classification.upper(),
                )
                conn.execute(
                    """
                    UPDATE security_sessions
                    SET
                        last_seen = CURRENT_TIMESTAMP,
                        request_count = request_count + ?,
                        suspicious_event_count = suspicious_event_count + ?,
                        malicious_event_count = malicious_event_count + ?,
                        latest_risk_score = CASE
                            WHEN ? IS NULL THEN latest_risk_score ELSE ?
                        END,
                        max_risk_score = CASE
                            WHEN ? IS NULL THEN max_risk_score
                            WHEN max_risk_score IS NULL OR ? > max_risk_score THEN ?
                            ELSE max_risk_score
                        END,
                        risk_state = ?
                    WHERE id = ?
                    """,
                    (
                        0 if prior_request else 1,
                        1 if classification == "suspicious" else 0,
                        1 if classification == "malicious" else 0,
                        risk_score,
                        risk_score,
                        risk_score,
                        risk_score,
                        risk_score,
                        new_state,
                        session_row["id"],
                    ),
                )

            stored = conn.execute(
                "SELECT * FROM security_sessions WHERE id = ?",
                (session_row["id"],),
            ).fetchone()
    finally:
        conn.close()
    if stored is None:
        raise RuntimeError("Security session could not be loaded after persistence")
    return _session_from_row(stored)


def get_session_risk(
    application_id: str,
    channel: str,
    session_identifier: str,
) -> SecuritySessionRecord | None:
    session_hash = pseudonymize_session_identifier(
        application_id,
        channel,
        session_identifier,
    )
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute(
            """
            SELECT * FROM security_sessions
            WHERE application_id = ? AND channel = ? AND session_hash = ?
            """,
            (application_id, channel, session_hash),
        ).fetchone()
    finally:
        conn.close()
    return _session_from_row(row) if row is not None else None


def list_session_events(
    security_session_id: int,
) -> list[SecuritySessionEventRecord]:
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            """
            SELECT * FROM security_session_events
            WHERE security_session_id = ?
            ORDER BY id
            """,
            (security_session_id,),
        ).fetchall()
    finally:
        conn.close()
    return [_event_from_row(row) for row in rows]


def pseudonymize_session_identifier(
    application_id: str,
    channel: str,
    session_identifier: str,
) -> str:
    normalized = session_identifier.strip()
    if not normalized or len(normalized.encode("utf-8")) > 512:
        raise ValueError("session identifier must contain 1 to 512 UTF-8 bytes")
    key = get_settings().session_hash_secret.encode("utf-8")
    message = f"{application_id}\x1f{channel}\x1f{normalized}".encode("utf-8")
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def _session_hash_from_context(
    application_id: str,
    channel: str,
    security_context: Mapping[str, Any] | None,
) -> str | None:
    if not security_context:
        return None
    identifier = security_context.get("session_id")
    if not isinstance(identifier, str) or not identifier.strip():
        return None
    return pseudonymize_session_identifier(
        application_id,
        channel,
        identifier,
    )


def _validate_event(
    stage: str,
    classification: str,
    risk_score: float | None,
) -> None:
    if stage not in {"input", "context", "output", "ingestion"}:
        raise ValueError("Unsupported guard stage")
    if classification not in {"safe", "suspicious", "malicious"}:
        raise ValueError("Unsupported guard classification")
    if risk_score is not None and not 0 <= risk_score <= 1:
        raise ValueError("risk_score must be between 0 and 1")


def _higher_risk_state(current: str, candidate: str) -> RiskState:
    if _RISK_STATE_RANK[candidate] > _RISK_STATE_RANK[current]:
        return candidate  # type: ignore[return-value]
    return current  # type: ignore[return-value]


def _session_from_row(row: sqlite3.Row) -> SecuritySessionRecord:
    return SecuritySessionRecord(
        id=int(row["id"]),
        application_id=str(row["application_id"]),
        channel=str(row["channel"]),
        session_hash=str(row["session_hash"]),
        first_seen=str(row["first_seen"]),
        last_seen=str(row["last_seen"]),
        request_count=int(row["request_count"]),
        suspicious_event_count=int(row["suspicious_event_count"]),
        malicious_event_count=int(row["malicious_event_count"]),
        latest_risk_score=(
            float(row["latest_risk_score"])
            if row["latest_risk_score"] is not None
            else None
        ),
        max_risk_score=(
            float(row["max_risk_score"])
            if row["max_risk_score"] is not None
            else None
        ),
        risk_state=str(row["risk_state"]),  # type: ignore[arg-type]
    )


def _event_from_row(row: sqlite3.Row) -> SecuritySessionEventRecord:
    return SecuritySessionEventRecord(
        id=int(row["id"]),
        security_session_id=int(row["security_session_id"]),
        request_id=str(row["request_id"]),
        stage=str(row["stage"]),  # type: ignore[arg-type]
        classification=str(row["classification"]),  # type: ignore[arg-type]
        risk_score=(
            float(row["risk_score"]) if row["risk_score"] is not None else None
        ),
        action=str(row["action"]),
        created_at=str(row["created_at"]),
    )
