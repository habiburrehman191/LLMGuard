from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import sqlite3
from typing import Literal

from app.config import get_settings
from app.db import get_connection
from app.session_risk import (
    GuardClassification,
    RiskState,
    SecuritySessionRecord,
    list_recent_session_events,
)


SessionPolicyCode = Literal[
    "SESSION_RESTRICT_REPEATED_SUSPICIOUS",
    "SESSION_RESTRICT_REPEATED_MALICIOUS",
]


@dataclass(frozen=True, slots=True)
class SessionEnforcementDecision:
    session_enforced: bool
    session_policy_code: SessionPolicyCode | None
    session_state: RiskState
    recent_suspicious_event_count: int
    recent_malicious_event_count: int


@dataclass(frozen=True, slots=True)
class SessionEnforcementEvent:
    id: int
    application_id: str
    channel: str
    session_hash: str
    request_id: str
    policy_code: str
    created_at: str


def evaluate_input_session_policy(
    *,
    session: SecuritySessionRecord,
    current_classification: GuardClassification,
    current_action: str,
    current_risk_score: float,
    evaluated_at: datetime | None = None,
) -> SessionEnforcementDecision:
    """Apply bounded session policy without changing the detector outcome."""
    if not 0 <= current_risk_score <= 1:
        raise ValueError("current_risk_score must be between 0 and 1")

    settings = get_settings()
    now = evaluated_at or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    since = now.astimezone(timezone.utc) - timedelta(
        seconds=settings.session_enforcement_window_seconds
    )
    events = list_recent_session_events(
        session.id,
        stage="input",
        since=since,
        limit=settings.session_recent_event_limit,
    )
    recent_suspicious = sum(
        event.classification == "suspicious" for event in events
    )
    recent_malicious = sum(
        event.classification == "malicious" for event in events
    )
    recent_state: RiskState
    if recent_malicious:
        recent_state = "MALICIOUS"
    elif recent_suspicious:
        recent_state = "SUSPICIOUS"
    else:
        recent_state = "SAFE"

    base = SessionEnforcementDecision(
        session_enforced=False,
        session_policy_code=None,
        session_state=recent_state,
        recent_suspicious_event_count=recent_suspicious,
        recent_malicious_event_count=recent_malicious,
    )

    # A detector restriction remains a detector restriction. Session policy is
    # evaluated only for traffic the per-request detector would otherwise allow.
    if current_action not in {"allow", "log"}:
        return base
    if current_classification == "malicious":
        return base

    if (
        session.malicious_event_count
        >= settings.session_malicious_event_threshold
        and recent_malicious >= settings.session_malicious_event_threshold
    ):
        return SessionEnforcementDecision(
            session_enforced=True,
            session_policy_code="SESSION_RESTRICT_REPEATED_MALICIOUS",
            session_state="MALICIOUS",
            recent_suspicious_event_count=recent_suspicious,
            recent_malicious_event_count=recent_malicious,
        )
    if (
        session.suspicious_event_count
        >= settings.session_suspicious_event_threshold
        and recent_suspicious >= settings.session_suspicious_event_threshold
    ):
        return SessionEnforcementDecision(
            session_enforced=True,
            session_policy_code="SESSION_RESTRICT_REPEATED_SUSPICIOUS",
            session_state="SUSPICIOUS",
            recent_suspicious_event_count=recent_suspicious,
            recent_malicious_event_count=recent_malicious,
        )
    return base


def record_session_enforcement(
    *,
    session: SecuritySessionRecord,
    request_id: str,
    policy_code: SessionPolicyCode,
) -> SessionEnforcementEvent:
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    try:
        with conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO session_enforcement_events (
                    application_id,
                    channel,
                    session_hash,
                    request_id,
                    policy_code
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    session.application_id,
                    session.channel,
                    session.session_hash,
                    request_id,
                    policy_code,
                ),
            )
            row = conn.execute(
                """
                SELECT * FROM session_enforcement_events
                WHERE application_id = ?
                  AND channel = ?
                  AND request_id = ?
                  AND policy_code = ?
                """,
                (
                    session.application_id,
                    session.channel,
                    request_id,
                    policy_code,
                ),
            ).fetchone()
    finally:
        conn.close()
    if row is None:
        raise RuntimeError("Session enforcement telemetry could not be stored")
    return SessionEnforcementEvent(
        id=int(row["id"]),
        application_id=str(row["application_id"]),
        channel=str(row["channel"]),
        session_hash=str(row["session_hash"]),
        request_id=str(row["request_id"]),
        policy_code=str(row["policy_code"]),
        created_at=str(row["created_at"]),
    )
