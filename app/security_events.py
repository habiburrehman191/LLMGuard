from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import sqlite3
from typing import Literal
from uuid import uuid4

from app.db import get_connection


Severity = Literal["none", "low", "medium", "high", "critical"]
IncidentStatus = Literal["OPEN", "ACKNOWLEDGED", "RESOLVED"]

_SEVERITY_RANK = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_INCIDENT_TRANSITIONS: dict[str, set[str]] = {
    "OPEN": {"ACKNOWLEDGED", "RESOLVED"},
    "ACKNOWLEDGED": {"RESOLVED"},
    "RESOLVED": set(),
}


class InvalidIncidentTransitionError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class SecurityEventRecord:
    event_id: str
    application_id: str
    channel: str
    request_id: str | None
    session_hash: str | None
    stage: str
    event_type: str
    classification: str
    severity: Severity
    risk_score: float | None
    action: str
    source_id: str | None
    chunk_id: str | None
    created_at: str


@dataclass(frozen=True, slots=True)
class SecurityIncidentRecord:
    incident_id: str
    application_id: str
    status: IncidentStatus
    severity: str
    primary_event_id: str
    first_seen: str
    last_seen: str
    event_count: int
    category: str
    summary_code: str


@dataclass(frozen=True, slots=True)
class IncidentStatusAuditRecord:
    id: int
    incident_id: str
    old_status: IncidentStatus
    new_status: IncidentStatus
    actor: str
    created_at: str


@dataclass(frozen=True, slots=True)
class IncidentDetail:
    incident: SecurityIncidentRecord
    events: tuple[SecurityEventRecord, ...]
    status_audit: tuple[IncidentStatusAuditRecord, ...]


@dataclass(frozen=True, slots=True)
class SecurityOverview:
    window_hours: int
    total_events: int
    suspicious_events: int
    malicious_events: int
    open_incidents: int
    blocked_events: int
    quarantined_events: int
    session_restricted_events: int
    application_breakdown: tuple[tuple[str, int], ...]
    channel_breakdown: tuple[tuple[str, str, int], ...]
    recent_events: tuple[SecurityEventRecord, ...]


@dataclass(frozen=True, slots=True)
class QuarantineEventRecord:
    event: SecurityEventRecord
    incident_id: str | None


@dataclass(frozen=True, slots=True)
class RequestTraceRecord:
    application_id: str
    events: tuple[SecurityEventRecord, ...]


def record_security_event(
    *,
    application_id: str,
    channel: str,
    stage: str,
    event_type: str,
    classification: str,
    severity: Severity,
    action: str,
    request_id: str | None = None,
    session_hash: str | None = None,
    risk_score: float | None = None,
    source_id: str | None = None,
    chunk_id: str | None = None,
) -> SecurityEventRecord:
    values = {
        "application_id": _bounded_required(application_id, "application_id", 160),
        "channel": _bounded_required(channel, "channel", 64),
        "stage": _bounded_required(stage, "stage", 64),
        "event_type": _bounded_required(event_type, "event_type", 100),
        "classification": _bounded_required(classification, "classification", 40),
        "action": _bounded_required(action, "action", 80),
        "request_id": _bounded_optional(request_id, "request_id", 200),
        "session_hash": _bounded_optional(session_hash, "session_hash", 128),
        "source_id": _bounded_optional(source_id, "source_id", 300),
        "chunk_id": _bounded_optional(chunk_id, "chunk_id", 300),
    }
    if severity not in _SEVERITY_RANK:
        raise ValueError("Unsupported security event severity")
    if risk_score is not None and not 0 <= risk_score <= 1:
        raise ValueError("risk_score must be between 0 and 1")

    created_at = _utc_timestamp()
    deduplication_key = _event_deduplication_key(**values)
    event_id = f"evt_{uuid4().hex}"
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        with conn:
            cursor = conn.execute(
                """
                INSERT OR IGNORE INTO security_events (
                    event_id,
                    application_id,
                    channel,
                    request_id,
                    session_hash,
                    stage,
                    event_type,
                    classification,
                    severity,
                    risk_score,
                    action,
                    source_id,
                    chunk_id,
                    deduplication_key,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    values["application_id"],
                    values["channel"],
                    values["request_id"],
                    values["session_hash"],
                    values["stage"],
                    values["event_type"],
                    values["classification"],
                    severity,
                    risk_score,
                    values["action"],
                    values["source_id"],
                    values["chunk_id"],
                    deduplication_key,
                    created_at,
                ),
            )
            if cursor.rowcount:
                row = conn.execute(
                    "SELECT * FROM security_events WHERE event_id = ?",
                    (event_id,),
                ).fetchone()
                if row is None:
                    raise RuntimeError("Security event could not be loaded")
                _correlate_incident(conn, row)
            else:
                row = conn.execute(
                    "SELECT * FROM security_events WHERE deduplication_key = ?",
                    (deduplication_key,),
                ).fetchone()
    finally:
        conn.close()
    if row is None:
        raise RuntimeError("Security event could not be loaded after persistence")
    return _event_from_row(row)


def record_security_event_safely(**kwargs: object) -> SecurityEventRecord | None:
    """Best-effort projection that must never change an existing firewall outcome."""
    try:
        return record_security_event(**kwargs)  # type: ignore[arg-type]
    except Exception:
        return None


def list_security_events(
    *,
    application_id: str | None = None,
    channel: str | None = None,
    stage: str | None = None,
    classification: str | None = None,
    severity: str | None = None,
    action: str | None = None,
    event_type: str | None = None,
    created_since: str | None = None,
    limit: int = 100,
) -> list[SecurityEventRecord]:
    _validate_limit(limit)
    filters = {
        "application_id": application_id,
        "channel": channel,
        "stage": stage,
        "classification": classification,
        "severity": severity,
        "action": action,
        "event_type": event_type,
    }
    clauses: list[str] = []
    parameters: list[object] = []
    for column, value in filters.items():
        if value:
            clauses.append(f"{column} = ?")
            parameters.append(value)
    if created_since:
        clauses.append("created_at >= ?")
        parameters.append(created_since)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    parameters.append(limit)
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            f"""
            SELECT * FROM security_events
            {where}
            ORDER BY created_at DESC, event_id DESC
            LIMIT ?
            """,
            tuple(parameters),
        ).fetchall()
    finally:
        conn.close()
    return [_event_from_row(row) for row in rows]


def get_security_overview(
    *,
    application_id: str | None = None,
    window_hours: int = 24,
    recent_limit: int = 8,
) -> SecurityOverview:
    if window_hours < 1 or window_hours > 24 * 30:
        raise ValueError("window_hours must be between 1 and 720")
    _validate_limit(recent_limit)
    since = (
        datetime.now(timezone.utc) - timedelta(hours=window_hours)
    ).isoformat(timespec="microseconds")
    clauses = ["created_at >= ?"]
    parameters: list[object] = [since]
    incident_clauses = ["status = 'OPEN'"]
    incident_parameters: list[object] = []
    if application_id:
        clauses.append("application_id = ?")
        parameters.append(application_id)
        incident_clauses.append("application_id = ?")
        incident_parameters.append(application_id)
    where = f"WHERE {' AND '.join(clauses)}"
    incident_where = f"WHERE {' AND '.join(incident_clauses)}"

    conn = get_connection()
    conn.row_factory = sqlite3.Row
    try:
        totals = conn.execute(
            f"""
            SELECT
                COUNT(*) AS total_events,
                SUM(CASE WHEN LOWER(classification) = 'suspicious' THEN 1 ELSE 0 END)
                    AS suspicious_events,
                SUM(CASE WHEN LOWER(classification) = 'malicious' THEN 1 ELSE 0 END)
                    AS malicious_events,
                SUM(CASE WHEN LOWER(action) = 'block' THEN 1 ELSE 0 END)
                    AS blocked_events,
                SUM(CASE WHEN LOWER(action) = 'quarantine' THEN 1 ELSE 0 END)
                    AS quarantined_events,
                SUM(CASE WHEN LOWER(action) = 'session_restrict' THEN 1 ELSE 0 END)
                    AS session_restricted_events
            FROM security_events
            {where}
            """,
            tuple(parameters),
        ).fetchone()
        open_incidents = conn.execute(
            f"SELECT COUNT(*) FROM security_incidents {incident_where}",
            tuple(incident_parameters),
        ).fetchone()[0]
        application_rows = conn.execute(
            f"""
            SELECT application_id, COUNT(*) AS event_count
            FROM security_events
            {where}
            GROUP BY application_id
            ORDER BY event_count DESC, application_id
            """,
            tuple(parameters),
        ).fetchall()
        channel_rows = conn.execute(
            f"""
            SELECT application_id, channel, COUNT(*) AS event_count
            FROM security_events
            {where}
            GROUP BY application_id, channel
            ORDER BY event_count DESC, application_id, channel
            """,
            tuple(parameters),
        ).fetchall()
    finally:
        conn.close()

    recent_events = list_security_events(
        application_id=application_id,
        created_since=since,
        limit=recent_limit,
    )
    return SecurityOverview(
        window_hours=window_hours,
        total_events=int(totals["total_events"] or 0),
        suspicious_events=int(totals["suspicious_events"] or 0),
        malicious_events=int(totals["malicious_events"] or 0),
        open_incidents=int(open_incidents or 0),
        blocked_events=int(totals["blocked_events"] or 0),
        quarantined_events=int(totals["quarantined_events"] or 0),
        session_restricted_events=int(totals["session_restricted_events"] or 0),
        application_breakdown=tuple(
            (str(row["application_id"]), int(row["event_count"]))
            for row in application_rows
        ),
        channel_breakdown=tuple(
            (
                str(row["application_id"]),
                str(row["channel"]),
                int(row["event_count"]),
            )
            for row in channel_rows
        ),
        recent_events=tuple(recent_events),
    )


def list_quarantine_events(
    *,
    application_id: str | None = None,
    limit: int = 100,
) -> list[QuarantineEventRecord]:
    _validate_limit(limit)
    clauses = ["LOWER(e.action) = 'quarantine'"]
    parameters: list[object] = []
    if application_id:
        clauses.append("e.application_id = ?")
        parameters.append(application_id)
    parameters.append(limit)
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            f"""
            SELECT e.*,
                   (
                       SELECT ie.incident_id
                       FROM security_incident_events AS ie
                       WHERE ie.event_id = e.event_id
                       ORDER BY ie.incident_id
                       LIMIT 1
                   ) AS incident_id
            FROM security_events AS e
            WHERE {' AND '.join(clauses)}
            ORDER BY e.created_at DESC, e.event_id DESC
            LIMIT ?
            """,
            tuple(parameters),
        ).fetchall()
    finally:
        conn.close()
    return [
        QuarantineEventRecord(
            event=_event_from_row(row),
            incident_id=(
                str(row["incident_id"]) if row["incident_id"] is not None else None
            ),
        )
        for row in rows
    ]


def session_policy_codes_for(
    events: list[SecurityEventRecord] | tuple[SecurityEventRecord, ...],
) -> dict[str, str]:
    session_events = [
        event
        for event in events
        if event.event_type == "SESSION_RESTRICTION" and event.request_id
    ]
    if not session_events:
        return {}
    request_ids = tuple(dict.fromkeys(event.request_id for event in session_events))
    placeholders = ", ".join("?" for _ in request_ids)
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            f"""
            SELECT application_id, channel, request_id, policy_code
            FROM session_enforcement_events
            WHERE request_id IN ({placeholders})
            ORDER BY created_at, id
            """,
            request_ids,
        ).fetchall()
    finally:
        conn.close()
    codes = {
        (str(row["application_id"]), str(row["channel"]), str(row["request_id"])):
        str(row["policy_code"])
        for row in rows
    }
    return {
        event.event_id: codes[(event.application_id, event.channel, event.request_id)]
        for event in session_events
        if (event.application_id, event.channel, event.request_id) in codes
    }


def get_request_trace(
    application_id: str,
    request_id: str,
) -> list[SecurityEventRecord]:
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            """
            SELECT * FROM security_events
            WHERE application_id = ? AND request_id = ?
            ORDER BY created_at, event_id
            """,
            (application_id, request_id),
        ).fetchall()
    finally:
        conn.close()
    return [_event_from_row(row) for row in rows]


def find_request_traces(request_id: str) -> list[RequestTraceRecord]:
    normalized_request_id = _bounded_required(request_id, "request_id", 200)
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            """
            SELECT * FROM security_events
            WHERE request_id = ?
            ORDER BY application_id, created_at, event_id
            """,
            (normalized_request_id,),
        ).fetchall()
    finally:
        conn.close()
    grouped: dict[str, list[SecurityEventRecord]] = {}
    for row in rows:
        event = _event_from_row(row)
        grouped.setdefault(event.application_id, []).append(event)
    return [
        RequestTraceRecord(application_id=application_id, events=tuple(events))
        for application_id, events in grouped.items()
    ]


def list_incidents(
    *,
    application_id: str | None = None,
    status: IncidentStatus | None = None,
    severity: str | None = None,
    category: str | None = None,
    limit: int = 100,
) -> list[SecurityIncidentRecord]:
    _validate_limit(limit)
    clauses: list[str] = []
    parameters: list[object] = []
    if application_id:
        clauses.append("application_id = ?")
        parameters.append(application_id)
    if status:
        clauses.append("status = ?")
        parameters.append(status)
    if severity:
        clauses.append("severity = ?")
        parameters.append(severity)
    if category:
        clauses.append("category = ?")
        parameters.append(category)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    parameters.append(limit)
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            f"""
            SELECT * FROM security_incidents
            {where}
            ORDER BY last_seen DESC, incident_id DESC
            LIMIT ?
            """,
            tuple(parameters),
        ).fetchall()
    finally:
        conn.close()
    return [_incident_from_row(row) for row in rows]


def get_incident(incident_id: str) -> IncidentDetail | None:
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    try:
        incident_row = conn.execute(
            "SELECT * FROM security_incidents WHERE incident_id = ?",
            (incident_id,),
        ).fetchone()
        if incident_row is None:
            return None
        event_rows = conn.execute(
            """
            SELECT e.*
            FROM security_events AS e
            JOIN security_incident_events AS ie ON ie.event_id = e.event_id
            WHERE ie.incident_id = ?
            ORDER BY e.created_at, e.event_id
            """,
            (incident_id,),
        ).fetchall()
        audit_rows = conn.execute(
            """
            SELECT * FROM security_incident_status_audit
            WHERE incident_id = ?
            ORDER BY created_at, id
            """,
            (incident_id,),
        ).fetchall()
    finally:
        conn.close()
    return IncidentDetail(
        incident=_incident_from_row(incident_row),
        events=tuple(_event_from_row(row) for row in event_rows),
        status_audit=tuple(_audit_from_row(row) for row in audit_rows),
    )


def update_incident_status(
    incident_id: str,
    *,
    new_status: IncidentStatus,
    actor: str,
) -> SecurityIncidentRecord | None:
    actor_value = _bounded_required(actor, "actor", 160)
    if new_status not in _INCIDENT_TRANSITIONS:
        raise ValueError("Unsupported incident status")
    now = _utc_timestamp()
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        with conn:
            current = conn.execute(
                "SELECT * FROM security_incidents WHERE incident_id = ?",
                (incident_id,),
            ).fetchone()
            if current is None:
                return None
            old_status = str(current["status"])
            if new_status == old_status:
                return _incident_from_row(current)
            if new_status not in _INCIDENT_TRANSITIONS[old_status]:
                raise InvalidIncidentTransitionError(
                    f"Incident cannot transition from {old_status} to {new_status}"
                )
            conn.execute(
                "UPDATE security_incidents SET status = ? WHERE incident_id = ?",
                (new_status, incident_id),
            )
            conn.execute(
                """
                INSERT INTO security_incident_status_audit (
                    incident_id,
                    old_status,
                    new_status,
                    actor,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                (incident_id, old_status, new_status, actor_value, now),
            )
            updated = conn.execute(
                "SELECT * FROM security_incidents WHERE incident_id = ?",
                (incident_id,),
            ).fetchone()
    finally:
        conn.close()
    return _incident_from_row(updated) if updated is not None else None


def _correlate_incident(conn: sqlite3.Connection, event: sqlite3.Row) -> None:
    rule = _incident_rule(event)
    if rule is None:
        return
    category, summary_code, incident_severity = rule
    correlation_key = _incident_correlation_key(event)
    existing = conn.execute(
        "SELECT * FROM security_incidents WHERE correlation_key = ?",
        (correlation_key,),
    ).fetchone()
    if existing is None:
        incident_id = f"inc_{uuid4().hex}"
        conn.execute(
            """
            INSERT INTO security_incidents (
                incident_id,
                application_id,
                status,
                severity,
                primary_event_id,
                first_seen,
                last_seen,
                event_count,
                category,
                summary_code,
                correlation_key
            )
            VALUES (?, ?, 'OPEN', ?, ?, ?, ?, 1, ?, ?, ?)
            """,
            (
                incident_id,
                event["application_id"],
                incident_severity,
                event["event_id"],
                event["created_at"],
                event["created_at"],
                category,
                summary_code,
                correlation_key,
            ),
        )
    else:
        incident_id = str(existing["incident_id"])
        severity = _higher_severity(str(existing["severity"]), incident_severity)
        conn.execute(
            """
            UPDATE security_incidents
            SET last_seen = ?, event_count = event_count + 1, severity = ?
            WHERE incident_id = ?
            """,
            (event["created_at"], severity, incident_id),
        )
    conn.execute(
        """
        INSERT OR IGNORE INTO security_incident_events (incident_id, event_id)
        VALUES (?, ?)
        """,
        (incident_id, event["event_id"]),
    )


def _incident_rule(row: sqlite3.Row) -> tuple[str, str, str] | None:
    event_type = str(row["event_type"])
    classification = str(row["classification"]).lower()
    action = str(row["action"]).lower()
    if event_type == "SESSION_RESTRICTION":
        return "SESSION_ACTIVITY", "SESSION_RESTRICTION", "high"
    if event_type == "SECURITY_PATH_FAILURE" and row["severity"] == "critical":
        return "SECURITY_PATH", "CRITICAL_SECURITY_PATH_FAILURE", "critical"
    if classification == "malicious" and action in {"block", "quarantine", "reject"}:
        severity = _higher_severity("high", str(row["severity"]))
        return (
            "MALICIOUS_ACTIVITY",
            f"MALICIOUS_{str(row['stage']).upper()}_{action.upper()}",
            severity,
        )
    return None


def _incident_correlation_key(row: sqlite3.Row) -> str:
    request_id = row["request_id"]
    if request_id:
        material = f"request\x1f{row['application_id']}\x1f{request_id}"
    elif row["session_hash"]:
        material = (
            f"session\x1f{row['application_id']}\x1f{row['channel']}"
            f"\x1f{row['session_hash']}"
        )
    else:
        material = f"event\x1f{row['event_id']}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _event_deduplication_key(**values: str | None) -> str | None:
    if not values["request_id"]:
        return None
    material = "\x1f".join(
        str(values[name] or "")
        for name in (
            "application_id",
            "channel",
            "request_id",
            "session_hash",
            "stage",
            "event_type",
            "classification",
            "action",
            "source_id",
            "chunk_id",
        )
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _higher_severity(current: str, candidate: str) -> str:
    return candidate if _SEVERITY_RANK[candidate] > _SEVERITY_RANK[current] else current


def _bounded_required(value: str, field: str, maximum: int) -> str:
    normalized = value.strip()
    if not normalized or len(normalized.encode("utf-8")) > maximum:
        raise ValueError(f"{field} must contain 1 to {maximum} UTF-8 bytes")
    return normalized


def _bounded_optional(value: str | None, field: str, maximum: int) -> str | None:
    if value is None:
        return None
    normalized = value.strip()
    if not normalized:
        return None
    if len(normalized.encode("utf-8")) > maximum:
        raise ValueError(f"{field} must not exceed {maximum} UTF-8 bytes")
    return normalized


def _validate_limit(limit: int) -> None:
    if limit < 1 or limit > 200:
        raise ValueError("limit must be between 1 and 200")


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def _event_from_row(row: sqlite3.Row) -> SecurityEventRecord:
    return SecurityEventRecord(
        event_id=str(row["event_id"]),
        application_id=str(row["application_id"]),
        channel=str(row["channel"]),
        request_id=str(row["request_id"]) if row["request_id"] is not None else None,
        session_hash=(
            str(row["session_hash"]) if row["session_hash"] is not None else None
        ),
        stage=str(row["stage"]),
        event_type=str(row["event_type"]),
        classification=str(row["classification"]),
        severity=str(row["severity"]),  # type: ignore[arg-type]
        risk_score=(float(row["risk_score"]) if row["risk_score"] is not None else None),
        action=str(row["action"]),
        source_id=str(row["source_id"]) if row["source_id"] is not None else None,
        chunk_id=str(row["chunk_id"]) if row["chunk_id"] is not None else None,
        created_at=str(row["created_at"]),
    )


def _incident_from_row(row: sqlite3.Row) -> SecurityIncidentRecord:
    return SecurityIncidentRecord(
        incident_id=str(row["incident_id"]),
        application_id=str(row["application_id"]),
        status=str(row["status"]),  # type: ignore[arg-type]
        severity=str(row["severity"]),
        primary_event_id=str(row["primary_event_id"]),
        first_seen=str(row["first_seen"]),
        last_seen=str(row["last_seen"]),
        event_count=int(row["event_count"]),
        category=str(row["category"]),
        summary_code=str(row["summary_code"]),
    )


def _audit_from_row(row: sqlite3.Row) -> IncidentStatusAuditRecord:
    return IncidentStatusAuditRecord(
        id=int(row["id"]),
        incident_id=str(row["incident_id"]),
        old_status=str(row["old_status"]),  # type: ignore[arg-type]
        new_status=str(row["new_status"]),  # type: ignore[arg-type]
        actor=str(row["actor"]),
        created_at=str(row["created_at"]),
    )
