from __future__ import annotations

from dataclasses import dataclass
import sqlite3

from app.db import get_connection
from app.guard_telemetry import DuplicateGuardRequestError


@dataclass(frozen=True, slots=True)
class OutputGuardTelemetryRecord:
    id: int
    application_id: str
    channel: str
    request_id: str
    decision: str
    classification: str
    risk_score: float
    action: str
    created_at: str


def record_output_guard_decision(
    *,
    application_id: str,
    channel: str,
    request_id: str,
    decision: str,
    classification: str,
    risk_score: float,
    action: str,
) -> OutputGuardTelemetryRecord:
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        try:
            with conn:
                cursor = conn.execute(
                    """
                    INSERT INTO guard_output_events (
                        application_id,
                        channel,
                        request_id,
                        decision,
                        classification,
                        risk_score,
                        action
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        application_id,
                        channel,
                        request_id,
                        decision,
                        classification,
                        risk_score,
                        action,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            if "unique" in str(exc).lower():
                raise DuplicateGuardRequestError(
                    "The output request ID has already been used for this application."
                ) from None
            raise

        row = conn.execute(
            """
            SELECT
                id,
                application_id,
                channel,
                request_id,
                decision,
                classification,
                risk_score,
                action,
                created_at
            FROM guard_output_events
            WHERE id = ?
            """,
            (cursor.lastrowid,),
        ).fetchone()
    finally:
        conn.close()
    if row is None:
        raise RuntimeError("Output guard telemetry could not be loaded after persistence")
    return _record_from_row(row)


def get_output_guard_decision(
    application_id: str,
    request_id: str,
) -> OutputGuardTelemetryRecord | None:
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute(
            """
            SELECT
                id,
                application_id,
                channel,
                request_id,
                decision,
                classification,
                risk_score,
                action,
                created_at
            FROM guard_output_events
            WHERE application_id = ? AND request_id = ?
            """,
            (application_id, request_id),
        ).fetchone()
    finally:
        conn.close()
    return _record_from_row(row) if row is not None else None


def _record_from_row(row: sqlite3.Row) -> OutputGuardTelemetryRecord:
    return OutputGuardTelemetryRecord(
        id=row["id"],
        application_id=row["application_id"],
        channel=row["channel"],
        request_id=row["request_id"],
        decision=row["decision"],
        classification=row["classification"],
        risk_score=float(row["risk_score"]),
        action=row["action"],
        created_at=row["created_at"],
    )
