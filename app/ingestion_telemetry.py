from __future__ import annotations

from dataclasses import dataclass
import sqlite3

from app.db import get_connection
from app.guard_telemetry import DuplicateGuardRequestError


@dataclass(frozen=True, slots=True)
class IngestionTelemetryRecord:
    id: int
    application_id: str
    channel: str
    source_id: str
    request_id: str
    classification: str
    risk_score: float | None
    action: str
    created_at: str


def record_ingestion_inspection(
    *,
    application_id: str,
    channel: str,
    source_id: str,
    request_id: str,
    classification: str,
    risk_score: float | None,
    action: str,
) -> IngestionTelemetryRecord:
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        try:
            with conn:
                cursor = conn.execute(
                    """
                    INSERT INTO ingestion_inspection_events (
                        application_id,
                        channel,
                        source_id,
                        request_id,
                        classification,
                        risk_score,
                        action
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        application_id,
                        channel,
                        source_id,
                        request_id,
                        classification,
                        risk_score,
                        action,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            if "unique" in str(exc).lower():
                raise DuplicateGuardRequestError(
                    "The ingestion request ID has already been used for this application."
                ) from None
            raise

        row = conn.execute(
            """
            SELECT
                id,
                application_id,
                channel,
                source_id,
                request_id,
                classification,
                risk_score,
                action,
                created_at
            FROM ingestion_inspection_events
            WHERE id = ?
            """,
            (cursor.lastrowid,),
        ).fetchone()
    finally:
        conn.close()
    if row is None:
        raise RuntimeError("Ingestion telemetry could not be loaded after persistence")
    return _record_from_row(row)


def get_ingestion_inspection(
    application_id: str,
    request_id: str,
) -> IngestionTelemetryRecord | None:
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute(
            """
            SELECT
                id,
                application_id,
                channel,
                source_id,
                request_id,
                classification,
                risk_score,
                action,
                created_at
            FROM ingestion_inspection_events
            WHERE application_id = ? AND request_id = ?
            """,
            (application_id, request_id),
        ).fetchone()
    finally:
        conn.close()
    return _record_from_row(row) if row is not None else None


def _record_from_row(row: sqlite3.Row) -> IngestionTelemetryRecord:
    return IngestionTelemetryRecord(
        id=row["id"],
        application_id=row["application_id"],
        channel=row["channel"],
        source_id=row["source_id"],
        request_id=row["request_id"],
        classification=row["classification"],
        risk_score=(
            float(row["risk_score"])
            if row["risk_score"] is not None
            else None
        ),
        action=row["action"],
        created_at=row["created_at"],
    )
