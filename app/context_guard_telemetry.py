from __future__ import annotations

from dataclasses import dataclass
import json
import sqlite3
from typing import Sequence

from app.db import get_connection
from app.guard_telemetry import DuplicateGuardRequestError


@dataclass(frozen=True, slots=True)
class ContextGuardTelemetryRecord:
    id: int
    application_id: str
    channel: str
    request_id: str
    decision: str
    classification: str
    risk_score: float
    action: str
    source_references: tuple[dict[str, str], ...]
    created_at: str


def record_context_guard_decision(
    *,
    application_id: str,
    channel: str,
    request_id: str,
    decision: str,
    classification: str,
    risk_score: float,
    action: str,
    source_references: Sequence[tuple[str, str]],
) -> ContextGuardTelemetryRecord:
    references_json = json.dumps(
        [
            {"source_id": source_id, "chunk_id": chunk_id}
            for source_id, chunk_id in source_references
        ],
        ensure_ascii=False,
        separators=(",", ":"),
    )
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        try:
            with conn:
                cursor = conn.execute(
                    """
                    INSERT INTO guard_context_events (
                        application_id,
                        channel,
                        request_id,
                        decision,
                        classification,
                        risk_score,
                        action,
                        source_references
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        application_id,
                        channel,
                        request_id,
                        decision,
                        classification,
                        risk_score,
                        action,
                        references_json,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            if "unique" in str(exc).lower():
                raise DuplicateGuardRequestError(
                    "The context request ID has already been used for this application."
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
                source_references,
                created_at
            FROM guard_context_events
            WHERE id = ?
            """,
            (cursor.lastrowid,),
        ).fetchone()
    finally:
        conn.close()
    if row is None:
        raise RuntimeError("Context guard telemetry could not be loaded after persistence")
    return _record_from_row(row)


def get_context_guard_decision(
    application_id: str,
    request_id: str,
) -> ContextGuardTelemetryRecord | None:
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
                source_references,
                created_at
            FROM guard_context_events
            WHERE application_id = ? AND request_id = ?
            """,
            (application_id, request_id),
        ).fetchone()
    finally:
        conn.close()
    return _record_from_row(row) if row is not None else None


def _record_from_row(row: sqlite3.Row) -> ContextGuardTelemetryRecord:
    references = json.loads(row["source_references"])
    return ContextGuardTelemetryRecord(
        id=row["id"],
        application_id=row["application_id"],
        channel=row["channel"],
        request_id=row["request_id"],
        decision=row["decision"],
        classification=row["classification"],
        risk_score=float(row["risk_score"]),
        action=row["action"],
        source_references=tuple(
            {
                "source_id": str(item["source_id"]),
                "chunk_id": str(item["chunk_id"]),
            }
            for item in references
        ),
        created_at=row["created_at"],
    )
