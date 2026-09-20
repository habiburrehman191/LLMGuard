from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import sqlite3
from typing import Literal

from app.db import get_connection
from app.guard_telemetry import DuplicateGuardRequestError


GuardStage = Literal["input", "context", "output"]
REQUIRED_GUARD_STAGES: tuple[GuardStage, ...] = ("input", "context", "output")


@dataclass(frozen=True, slots=True)
class ProtectionConfigRecord:
    application_id: str
    protection_enabled: bool
    updated_at: str
    updated_by: str
    change_reason: str


@dataclass(frozen=True, slots=True)
class ProtectionAuditRecord:
    id: int
    application_id: str
    old_state: bool
    new_state: bool
    actor: str
    timestamp: str
    reason: str


@dataclass(frozen=True, slots=True)
class GuardStageHealthRecord:
    application_id: str
    stage: str
    last_success_at: str | None
    last_error_at: str | None
    last_error_code: str | None
    updated_at: str

    @property
    def available(self) -> bool:
        if self.last_success_at is None:
            return False
        if self.last_error_at is None:
            return True
        return _parse_timestamp(self.last_success_at) >= _parse_timestamp(
            self.last_error_at
        )


def ensure_protection_config(
    application_id: str,
    *,
    enabled: bool = True,
) -> ProtectionConfigRecord:
    now = _utc_timestamp()
    conn = get_connection()
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        with conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO application_protection (
                    application_id,
                    protection_enabled,
                    updated_at,
                    updated_by,
                    change_reason
                )
                VALUES (?, ?, ?, 'system', 'Default protection policy')
                """,
                (application_id, int(enabled), now),
            )
    finally:
        conn.close()
    config = get_protection_config(application_id)
    if config is None:
        raise RuntimeError("Application protection configuration could not be loaded")
    return config


def get_protection_config(application_id: str) -> ProtectionConfigRecord | None:
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute(
            """
            SELECT application_id, protection_enabled, updated_at, updated_by, change_reason
            FROM application_protection
            WHERE application_id = ?
            """,
            (application_id,),
        ).fetchone()
    finally:
        conn.close()
    return _config_from_row(row) if row is not None else None


def set_protection_enabled(
    application_id: str,
    *,
    enabled: bool,
    actor: str,
    reason: str | None,
) -> ProtectionConfigRecord:
    actor_value = actor.strip()
    reason_value = (reason or "").strip()
    if not actor_value:
        raise ValueError("Protection changes require an actor")
    if not enabled and not reason_value:
        raise ValueError("A reason is required when disabling protection")
    if enabled and not reason_value:
        reason_value = "Protection enabled"

    current = ensure_protection_config(application_id)
    if current.protection_enabled == enabled:
        return current

    now = _utc_timestamp()
    conn = get_connection()
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        with conn:
            cursor = conn.execute(
                """
                UPDATE application_protection
                SET protection_enabled = ?, updated_at = ?, updated_by = ?, change_reason = ?
                WHERE application_id = ? AND protection_enabled = ?
                """,
                (
                    int(enabled),
                    now,
                    actor_value,
                    reason_value,
                    application_id,
                    int(current.protection_enabled),
                ),
            )
            if cursor.rowcount != 1:
                raise RuntimeError("Protection configuration changed concurrently")
            conn.execute(
                """
                INSERT INTO application_protection_audit (
                    application_id,
                    old_state,
                    new_state,
                    actor,
                    timestamp,
                    reason
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    application_id,
                    int(current.protection_enabled),
                    int(enabled),
                    actor_value,
                    now,
                    reason_value,
                ),
            )
    finally:
        conn.close()
    updated = get_protection_config(application_id)
    if updated is None:
        raise RuntimeError("Updated protection configuration could not be loaded")
    return updated


def list_protection_audit(application_id: str) -> list[ProtectionAuditRecord]:
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            """
            SELECT id, application_id, old_state, new_state, actor, timestamp, reason
            FROM application_protection_audit
            WHERE application_id = ?
            ORDER BY id DESC
            """,
            (application_id,),
        ).fetchall()
    finally:
        conn.close()
    return [
        ProtectionAuditRecord(
            id=row["id"],
            application_id=row["application_id"],
            old_state=bool(row["old_state"]),
            new_state=bool(row["new_state"]),
            actor=row["actor"],
            timestamp=row["timestamp"],
            reason=row["reason"],
        )
        for row in rows
    ]


def record_guard_stage_success(application_id: str, stage: GuardStage) -> None:
    _record_guard_stage_result(application_id, stage, error_code=None)


def record_guard_stage_failure(
    application_id: str,
    stage: GuardStage,
    error_code: str,
) -> None:
    _record_guard_stage_result(application_id, stage, error_code=error_code)


def list_guard_stage_health(application_id: str) -> tuple[GuardStageHealthRecord, ...]:
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            """
            SELECT application_id, stage, last_success_at, last_error_at, last_error_code, updated_at
            FROM application_guard_health
            WHERE application_id = ?
            ORDER BY CASE stage WHEN 'input' THEN 1 WHEN 'context' THEN 2 ELSE 3 END
            """,
            (application_id,),
        ).fetchall()
    finally:
        conn.close()
    return tuple(_health_from_row(row) for row in rows)


def guard_path_available(application_id: str) -> bool:
    health = {item.stage: item for item in list_guard_stage_health(application_id)}
    return all(
        stage in health and health[stage].available
        for stage in REQUIRED_GUARD_STAGES
    )


def record_guard_bypass(
    *,
    application_id: str,
    channel: str,
    request_id: str,
    stage: GuardStage,
) -> None:
    conn = get_connection()
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        try:
            with conn:
                conn.execute(
                    """
                    INSERT INTO guard_bypass_events (application_id, channel, request_id, stage)
                    VALUES (?, ?, ?, ?)
                    """,
                    (application_id, channel, request_id, stage),
                )
        except sqlite3.IntegrityError as exc:
            if "unique" in str(exc).lower():
                raise DuplicateGuardRequestError(
                    "The bypassed request ID has already been used for this stage."
                ) from None
            raise
    finally:
        conn.close()


def _record_guard_stage_result(
    application_id: str,
    stage: GuardStage,
    *,
    error_code: str | None,
) -> None:
    now = _utc_timestamp()
    conn = get_connection()
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        with conn:
            conn.execute(
                """
                INSERT INTO application_guard_health (
                    application_id,
                    stage,
                    last_success_at,
                    last_error_at,
                    last_error_code,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(application_id, stage) DO UPDATE SET
                    last_success_at = CASE
                        WHEN excluded.last_error_at IS NULL THEN excluded.last_success_at
                        ELSE application_guard_health.last_success_at
                    END,
                    last_error_at = CASE
                        WHEN excluded.last_error_at IS NOT NULL THEN excluded.last_error_at
                        ELSE application_guard_health.last_error_at
                    END,
                    last_error_code = CASE
                        WHEN excluded.last_error_at IS NOT NULL THEN excluded.last_error_code
                        ELSE NULL
                    END,
                    updated_at = excluded.updated_at
                """,
                (
                    application_id,
                    stage,
                    now if error_code is None else None,
                    now if error_code is not None else None,
                    error_code,
                    now,
                ),
            )
    finally:
        conn.close()


def _config_from_row(row: sqlite3.Row) -> ProtectionConfigRecord:
    return ProtectionConfigRecord(
        application_id=row["application_id"],
        protection_enabled=bool(row["protection_enabled"]),
        updated_at=row["updated_at"],
        updated_by=row["updated_by"],
        change_reason=row["change_reason"],
    )


def _health_from_row(row: sqlite3.Row) -> GuardStageHealthRecord:
    return GuardStageHealthRecord(
        application_id=row["application_id"],
        stage=row["stage"],
        last_success_at=row["last_success_at"],
        last_error_at=row["last_error_at"],
        last_error_code=row["last_error_code"],
        updated_at=row["updated_at"],
    )


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def _parse_timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)
