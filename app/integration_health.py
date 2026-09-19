from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import sqlite3

from app.application_registry import ApplicationRecord
from app.config import get_settings
from app.db import get_connection


INTEGRATION_PENDING = "INTEGRATION_PENDING"
CONNECTED = "CONNECTED"
DISCONNECTED = "DISCONNECTED"


@dataclass(frozen=True, slots=True)
class IntegrationHealthRecord:
    application_id: str
    last_heartbeat_at: str
    application_version: str | None
    integration_version: str | None
    environment: str
    reported_status: str
    channels: tuple[str, ...]
    updated_at: str


@dataclass(frozen=True, slots=True)
class ApplicationIntegrationStatus:
    application: ApplicationRecord
    state: str
    last_heartbeat_at: str | None
    application_version: str | None
    integration_version: str | None
    heartbeat_environment: str | None
    reported_status: str | None
    reported_channels: tuple[str, ...]
    updated_at: str | None


def record_heartbeat(
    *,
    application_id: str,
    environment: str,
    application_version: str | None,
    integration_version: str | None,
    channels: tuple[str, ...],
    received_at: datetime | None = None,
) -> IntegrationHealthRecord:
    heartbeat_at = _serialize_timestamp(received_at or _utc_now())
    normalized_channels = tuple(dict.fromkeys(channel.strip().lower() for channel in channels))
    conn = get_connection()
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        with conn:
            conn.execute(
                """
                INSERT INTO integration_health (
                    application_id,
                    last_heartbeat_at,
                    application_version,
                    integration_version,
                    environment,
                    reported_status,
                    channels,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(application_id) DO UPDATE SET
                    last_heartbeat_at = excluded.last_heartbeat_at,
                    application_version = excluded.application_version,
                    integration_version = excluded.integration_version,
                    environment = excluded.environment,
                    reported_status = excluded.reported_status,
                    channels = excluded.channels,
                    updated_at = excluded.updated_at
                """,
                (
                    application_id,
                    heartbeat_at,
                    _optional_text(application_version),
                    _optional_text(integration_version),
                    environment.strip().lower(),
                    CONNECTED,
                    json.dumps(normalized_channels),
                    heartbeat_at,
                ),
            )
    finally:
        conn.close()

    health = get_integration_health(application_id)
    if health is None:
        raise RuntimeError("Heartbeat could not be loaded after persistence")
    return health


def get_integration_health(application_id: str) -> IntegrationHealthRecord | None:
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute(
            """
            SELECT
                application_id,
                last_heartbeat_at,
                application_version,
                integration_version,
                environment,
                reported_status,
                channels,
                updated_at
            FROM integration_health
            WHERE application_id = ?
            """,
            (application_id,),
        ).fetchone()
    finally:
        conn.close()
    return _health_from_row(row) if row is not None else None


def integration_status_for(
    application: ApplicationRecord,
    *,
    now: datetime | None = None,
    timeout_seconds: int | None = None,
) -> ApplicationIntegrationStatus:
    health = get_integration_health(application.application_id)
    if health is None:
        return ApplicationIntegrationStatus(
            application=application,
            state=INTEGRATION_PENDING,
            last_heartbeat_at=None,
            application_version=None,
            integration_version=None,
            heartbeat_environment=None,
            reported_status=None,
            reported_channels=(),
            updated_at=None,
        )

    active_timeout = (
        timeout_seconds
        if timeout_seconds is not None
        else get_settings().heartbeat_timeout_seconds
    )
    current_time = _as_utc(now or _utc_now())
    last_heartbeat = _parse_timestamp(health.last_heartbeat_at)
    age_seconds = (current_time - last_heartbeat).total_seconds()
    state = CONNECTED if age_seconds <= active_timeout else DISCONNECTED
    return ApplicationIntegrationStatus(
        application=application,
        state=state,
        last_heartbeat_at=health.last_heartbeat_at,
        application_version=health.application_version,
        integration_version=health.integration_version,
        heartbeat_environment=health.environment,
        reported_status=health.reported_status,
        reported_channels=health.channels,
        updated_at=health.updated_at,
    )


def integration_statuses_for(
    applications: list[ApplicationRecord],
) -> list[ApplicationIntegrationStatus]:
    return [integration_status_for(application) for application in applications]


def _health_from_row(row: sqlite3.Row) -> IntegrationHealthRecord:
    try:
        decoded_channels = json.loads(row["channels"])
    except (json.JSONDecodeError, TypeError):
        decoded_channels = []
    channels = tuple(
        str(channel) for channel in decoded_channels if isinstance(channel, str)
    )
    return IntegrationHealthRecord(
        application_id=row["application_id"],
        last_heartbeat_at=row["last_heartbeat_at"],
        application_version=row["application_version"],
        integration_version=row["integration_version"],
        environment=row["environment"],
        reported_status=row["reported_status"],
        channels=channels,
        updated_at=row["updated_at"],
    )


def _optional_text(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip()
    return normalized or None


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _serialize_timestamp(value: datetime) -> str:
    return _as_utc(value).isoformat(timespec="seconds")


def _parse_timestamp(value: str) -> datetime:
    return _as_utc(datetime.fromisoformat(value.replace("Z", "+00:00")))


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)
