from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
import sqlite3

from app.db import get_connection


UNIVERSITY_APPLICATION_ID = "university-of-haripur"
UNIVERSITY_CHANNELS = ("public", "student", "employee")


@dataclass(frozen=True, slots=True)
class OrganizationRecord:
    id: int
    name: str
    slug: str
    created_at: str


@dataclass(frozen=True, slots=True)
class ApplicationChannelRecord:
    id: int
    application_id: str
    channel: str
    enabled: bool
    created_at: str


@dataclass(frozen=True, slots=True)
class ApplicationRecord:
    id: int
    application_id: str
    organization: OrganizationRecord
    name: str
    slug: str
    environment: str
    status: str
    created_at: str
    updated_at: str
    channels: tuple[ApplicationChannelRecord, ...]


def register_application(
    *,
    organization_name: str,
    organization_slug: str,
    application_id: str,
    name: str,
    slug: str,
    environment: str,
    status: str,
    channels: Iterable[str],
) -> ApplicationRecord:
    """Register an application and its channels without duplicating existing rows."""
    required_values = {
        "organization_name": organization_name,
        "organization_slug": organization_slug,
        "application_id": application_id,
        "name": name,
        "slug": slug,
        "environment": environment,
        "status": status,
    }
    for field_name, value in required_values.items():
        if not value.strip():
            raise ValueError(f"{field_name} must not be empty")

    normalized_channels = tuple(
        dict.fromkeys(channel.strip().lower() for channel in channels if channel.strip())
    )
    if not normalized_channels:
        raise ValueError("At least one application channel is required")

    conn = get_connection()
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        with conn:
            conn.execute(
                "INSERT OR IGNORE INTO organizations (name, slug) VALUES (?, ?)",
                (organization_name.strip(), organization_slug.strip()),
            )
            organization = conn.execute(
                "SELECT id, name, slug FROM organizations WHERE slug = ?",
                (organization_slug.strip(),),
            ).fetchone()
            if organization is None:
                raise RuntimeError("Organization registration failed")
            if organization["name"] != organization_name.strip():
                raise ValueError("Organization slug is already registered with a different name")

            conn.execute(
                """
                INSERT OR IGNORE INTO applications (
                    application_id,
                    organization_id,
                    name,
                    slug,
                    environment,
                    status
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    application_id.strip(),
                    organization["id"],
                    name.strip(),
                    slug.strip(),
                    environment.strip(),
                    status.strip(),
                ),
            )
            application = conn.execute(
                """
                SELECT organization_id, name, slug, environment
                FROM applications
                WHERE application_id = ?
                """,
                (application_id.strip(),),
            ).fetchone()
            if application is None:
                raise RuntimeError("Application registration failed")
            identity = (
                application["organization_id"],
                application["name"],
                application["slug"],
                application["environment"],
            )
            requested_identity = (
                organization["id"],
                name.strip(),
                slug.strip(),
                environment.strip(),
            )
            if identity != requested_identity:
                raise ValueError("Application ID is already registered to a different application")

            conn.executemany(
                """
                INSERT OR IGNORE INTO application_channels (
                    application_id,
                    channel,
                    enabled
                )
                VALUES (?, ?, 1)
                """,
                [(application_id.strip(), channel) for channel in normalized_channels],
            )
    finally:
        conn.close()

    application_record = get_application(application_id.strip())
    if application_record is None:
        raise RuntimeError("Registered application could not be loaded")
    return application_record


def get_application(application_id: str) -> ApplicationRecord | None:
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute(
            """
            SELECT
                a.id,
                a.application_id,
                a.name,
                a.slug,
                a.environment,
                a.status,
                a.created_at,
                a.updated_at,
                o.id AS organization_id,
                o.name AS organization_name,
                o.slug AS organization_slug,
                o.created_at AS organization_created_at
            FROM applications AS a
            JOIN organizations AS o ON o.id = a.organization_id
            WHERE a.application_id = ?
            """,
            (application_id,),
        ).fetchone()
    finally:
        conn.close()
    return _application_from_row(row) if row is not None else None


def list_applications() -> list[ApplicationRecord]:
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            """
            SELECT
                a.id,
                a.application_id,
                a.name,
                a.slug,
                a.environment,
                a.status,
                a.created_at,
                a.updated_at,
                o.id AS organization_id,
                o.name AS organization_name,
                o.slug AS organization_slug,
                o.created_at AS organization_created_at
            FROM applications AS a
            JOIN organizations AS o ON o.id = a.organization_id
            ORDER BY o.name, a.name, a.environment
            """
        ).fetchall()
    finally:
        conn.close()
    return [_application_from_row(row) for row in rows]


def list_channels(application_id: str) -> list[ApplicationChannelRecord]:
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            """
            SELECT id, application_id, channel, enabled, created_at
            FROM application_channels
            WHERE application_id = ?
            ORDER BY id
            """,
            (application_id,),
        ).fetchall()
    finally:
        conn.close()
    return [
        ApplicationChannelRecord(
            id=row["id"],
            application_id=row["application_id"],
            channel=row["channel"],
            enabled=bool(row["enabled"]),
            created_at=row["created_at"],
        )
        for row in rows
    ]


def bootstrap_default_application() -> ApplicationRecord:
    return register_application(
        organization_name="University of Haripur",
        organization_slug="university-of-haripur",
        application_id=UNIVERSITY_APPLICATION_ID,
        name="University of Haripur AI System",
        slug="university-of-haripur-ai-system",
        environment="development",
        status="INTEGRATION_PENDING",
        channels=UNIVERSITY_CHANNELS,
    )


def _application_from_row(row: sqlite3.Row) -> ApplicationRecord:
    return ApplicationRecord(
        id=row["id"],
        application_id=row["application_id"],
        organization=OrganizationRecord(
            id=row["organization_id"],
            name=row["organization_name"],
            slug=row["organization_slug"],
            created_at=row["organization_created_at"],
        ),
        name=row["name"],
        slug=row["slug"],
        environment=row["environment"],
        status=row["status"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
        channels=tuple(list_channels(row["application_id"])),
    )
