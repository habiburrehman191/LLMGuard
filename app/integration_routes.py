from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated, Literal

from fastapi import APIRouter, Header, HTTPException, status
from pydantic import BaseModel, Field, SecretStr, field_validator

from app.application_credentials import verify_credential
from app.application_registry import get_application
from app.config import get_settings
from app.integration_health import CONNECTED, record_heartbeat
from app.security_events import record_security_event_safely


router = APIRouter(prefix="/api/v1/integrations", tags=["application-integrations"])


class HeartbeatRequest(BaseModel):
    application_id: str = Field(min_length=1, max_length=160)
    environment: str = Field(min_length=1, max_length=64)
    application_version: str | None = Field(default=None, max_length=100)
    integration_version: str | None = Field(default=None, max_length=100)
    timestamp: datetime
    channels: list[Literal["public", "student", "employee"]] = Field(min_length=1)

    @field_validator("application_id", "environment")
    @classmethod
    def normalize_required_text(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("Value must not be empty")
        return normalized

    @field_validator("application_version", "integration_version")
    @classmethod
    def normalize_optional_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None

    @field_validator("timestamp")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("Heartbeat timestamp must include a timezone")
        return value.astimezone(timezone.utc)

    @field_validator("channels")
    @classmethod
    def reject_duplicate_channels(
        cls,
        value: list[Literal["public", "student", "employee"]],
    ) -> list[Literal["public", "student", "employee"]]:
        if len(value) != len(set(value)):
            raise ValueError("Heartbeat channels must be unique")
        return value


class HeartbeatResponse(BaseModel):
    accepted: bool
    application_id: str
    integration_state: Literal["CONNECTED"]
    last_heartbeat_at: str


@router.post("/heartbeat", response_model=HeartbeatResponse)
def receive_heartbeat(
    payload: HeartbeatRequest,
    key_id: Annotated[str, Header(alias="X-LLMGuard-Key-ID")],
    api_secret: Annotated[SecretStr, Header(alias="X-LLMGuard-API-Secret")],
) -> HeartbeatResponse:
    application = get_application(payload.application_id)
    if application is None:
        raise HTTPException(status_code=404, detail="Application not found.")

    if not verify_credential(
        payload.application_id,
        key_id,
        api_secret.get_secret_value(),
    ):
        _record_integration_failure(
            payload.application_id,
            event_type="INTEGRATION_AUTH_FAILURE",
            severity="high",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid application credential.",
        )

    if payload.environment.lower() != application.environment.lower():
        _record_integration_failure(payload.application_id)
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Heartbeat environment does not match the registered application.",
        )

    settings = get_settings()
    now = datetime.now(timezone.utc)
    timestamp_skew = abs((now - payload.timestamp).total_seconds())
    if timestamp_skew > settings.heartbeat_max_skew_seconds:
        _record_integration_failure(payload.application_id)
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Heartbeat timestamp is stale or too far in the future.",
        )

    registered_channels = {
        channel.channel for channel in application.channels if channel.enabled
    }
    if set(payload.channels) != registered_channels:
        _record_integration_failure(payload.application_id)
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Heartbeat channels do not match the registered application channels.",
        )

    health = record_heartbeat(
        application_id=payload.application_id,
        environment=payload.environment,
        application_version=payload.application_version,
        integration_version=payload.integration_version,
        channels=tuple(payload.channels),
        received_at=now,
    )
    return HeartbeatResponse(
        accepted=True,
        application_id=payload.application_id,
        integration_state=CONNECTED,
        last_heartbeat_at=health.last_heartbeat_at,
    )


def _record_integration_failure(
    application_id: str,
    *,
    event_type: str = "INTEGRATION_VALIDATION_FAILURE",
    severity: Literal["medium", "high"] = "medium",
) -> None:
    record_security_event_safely(
        application_id=application_id,
        channel="integration",
        request_id=None,
        session_hash=None,
        stage="integration",
        event_type=event_type,
        classification="suspicious",
        severity=severity,
        risk_score=None,
        action="reject",
    )
