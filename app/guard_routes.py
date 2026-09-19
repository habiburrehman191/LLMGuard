from __future__ import annotations

import json
from typing import Annotated, Literal

from fastapi import APIRouter, Header, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field, JsonValue, SecretStr, field_validator

from app.application_credentials import verify_credential
from app.application_registry import get_application
from app.guard_telemetry import (
    DuplicateGuardRequestError,
    get_guard_decision,
    record_guard_decision,
)
from app.input_guard import inspect_input_content


router = APIRouter(prefix="/api/v1", tags=["application-security"])


class InputGuardRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    application_id: str = Field(min_length=1, max_length=160)
    request_id: str = Field(min_length=1, max_length=200)
    channel: Literal["public", "student", "employee"]
    stage: Literal["input"]
    content: str = Field(min_length=1, max_length=16_000)
    security_context: dict[str, JsonValue]

    @field_validator("application_id", "request_id")
    @classmethod
    def normalize_identifiers(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("Identifier must not be empty")
        return normalized

    @field_validator("content")
    @classmethod
    def reject_blank_content(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Content must not be blank")
        return value

    @field_validator("security_context")
    @classmethod
    def bound_security_context(
        cls,
        value: dict[str, JsonValue],
    ) -> dict[str, JsonValue]:
        if len(value) > 32:
            raise ValueError("security_context may contain at most 32 fields")
        encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
        if len(encoded.encode("utf-8")) > 8_192:
            raise ValueError("security_context must not exceed 8192 bytes")
        return value


class InputGuardResponse(BaseModel):
    request_id: str
    stage: Literal["input"]
    decision: Literal["allow", "restrict"]
    classification: Literal["safe", "suspicious", "malicious"]
    threat_type: str | None
    severity: Literal["none", "low", "medium", "high", "critical"]
    risk_score: float = Field(ge=0, le=1)
    action: Literal["allow", "log", "sanitize", "quarantine", "block"]
    reasons: list[str]


@router.post("/guard", response_model=InputGuardResponse)
def inspect_input(
    payload: InputGuardRequest,
    key_id: Annotated[str, Header(alias="X-LLMGuard-Key-ID")],
    api_secret: Annotated[SecretStr, Header(alias="X-LLMGuard-API-Secret")],
) -> InputGuardResponse:
    application = get_application(payload.application_id)
    if application is None:
        raise HTTPException(status_code=404, detail="Application not found.")

    if not verify_credential(
        payload.application_id,
        key_id,
        api_secret.get_secret_value(),
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid application credential.",
        )

    channel = next(
        (
            item
            for item in application.channels
            if item.channel == payload.channel and item.enabled
        ),
        None,
    )
    if channel is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Application channel is not registered or enabled.",
        )

    if get_guard_decision(payload.application_id, payload.request_id) is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Request ID has already been used for this application.",
        )

    decision = inspect_input_content(payload.content)
    try:
        record_guard_decision(
            application_id=payload.application_id,
            channel=payload.channel,
            request_id=payload.request_id,
            classification=decision.classification,
            risk_score=decision.risk_score,
            action=decision.action,
        )
    except DuplicateGuardRequestError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Request ID has already been used for this application.",
        ) from None

    return InputGuardResponse(
        request_id=payload.request_id,
        stage="input",
        decision=decision.decision,
        classification=decision.classification,
        threat_type=decision.threat_type,
        severity=decision.severity,
        risk_score=decision.risk_score,
        action=decision.action,
        reasons=list(decision.reasons),
    )
