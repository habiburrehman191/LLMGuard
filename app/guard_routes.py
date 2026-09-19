from __future__ import annotations

import json
from typing import Annotated, Literal

from fastapi import APIRouter, Header, HTTPException, status
from fastapi.responses import JSONResponse
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    SecretStr,
    field_validator,
    model_validator,
)

from app.application_credentials import verify_credential
from app.application_registry import get_application
from app.context_guard import inspect_context_chunks
from app.context_guard_telemetry import (
    get_context_guard_decision,
    record_context_guard_decision,
)
from app.guard_telemetry import (
    DuplicateGuardRequestError,
    get_guard_decision,
    record_guard_decision,
)
from app.input_guard import inspect_input_content


router = APIRouter(prefix="/api/v1", tags=["application-security"])

MAX_CONTEXT_CHUNKS = 32
MAX_CONTEXT_CHUNK_BYTES = 16_000
MAX_TOTAL_CONTEXT_BYTES = 64_000


class GuardRequestBase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    application_id: str = Field(min_length=1, max_length=160)
    request_id: str = Field(min_length=1, max_length=200)
    channel: Literal["public", "student", "employee"]

    @field_validator("application_id", "request_id")
    @classmethod
    def normalize_identifiers(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("Identifier must not be empty")
        return normalized


class InputGuardRequest(GuardRequestBase):
    stage: Literal["input"]
    content: str = Field(min_length=1, max_length=16_000)
    security_context: dict[str, JsonValue]

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


class ContextChunk(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_id: str = Field(min_length=1, max_length=300)
    chunk_id: str = Field(min_length=1, max_length=300)
    text: str = Field(min_length=1, max_length=MAX_CONTEXT_CHUNK_BYTES)
    metadata: dict[str, JsonValue] | None = None

    @field_validator("source_id", "chunk_id")
    @classmethod
    def normalize_identifiers(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("Chunk identifier must not be empty")
        return normalized

    @field_validator("text")
    @classmethod
    def bound_text(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Chunk text must not be blank")
        if len(value.encode("utf-8")) > MAX_CONTEXT_CHUNK_BYTES:
            raise ValueError(
                f"Chunk text must not exceed {MAX_CONTEXT_CHUNK_BYTES} bytes"
            )
        return value

    @field_validator("metadata")
    @classmethod
    def bound_metadata(
        cls,
        value: dict[str, JsonValue] | None,
    ) -> dict[str, JsonValue] | None:
        if value is None:
            return None
        if len(value) > 32:
            raise ValueError("Chunk metadata may contain at most 32 fields")
        encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
        if len(encoded.encode("utf-8")) > 8_192:
            raise ValueError("Chunk metadata must not exceed 8192 bytes")
        return value


class ContextGuardRequest(GuardRequestBase):
    stage: Literal["context"]
    chunks: list[ContextChunk] = Field(
        min_length=1,
        max_length=MAX_CONTEXT_CHUNKS,
    )

    @model_validator(mode="after")
    def bound_total_context(self) -> "ContextGuardRequest":
        total_bytes = sum(len(chunk.text.encode("utf-8")) for chunk in self.chunks)
        if total_bytes > MAX_TOTAL_CONTEXT_BYTES:
            raise ValueError(
                f"Total context must not exceed {MAX_TOTAL_CONTEXT_BYTES} bytes"
            )
        return self


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


class SanitizedContextChunk(BaseModel):
    source_id: str
    chunk_id: str
    text: str
    metadata: dict[str, JsonValue] | None = None


class ContextGuardResponse(BaseModel):
    request_id: str
    stage: Literal["context"]
    decision: Literal["allow", "restrict"]
    classification: Literal["safe", "suspicious", "malicious"]
    threat_type: str | None
    severity: Literal["none", "low", "medium", "high", "critical"]
    risk_score: float = Field(ge=0, le=1)
    action: Literal["allow", "log", "sanitize", "quarantine", "block"]
    reasons: list[str]
    sanitized_chunks: list[SanitizedContextChunk] | None = None


GuardRequest = Annotated[
    InputGuardRequest | ContextGuardRequest,
    Field(discriminator="stage"),
]
GuardResponse = InputGuardResponse | ContextGuardResponse


@router.post("/guard", response_model=GuardResponse)
def inspect_guard(
    payload: GuardRequest,
    key_id: Annotated[str, Header(alias="X-LLMGuard-Key-ID")],
    api_secret: Annotated[SecretStr, Header(alias="X-LLMGuard-API-Secret")],
) -> GuardResponse | JSONResponse:
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

    if isinstance(payload, ContextGuardRequest):
        return _inspect_context(payload)
    return _inspect_input(payload)


def _inspect_input(payload: InputGuardRequest) -> InputGuardResponse:
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


def _inspect_context(payload: ContextGuardRequest) -> JSONResponse:
    if (
        get_context_guard_decision(payload.application_id, payload.request_id)
        is not None
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Context request ID has already been used for this application.",
        )

    chunks = [chunk.model_dump() for chunk in payload.chunks]
    decision = inspect_context_chunks(chunks)
    try:
        record_context_guard_decision(
            application_id=payload.application_id,
            channel=payload.channel,
            request_id=payload.request_id,
            decision=decision.decision,
            classification=decision.classification,
            risk_score=decision.risk_score,
            action=decision.action,
            source_references=[
                (chunk.source_id, chunk.chunk_id) for chunk in payload.chunks
            ],
        )
    except DuplicateGuardRequestError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Context request ID has already been used for this application.",
        ) from None

    response = ContextGuardResponse(
        request_id=payload.request_id,
        stage="context",
        decision=decision.decision,
        classification=decision.classification,
        threat_type=decision.threat_type,
        severity=decision.severity,
        risk_score=decision.risk_score,
        action=decision.action,
        reasons=list(decision.reasons),
        sanitized_chunks=(
            [SanitizedContextChunk(**chunk) for chunk in decision.sanitized_chunks]
            if decision.sanitized_chunks is not None
            else None
        ),
    )
    return JSONResponse(response.model_dump(mode="json", exclude_none=True))
