from __future__ import annotations

import json
from pathlib import Path
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
from app.document_ingestion_security import inspect_document_text
from app.guard_telemetry import DuplicateGuardRequestError
from app.ingestion_telemetry import (
    get_ingestion_inspection,
    record_ingestion_inspection,
)
from app.protection_control import ensure_protection_config


router = APIRouter(prefix="/api/v1/ingestion", tags=["application-security"])

MAX_DOCUMENT_TEXT_BYTES = 128_000
MAX_METADATA_BYTES = 8_192
SUPPORTED_TEXT_TYPES: dict[str, frozenset[str]] = {
    "text/plain": frozenset({".txt"}),
    "text/markdown": frozenset({".md", ".markdown"}),
    "text/csv": frozenset({".csv"}),
    "application/json": frozenset({".json"}),
    "application/xml": frozenset({".xml"}),
    "text/xml": frozenset({".xml"}),
    "application/yaml": frozenset({".yaml", ".yml"}),
    "text/yaml": frozenset({".yaml", ".yml"}),
}


class IngestionInspectionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    application_id: str = Field(min_length=1, max_length=160)
    request_id: str = Field(min_length=1, max_length=200)
    channel: Literal["public", "student", "employee"]
    source_id: str = Field(min_length=1, max_length=300)
    filename: str = Field(min_length=1, max_length=255)
    mime_type: str = Field(min_length=1, max_length=100)
    text: str = Field(min_length=1, max_length=MAX_DOCUMENT_TEXT_BYTES)
    metadata: dict[str, JsonValue] | None = None

    @field_validator("application_id", "request_id", "source_id")
    @classmethod
    def normalize_identifiers(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("Identifier must not be empty")
        return normalized

    @field_validator("filename")
    @classmethod
    def validate_filename(cls, value: str) -> str:
        normalized = value.strip()
        if (
            not normalized
            or normalized in {".", ".."}
            or "/" in normalized
            or "\\" in normalized
            or ":" in normalized
            or "\x00" in normalized
        ):
            raise ValueError("filename must be a plain file name without a path")
        return normalized

    @field_validator("mime_type")
    @classmethod
    def normalize_mime_type(cls, value: str) -> str:
        normalized = value.split(";", 1)[0].strip().lower()
        if normalized not in SUPPORTED_TEXT_TYPES:
            raise ValueError("mime_type is not a supported text-oriented type")
        return normalized

    @field_validator("text")
    @classmethod
    def bound_text(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("text must not be blank")
        if len(value.encode("utf-8")) > MAX_DOCUMENT_TEXT_BYTES:
            raise ValueError(
                f"text must not exceed {MAX_DOCUMENT_TEXT_BYTES} bytes"
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
            raise ValueError("metadata may contain at most 32 fields")
        encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
        if len(encoded.encode("utf-8")) > MAX_METADATA_BYTES:
            raise ValueError(
                f"metadata must not exceed {MAX_METADATA_BYTES} bytes"
            )
        return value

    @model_validator(mode="after")
    def validate_filename_type(self) -> "IngestionInspectionRequest":
        suffix = Path(self.filename).suffix.lower()
        if suffix not in SUPPORTED_TEXT_TYPES[self.mime_type]:
            raise ValueError("filename extension does not match mime_type")
        return self


class IngestionInspectionResponse(BaseModel):
    request_id: str
    source_id: str
    classification: Literal["safe", "suspicious", "malicious", "bypassed"]
    risk_score: float | None = Field(default=None, ge=0, le=1)
    action: Literal["APPROVE", "SANITIZE", "QUARANTINE", "REJECT", "BYPASSED"]
    reasons: list[str]
    sanitized_text: str | None = None


@router.post("/inspect", response_model=IngestionInspectionResponse)
def inspect_ingestion(
    payload: IngestionInspectionRequest,
    key_id: Annotated[str, Header(alias="X-LLMGuard-Key-ID")],
    api_secret: Annotated[SecretStr, Header(alias="X-LLMGuard-API-Secret")],
) -> JSONResponse:
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

    if not any(
        item.channel == payload.channel and item.enabled
        for item in application.channels
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Application channel is not registered or enabled.",
        )

    if (
        get_ingestion_inspection(payload.application_id, payload.request_id)
        is not None
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Ingestion request ID has already been used for this application.",
        )

    try:
        protection = ensure_protection_config(payload.application_id)
        if not protection.protection_enabled:
            return _record_and_respond(
                payload,
                classification="bypassed",
                risk_score=None,
                action="BYPASSED",
                reasons=["Application protection is disabled by LLMGuard policy."],
            )

        decision = inspect_document_text(
            source_id=payload.source_id,
            text=payload.text,
        )
        return _record_and_respond(
            payload,
            classification=decision.classification,
            risk_score=decision.risk_score,
            action=decision.action,
            reasons=list(decision.reasons),
            sanitized_text=decision.sanitized_text,
        )
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="The LLMGuard ingestion security path is unavailable.",
        ) from None


def _record_and_respond(
    payload: IngestionInspectionRequest,
    *,
    classification: Literal["safe", "suspicious", "malicious", "bypassed"],
    risk_score: float | None,
    action: Literal["APPROVE", "SANITIZE", "QUARANTINE", "REJECT", "BYPASSED"],
    reasons: list[str],
    sanitized_text: str | None = None,
) -> JSONResponse:
    try:
        record_ingestion_inspection(
            application_id=payload.application_id,
            channel=payload.channel,
            source_id=payload.source_id,
            request_id=payload.request_id,
            classification=classification,
            risk_score=risk_score,
            action=action,
        )
    except DuplicateGuardRequestError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Ingestion request ID has already been used for this application.",
        ) from None

    response = IngestionInspectionResponse(
        request_id=payload.request_id,
        source_id=payload.source_id,
        classification=classification,
        risk_score=risk_score,
        action=action,
        reasons=reasons,
        sanitized_text=sanitized_text,
    )
    body = response.model_dump(mode="json")
    if sanitized_text is None:
        body.pop("sanitized_text", None)
    return JSONResponse(body)
