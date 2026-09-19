from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class ClientErrorCode(str, Enum):
    TIMEOUT = "TIMEOUT"
    CONNECTION_FAILURE = "CONNECTION_FAILURE"
    REQUEST_FAILURE = "REQUEST_FAILURE"
    HTTP_ERROR = "HTTP_ERROR"
    INVALID_RESPONSE = "INVALID_RESPONSE"


@dataclass(frozen=True, slots=True)
class LLMGuardClientError:
    code: ClientErrorCode
    message: str
    status_code: int | None = None

    def __str__(self) -> str:
        return self.message


@dataclass(frozen=True, slots=True)
class HeartbeatResult:
    ok: bool
    accepted: bool = False
    application_id: str | None = None
    integration_state: str | None = None
    last_heartbeat_at: str | None = None
    error: LLMGuardClientError | None = None


@dataclass(frozen=True, slots=True)
class InputInspectionResult:
    ok: bool
    request_id: str | None = None
    stage: str | None = None
    decision: str | None = None
    classification: str | None = None
    threat_type: str | None = None
    severity: str | None = None
    risk_score: float | None = None
    action: str | None = None
    reasons: tuple[str, ...] = ()
    error: LLMGuardClientError | None = None


@dataclass(frozen=True, slots=True)
class ContextInspectionResult:
    ok: bool
    request_id: str | None = None
    stage: str | None = None
    decision: str | None = None
    classification: str | None = None
    threat_type: str | None = None
    severity: str | None = None
    risk_score: float | None = None
    action: str | None = None
    reasons: tuple[str, ...] = ()
    sanitized_chunks: tuple[dict[str, Any], ...] | None = None
    error: LLMGuardClientError | None = None
