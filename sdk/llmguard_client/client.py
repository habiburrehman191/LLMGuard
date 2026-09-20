from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from typing import Any

import httpx

from .models import (
    ClientErrorCode,
    ContextInspectionResult,
    HeartbeatResult,
    InputInspectionResult,
    LLMGuardClientError,
    OutputInspectionResult,
)


HEARTBEAT_PATH = "/api/v1/integrations/heartbeat"
GUARD_PATH = "/api/v1/guard"


class LLMGuardClient:
    """Asynchronous backend client for authenticated LLMGuard integration APIs."""

    def __init__(
        self,
        *,
        base_url: str,
        application_id: str,
        key_id: str,
        api_secret: str,
        environment: str,
        timeout: float = 5.0,
    ) -> None:
        self.base_url = _required_text(base_url, "base_url").rstrip("/")
        self.application_id = _required_text(application_id, "application_id")
        self.key_id = _required_text(key_id, "key_id")
        self._api_secret = _required_text(api_secret, "api_secret")
        self.environment = _required_text(environment, "environment").lower()
        self.timeout = float(timeout)
        if self.timeout <= 0:
            raise ValueError("timeout must be greater than zero")

    def __repr__(self) -> str:
        return (
            "LLMGuardClient("
            f"application_id={self.application_id!r}, "
            f"environment={self.environment!r}, "
            f"timeout={self.timeout!r})"
        )

    async def send_heartbeat(
        self,
        *,
        channels: Sequence[str],
        application_version: str | None = None,
        integration_version: str | None = None,
        timestamp: datetime | None = None,
        http_client: httpx.AsyncClient | None = None,
    ) -> HeartbeatResult:
        heartbeat_time = _as_utc(timestamp or datetime.now(timezone.utc))
        payload = {
            "application_id": self.application_id,
            "environment": self.environment,
            "application_version": _optional_text(application_version),
            "integration_version": _optional_text(integration_version),
            "timestamp": heartbeat_time.isoformat(),
            "channels": _normalize_channels(channels),
        }
        response_data, error = await self._post_json(
            HEARTBEAT_PATH,
            payload,
            operation="heartbeat",
            http_client=http_client,
        )
        if error is not None:
            return HeartbeatResult(ok=False, error=error)

        if not _is_valid_heartbeat_response(response_data, self.application_id):
            return _failure(
                ClientErrorCode.INVALID_RESPONSE,
                "LLMGuard returned an invalid heartbeat response.",
            )

        return HeartbeatResult(
            ok=True,
            accepted=True,
            application_id=self.application_id,
            integration_state=response_data["integration_state"],
            last_heartbeat_at=response_data["last_heartbeat_at"],
        )

    async def inspect_input(
        self,
        *,
        request_id: str,
        channel: str,
        content: str,
        security_context: Mapping[str, Any],
        http_client: httpx.AsyncClient | None = None,
    ) -> InputInspectionResult:
        payload = {
            "application_id": self.application_id,
            "request_id": _required_text(request_id, "request_id"),
            "channel": _required_text(channel, "channel").lower(),
            "stage": "input",
            "content": _required_content(content),
            "security_context": dict(security_context),
        }
        response_data, error = await self._post_json(
            GUARD_PATH,
            payload,
            operation="input inspection",
            http_client=http_client,
        )
        if error is not None:
            return InputInspectionResult(ok=False, error=error)

        if not _is_valid_input_response(response_data, payload["request_id"]):
            return InputInspectionResult(
                ok=False,
                error=LLMGuardClientError(
                    code=ClientErrorCode.INVALID_RESPONSE,
                    message="LLMGuard returned an invalid input inspection response.",
                ),
            )

        return InputInspectionResult(
            ok=True,
            request_id=response_data["request_id"],
            stage=response_data["stage"],
            decision=response_data["decision"],
            classification=response_data["classification"],
            threat_type=response_data["threat_type"],
            severity=response_data["severity"],
            risk_score=_optional_risk_score(response_data["risk_score"]),
            action=response_data["action"],
            reasons=tuple(response_data["reasons"]),
        )

    async def inspect_context(
        self,
        *,
        request_id: str,
        channel: str,
        chunks: Sequence[Mapping[str, Any]],
        http_client: httpx.AsyncClient | None = None,
    ) -> ContextInspectionResult:
        payload = {
            "application_id": self.application_id,
            "request_id": _required_text(request_id, "request_id"),
            "channel": _required_text(channel, "channel").lower(),
            "stage": "context",
            "chunks": _normalize_context_chunks(chunks),
        }
        response_data, error = await self._post_json(
            GUARD_PATH,
            payload,
            operation="context inspection",
            http_client=http_client,
        )
        if error is not None:
            return ContextInspectionResult(ok=False, error=error)

        if not _is_valid_context_response(response_data, payload["request_id"]):
            return ContextInspectionResult(
                ok=False,
                error=LLMGuardClientError(
                    code=ClientErrorCode.INVALID_RESPONSE,
                    message="LLMGuard returned an invalid context inspection response.",
                ),
            )

        sanitized_chunks = response_data.get("sanitized_chunks")
        return ContextInspectionResult(
            ok=True,
            request_id=response_data["request_id"],
            stage=response_data["stage"],
            decision=response_data["decision"],
            classification=response_data["classification"],
            threat_type=response_data.get("threat_type"),
            severity=response_data["severity"],
            risk_score=_optional_risk_score(response_data["risk_score"]),
            action=response_data["action"],
            reasons=tuple(response_data["reasons"]),
            sanitized_chunks=(
                tuple(dict(chunk) for chunk in sanitized_chunks)
                if isinstance(sanitized_chunks, list)
                else None
            ),
        )

    async def inspect_output(
        self,
        *,
        request_id: str,
        channel: str,
        content: str,
        security_context: Mapping[str, Any],
        http_client: httpx.AsyncClient | None = None,
    ) -> OutputInspectionResult:
        payload = {
            "application_id": self.application_id,
            "request_id": _required_text(request_id, "request_id"),
            "channel": _required_text(channel, "channel").lower(),
            "stage": "output",
            "content": _required_content(content),
            "security_context": dict(security_context),
        }
        response_data, error = await self._post_json(
            GUARD_PATH,
            payload,
            operation="output inspection",
            http_client=http_client,
        )
        if error is not None:
            return OutputInspectionResult(ok=False, error=error)

        if not _is_valid_output_response(
            response_data,
            payload["request_id"],
            original_content=payload["content"],
        ):
            return OutputInspectionResult(
                ok=False,
                error=LLMGuardClientError(
                    code=ClientErrorCode.INVALID_RESPONSE,
                    message="LLMGuard returned an invalid output inspection response.",
                ),
            )

        return OutputInspectionResult(
            ok=True,
            request_id=response_data["request_id"],
            stage=response_data["stage"],
            decision=response_data["decision"],
            classification=response_data["classification"],
            threat_type=response_data.get("threat_type"),
            severity=response_data["severity"],
            risk_score=_optional_risk_score(response_data["risk_score"]),
            action=response_data["action"],
            reasons=tuple(response_data["reasons"]),
            sanitized_content=response_data.get("sanitized_content"),
        )

    async def _post_json(
        self,
        path: str,
        payload: dict[str, Any],
        *,
        operation: str,
        http_client: httpx.AsyncClient | None,
    ) -> tuple[Any | None, LLMGuardClientError | None]:
        headers = {
            "X-LLMGuard-Key-ID": self.key_id,
            "X-LLMGuard-API-Secret": self._api_secret,
        }
        url = f"{self.base_url}{path}"
        try:
            if http_client is not None:
                response = await http_client.post(
                    url,
                    json=payload,
                    headers=headers,
                    timeout=self.timeout,
                )
            else:
                async with httpx.AsyncClient(timeout=self.timeout) as owned_client:
                    response = await owned_client.post(
                        url,
                        json=payload,
                        headers=headers,
                    )
        except httpx.TimeoutException:
            return None, LLMGuardClientError(
                code=ClientErrorCode.TIMEOUT,
                message=f"LLMGuard {operation} request timed out.",
            )
        except httpx.ConnectError:
            return None, LLMGuardClientError(
                code=ClientErrorCode.CONNECTION_FAILURE,
                message="Could not connect to LLMGuard.",
            )
        except httpx.RequestError:
            return None, LLMGuardClientError(
                code=ClientErrorCode.REQUEST_FAILURE,
                message=f"LLMGuard {operation} request could not be sent.",
            )
        except (TypeError, ValueError):
            return None, LLMGuardClientError(
                code=ClientErrorCode.REQUEST_FAILURE,
                message=f"LLMGuard {operation} request could not be encoded.",
            )

        if not response.is_success:
            return None, LLMGuardClientError(
                code=ClientErrorCode.HTTP_ERROR,
                message=f"LLMGuard rejected the {operation} request.",
                status_code=response.status_code,
            )

        try:
            return response.json(), None
        except ValueError:
            return None, LLMGuardClientError(
                code=ClientErrorCode.INVALID_RESPONSE,
                message=f"LLMGuard returned an invalid {operation} response.",
            )


def _failure(
    code: ClientErrorCode,
    message: str,
    *,
    status_code: int | None = None,
) -> HeartbeatResult:
    return HeartbeatResult(
        ok=False,
        error=LLMGuardClientError(
            code=code,
            message=message,
            status_code=status_code,
        ),
    )


def _is_valid_heartbeat_response(value: Any, application_id: str) -> bool:
    if not isinstance(value, Mapping):
        return False
    return (
        value.get("accepted") is True
        and value.get("application_id") == application_id
        and value.get("integration_state") == "CONNECTED"
        and isinstance(value.get("last_heartbeat_at"), str)
        and bool(value["last_heartbeat_at"].strip())
    )


def _is_valid_input_response(value: Any, request_id: str) -> bool:
    return _is_valid_inspection_response(value, request_id, stage="input")


def _is_valid_context_response(value: Any, request_id: str) -> bool:
    if not _is_valid_inspection_response(value, request_id, stage="context"):
        return False
    if not isinstance(value, Mapping):
        return False
    sanitized_chunks = value.get("sanitized_chunks")
    if sanitized_chunks is None:
        return True
    return (
        value.get("action") == "sanitize"
        and isinstance(sanitized_chunks, list)
        and bool(sanitized_chunks)
        and all(_is_valid_context_chunk(chunk) for chunk in sanitized_chunks)
    )


def _is_valid_output_response(
    value: Any,
    request_id: str,
    *,
    original_content: str,
) -> bool:
    if not _is_valid_inspection_response(value, request_id, stage="output"):
        return False
    if not isinstance(value, Mapping):
        return False
    sanitized_content = value.get("sanitized_content")
    if sanitized_content is None:
        return True
    return (
        value.get("action") == "sanitize"
        and isinstance(sanitized_content, str)
        and bool(sanitized_content.strip())
        and sanitized_content != original_content
    )


def _is_valid_inspection_response(
    value: Any,
    request_id: str,
    *,
    stage: str,
) -> bool:
    if not isinstance(value, Mapping):
        return False
    risk_score = value.get("risk_score")
    threat_type = value.get("threat_type")
    reasons = value.get("reasons")
    common_valid = (
        value.get("request_id") == request_id
        and value.get("stage") == stage
        and (threat_type is None or isinstance(threat_type, str))
        and isinstance(reasons, list)
        and all(isinstance(reason, str) for reason in reasons)
    )
    if not common_valid:
        return False
    if value.get("decision") == "bypassed":
        return (
            value.get("classification") == "bypassed"
            and threat_type is None
            and value.get("severity") == "none"
            and risk_score is None
            and value.get("action") == "bypass"
        )
    return (
        value.get("decision") in {"allow", "restrict"}
        and value.get("classification") in {"safe", "suspicious", "malicious"}
        and value.get("severity") in {"none", "low", "medium", "high", "critical"}
        and isinstance(risk_score, (int, float))
        and not isinstance(risk_score, bool)
        and 0 <= float(risk_score) <= 1
        and value.get("action") in {"allow", "log", "sanitize", "quarantine", "block"}
    )


def _is_valid_context_chunk(value: Any) -> bool:
    if not isinstance(value, Mapping):
        return False
    metadata = value.get("metadata")
    return (
        isinstance(value.get("source_id"), str)
        and bool(value["source_id"].strip())
        and isinstance(value.get("chunk_id"), str)
        and bool(value["chunk_id"].strip())
        and isinstance(value.get("text"), str)
        and (metadata is None or isinstance(metadata, Mapping))
    )


def _required_text(value: str, field_name: str) -> str:
    normalized = value.strip()
    if not normalized:
        raise ValueError(f"{field_name} must not be empty")
    return normalized


def _optional_risk_score(value: Any) -> float | None:
    return float(value) if value is not None else None


def _optional_text(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip()
    return normalized or None


def _required_content(value: str) -> str:
    if not value.strip():
        raise ValueError("content must not be empty")
    return value


def _normalize_channels(channels: Sequence[str]) -> list[str]:
    normalized = list(dict.fromkeys(channel.strip().lower() for channel in channels))
    if not normalized or any(not channel for channel in normalized):
        raise ValueError("channels must contain at least one non-empty channel")
    return normalized


def _normalize_context_chunks(
    chunks: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    if not chunks:
        raise ValueError("chunks must contain at least one context chunk")
    normalized: list[dict[str, Any]] = []
    for chunk in chunks:
        if not isinstance(chunk, Mapping):
            raise ValueError("each context chunk must be a mapping")
        text = chunk.get("text")
        if not isinstance(text, str) or not text.strip():
            raise ValueError("context chunk text must not be empty")
        item: dict[str, Any] = {
            "source_id": _required_mapping_text(chunk.get("source_id"), "source_id"),
            "chunk_id": _required_mapping_text(chunk.get("chunk_id"), "chunk_id"),
            "text": text,
        }
        metadata = chunk.get("metadata")
        if metadata is not None:
            if not isinstance(metadata, Mapping):
                raise ValueError("context chunk metadata must be a mapping")
            item["metadata"] = dict(metadata)
        normalized.append(item)
    return normalized


def _required_mapping_text(value: Any, field_name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string")
    return _required_text(value, field_name)


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)
