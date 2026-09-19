from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from typing import Any

import httpx

from .models import ClientErrorCode, HeartbeatResult, LLMGuardClientError


HEARTBEAT_PATH = "/api/v1/integrations/heartbeat"


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
        headers = {
            "X-LLMGuard-Key-ID": self.key_id,
            "X-LLMGuard-API-Secret": self._api_secret,
        }
        url = f"{self.base_url}{HEARTBEAT_PATH}"

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
            return _failure(
                ClientErrorCode.TIMEOUT,
                "LLMGuard heartbeat request timed out.",
            )
        except httpx.ConnectError:
            return _failure(
                ClientErrorCode.CONNECTION_FAILURE,
                "Could not connect to LLMGuard.",
            )
        except httpx.RequestError:
            return _failure(
                ClientErrorCode.REQUEST_FAILURE,
                "LLMGuard heartbeat request could not be sent.",
            )

        if not response.is_success:
            return _failure(
                ClientErrorCode.HTTP_ERROR,
                "LLMGuard rejected the heartbeat request.",
                status_code=response.status_code,
            )

        try:
            response_data = response.json()
        except ValueError:
            return _failure(
                ClientErrorCode.INVALID_RESPONSE,
                "LLMGuard returned an invalid heartbeat response.",
            )

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


def _required_text(value: str, field_name: str) -> str:
    normalized = value.strip()
    if not normalized:
        raise ValueError(f"{field_name} must not be empty")
    return normalized


def _optional_text(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip()
    return normalized or None


def _normalize_channels(channels: Sequence[str]) -> list[str]:
    normalized = list(dict.fromkeys(channel.strip().lower() for channel in channels))
    if not normalized or any(not channel for channel in normalized):
        raise ValueError("channels must contain at least one non-empty channel")
    return normalized


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)
