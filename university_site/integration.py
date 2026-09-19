from __future__ import annotations

import asyncio
from dataclasses import dataclass
import os

import httpx

from sdk.llmguard_client import HeartbeatResult, LLMGuardClient


class LLMGuardIntegrationConfigurationError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class HeartbeatClientConfig:
    sdk_client: LLMGuardClient
    application_version: str | None = None
    integration_version: str = "heartbeat-v1"
    channels: tuple[str, ...] = ("public", "student", "employee")
    interval_seconds: int = 30


def llmguard_client_from_env() -> LLMGuardClient | None:
    key_id = os.getenv("UOH_LLMGUARD_KEY_ID", "").strip()
    api_secret = os.getenv("UOH_LLMGUARD_API_SECRET", "").strip()
    if not key_id and not api_secret:
        return None
    if not key_id or not api_secret:
        raise LLMGuardIntegrationConfigurationError(
            "LLMGuard integration credentials are incomplete."
        )
    try:
        return LLMGuardClient(
            base_url=os.getenv("UOH_LLMGUARD_BASE_URL", "http://127.0.0.1:8000"),
            application_id=os.getenv(
                "UOH_LLMGUARD_APPLICATION_ID",
                "university-of-haripur",
            ),
            key_id=key_id,
            api_secret=api_secret,
            environment=os.getenv("UOH_LLMGUARD_ENVIRONMENT", "development"),
            timeout=float(os.getenv("UOH_LLMGUARD_TIMEOUT_SECONDS", "5")),
        )
    except (TypeError, ValueError) as exc:
        raise LLMGuardIntegrationConfigurationError(
            "LLMGuard integration configuration is invalid."
        ) from exc


def heartbeat_config_from_env() -> HeartbeatClientConfig | None:
    try:
        sdk_client = llmguard_client_from_env()
    except LLMGuardIntegrationConfigurationError:
        return None
    if sdk_client is None:
        return None
    application_version = os.getenv("UOH_APPLICATION_VERSION", "").strip() or None
    return HeartbeatClientConfig(
        sdk_client=sdk_client,
        application_version=application_version,
        integration_version=os.getenv(
            "UOH_LLMGUARD_INTEGRATION_VERSION",
            "heartbeat-v1",
        ).strip(),
        interval_seconds=max(
            5,
            int(os.getenv("UOH_LLMGUARD_HEARTBEAT_INTERVAL_SECONDS", "30")),
        ),
    )


async def send_heartbeat(
    config: HeartbeatClientConfig,
    *,
    client: httpx.AsyncClient | None = None,
) -> HeartbeatResult:
    return await config.sdk_client.send_heartbeat(
        application_version=config.application_version,
        integration_version=config.integration_version,
        channels=config.channels,
        http_client=client,
    )


async def heartbeat_loop(config: HeartbeatClientConfig) -> None:
    while True:
        await send_heartbeat(config)
        await asyncio.sleep(config.interval_seconds)
