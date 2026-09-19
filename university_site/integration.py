from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
import os

import httpx


@dataclass(frozen=True, slots=True)
class HeartbeatClientConfig:
    base_url: str
    application_id: str
    key_id: str
    api_secret: str = field(repr=False)
    environment: str = "development"
    application_version: str | None = None
    integration_version: str = "heartbeat-v1"
    channels: tuple[str, ...] = ("public", "student", "employee")
    interval_seconds: int = 30


def heartbeat_config_from_env() -> HeartbeatClientConfig | None:
    key_id = os.getenv("UOH_LLMGUARD_KEY_ID", "").strip()
    api_secret = os.getenv("UOH_LLMGUARD_API_SECRET", "").strip()
    if not key_id or not api_secret:
        return None
    application_version = os.getenv("UOH_APPLICATION_VERSION", "").strip() or None
    return HeartbeatClientConfig(
        base_url=os.getenv("UOH_LLMGUARD_BASE_URL", "http://127.0.0.1:8000").rstrip("/"),
        application_id=os.getenv(
            "UOH_LLMGUARD_APPLICATION_ID",
            "university-of-haripur",
        ).strip(),
        key_id=key_id,
        api_secret=api_secret,
        environment=os.getenv("UOH_LLMGUARD_ENVIRONMENT", "development").strip().lower(),
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
) -> dict[str, object]:
    payload = {
        "application_id": config.application_id,
        "environment": config.environment,
        "application_version": config.application_version,
        "integration_version": config.integration_version,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "channels": list(config.channels),
    }
    headers = {
        "X-LLMGuard-Key-ID": config.key_id,
        "X-LLMGuard-API-Secret": config.api_secret,
    }
    if client is not None:
        response = await client.post(
            "/api/v1/integrations/heartbeat",
            json=payload,
            headers=headers,
        )
    else:
        async with httpx.AsyncClient(
            base_url=config.base_url,
            timeout=5.0,
        ) as owned_client:
            response = await owned_client.post(
                "/api/v1/integrations/heartbeat",
                json=payload,
                headers=headers,
            )
    response.raise_for_status()
    return response.json()


async def heartbeat_loop(config: HeartbeatClientConfig) -> None:
    while True:
        try:
            await send_heartbeat(config)
        except httpx.HTTPError:
            pass
        await asyncio.sleep(config.interval_seconds)
