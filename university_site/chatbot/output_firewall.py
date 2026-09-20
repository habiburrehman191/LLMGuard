from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from ..integration import (
    LLMGuardIntegrationConfigurationError,
    llmguard_client_from_env,
)


@dataclass(frozen=True, slots=True)
class ChatOutputPreflight:
    request_id: str
    allowed: bool
    configured: bool
    content: str | None = None
    sanitized: bool = False
    inspection_failed: bool = False


async def inspect_chat_output(
    *,
    request_id: str,
    channel: str,
    content: str,
    security_context: Mapping[str, Any],
) -> ChatOutputPreflight:
    try:
        client = llmguard_client_from_env()
    except LLMGuardIntegrationConfigurationError:
        return _failed(request_id)

    if client is None:
        return ChatOutputPreflight(
            request_id=request_id,
            allowed=True,
            configured=False,
            content=content,
        )

    try:
        result = await client.inspect_output(
            request_id=request_id,
            channel=channel,
            content=content,
            security_context=security_context,
        )
    except Exception:
        return _failed(request_id)

    if (
        not result.ok
        or result.request_id != request_id
        or result.stage != "output"
    ):
        return _failed(request_id)

    if result.decision == "allow" and result.action in {"allow", "log"}:
        return ChatOutputPreflight(
            request_id=request_id,
            allowed=True,
            configured=True,
            content=content,
        )

    if (
        result.decision == "restrict"
        and result.action == "sanitize"
        and isinstance(result.sanitized_content, str)
        and result.sanitized_content.strip()
        and result.sanitized_content != content
    ):
        return ChatOutputPreflight(
            request_id=request_id,
            allowed=True,
            configured=True,
            content=result.sanitized_content,
            sanitized=True,
        )

    return ChatOutputPreflight(
        request_id=request_id,
        allowed=False,
        configured=True,
    )


def _failed(request_id: str) -> ChatOutputPreflight:
    return ChatOutputPreflight(
        request_id=request_id,
        allowed=False,
        configured=True,
        inspection_failed=True,
    )
