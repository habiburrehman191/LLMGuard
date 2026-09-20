from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from ..integration import (
    LLMGuardIntegrationConfigurationError,
    llmguard_client_from_env,
)


GENERIC_BLOCKED_MESSAGE = "The University AI Assistant cannot process this request."
GENERIC_FAILURE_MESSAGE = (
    "The University AI Assistant is temporarily unavailable. Please try again shortly."
)


@dataclass(frozen=True, slots=True)
class ChatInputPreflight:
    request_id: str
    allowed: bool
    configured: bool
    inspection_failed: bool = False
    protection_bypassed: bool = False


async def inspect_chat_input(
    *,
    request_id: str,
    channel: str,
    content: str,
    security_context: Mapping[str, Any],
) -> ChatInputPreflight:
    try:
        client = llmguard_client_from_env()
    except LLMGuardIntegrationConfigurationError:
        return ChatInputPreflight(
            request_id=request_id,
            allowed=False,
            configured=True,
            inspection_failed=True,
        )

    if client is None:
        return ChatInputPreflight(
            request_id=request_id,
            allowed=True,
            configured=False,
        )

    try:
        result = await client.inspect_input(
            request_id=request_id,
            channel=channel,
            content=content,
            security_context=security_context,
        )
    except Exception:
        return ChatInputPreflight(
            request_id=request_id,
            allowed=False,
            configured=True,
            inspection_failed=True,
        )

    if not result.ok:
        return ChatInputPreflight(
            request_id=request_id,
            allowed=False,
            configured=True,
            inspection_failed=True,
        )

    if (
        result.decision == "bypassed"
        and result.classification == "bypassed"
        and result.action == "bypass"
    ):
        return ChatInputPreflight(
            request_id=request_id,
            allowed=True,
            configured=True,
            protection_bypassed=True,
        )

    allowed = result.decision == "allow" and result.action in {"allow", "log"}
    return ChatInputPreflight(
        request_id=request_id,
        allowed=allowed,
        configured=True,
    )
