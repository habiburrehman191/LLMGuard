from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Mapping

from ..integration import (
    LLMGuardIntegrationConfigurationError,
    llmguard_client_from_env,
)
from .types import SourceReference


@dataclass(frozen=True, slots=True)
class ChatContextPreflight:
    request_id: str
    allowed: bool
    configured: bool
    sources: tuple[SourceReference, ...]
    sanitized: bool = False
    inspection_failed: bool = False


async def inspect_chat_context(
    *,
    request_id: str,
    channel: str,
    sources: list[SourceReference],
    security_context: Mapping[str, Any] | None = None,
) -> ChatContextPreflight:
    try:
        client = llmguard_client_from_env()
    except LLMGuardIntegrationConfigurationError:
        return _failed(request_id, configured=True)

    if client is None:
        return ChatContextPreflight(
            request_id=request_id,
            allowed=True,
            configured=False,
            sources=tuple(sources),
        )

    chunks = [_sdk_chunk(source, index) for index, source in enumerate(sources)]
    try:
        result = await client.inspect_context(
            request_id=request_id,
            channel=channel,
            chunks=chunks,
            security_context=security_context,
        )
    except Exception:
        return _failed(request_id, configured=True)

    if not result.ok:
        return _failed(request_id, configured=True)

    if (
        result.decision == "bypassed"
        and result.classification == "bypassed"
        and result.action == "bypass"
    ):
        return ChatContextPreflight(
            request_id=request_id,
            allowed=True,
            configured=True,
            sources=tuple(sources),
        )

    if result.decision == "allow" and result.action in {"allow", "log"}:
        return ChatContextPreflight(
            request_id=request_id,
            allowed=True,
            configured=True,
            sources=tuple(sources),
        )

    if result.action == "sanitize" and result.sanitized_chunks is not None:
        sanitized_sources = _validated_sanitized_sources(
            sources,
            chunks,
            result.sanitized_chunks,
        )
        if sanitized_sources is None:
            return _failed(request_id, configured=True)
        return ChatContextPreflight(
            request_id=request_id,
            allowed=True,
            configured=True,
            sources=sanitized_sources,
            sanitized=True,
        )

    return ChatContextPreflight(
        request_id=request_id,
        allowed=False,
        configured=True,
        sources=(),
    )


def _sdk_chunk(source: SourceReference, index: int) -> dict[str, Any]:
    return {
        "source_id": source.source_id,
        "chunk_id": f"{source.source_id}:{index}",
        "text": source.content,
        "metadata": {
            "source_type": source.source_type,
            "classification": source.classification,
            "portal_scope": source.portal_scope,
        },
    }


def _validated_sanitized_sources(
    sources: list[SourceReference],
    sent_chunks: list[dict[str, Any]],
    sanitized_chunks: tuple[dict[str, Any], ...],
) -> tuple[SourceReference, ...] | None:
    if len(sanitized_chunks) != len(sources):
        return None

    sanitized_sources: list[SourceReference] = []
    for source, sent, returned in zip(sources, sent_chunks, sanitized_chunks):
        if (
            returned.get("source_id") != sent["source_id"]
            or returned.get("chunk_id") != sent["chunk_id"]
            or not isinstance(returned.get("text"), str)
        ):
            return None
        sanitized_sources.append(replace(source, content=returned["text"]))
    return tuple(sanitized_sources)


def _failed(request_id: str, *, configured: bool) -> ChatContextPreflight:
    return ChatContextPreflight(
        request_id=request_id,
        allowed=False,
        configured=configured,
        sources=(),
        inspection_failed=True,
    )
