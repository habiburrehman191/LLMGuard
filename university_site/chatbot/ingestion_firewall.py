from __future__ import annotations

import asyncio
import hashlib
import re
from typing import Mapping, Sequence
from uuid import uuid4

from sdk.llmguard_client import LLMGuardClient

from ..integration import (
    LLMGuardIntegrationConfigurationError,
    llmguard_client_from_env,
)


class UniversityIngestionInspectionError(RuntimeError):
    """Raised when configured pre-index inspection cannot safely complete."""


def inspect_sources_before_index(
    sources: Sequence[Mapping[str, object]],
) -> list[dict[str, object]]:
    """Inspect trusted University sources before database or vector writes."""
    try:
        client = llmguard_client_from_env()
    except LLMGuardIntegrationConfigurationError as exc:
        raise UniversityIngestionInspectionError(
            "Configured LLMGuard document inspection is unavailable."
        ) from exc

    documents = [dict(source) for source in sources]
    if client is None:
        return documents

    batch_id = uuid4().hex
    inspected: list[dict[str, object]] = []
    for index, document in enumerate(documents):
        outcome = _inspect_source(
            client,
            document,
            request_id=f"uoh-ingestion-{batch_id}-{index}",
        )
        if outcome is not None:
            inspected.append(outcome)
    return inspected


def _inspect_source(
    client: LLMGuardClient,
    document: dict[str, object],
    *,
    request_id: str,
) -> dict[str, object] | None:
    source_id = _required_source_text(document, "source_id")
    channel = _required_source_text(document, "portal_scope")
    if channel not in {"public", "student", "employee"}:
        raise UniversityIngestionInspectionError(
            "University source channel is not valid for LLMGuard inspection."
        )
    content = _required_source_text(document, "content")
    source_type = _required_source_text(document, "source_type")
    classification = _required_source_text(document, "classification")

    try:
        result = asyncio.run(
            client.inspect_document(
                request_id=request_id,
                channel=channel,
                source_id=source_id,
                filename=_inspection_filename(source_id),
                mime_type="text/plain",
                text=content,
                metadata={
                    "source_type": source_type,
                    "classification": classification,
                    "portal_scope": channel,
                },
            )
        )
    except Exception as exc:
        raise UniversityIngestionInspectionError(
            "Configured LLMGuard document inspection is unavailable."
        ) from exc

    if not result.ok or result.source_id != source_id:
        raise UniversityIngestionInspectionError(
            "Configured LLMGuard document inspection failed closed."
        )

    if result.action in {"APPROVE", "BYPASSED"}:
        return document
    if result.action == "SANITIZE":
        sanitized = result.sanitized_text
        if not isinstance(sanitized, str) or not sanitized.strip() or sanitized == content:
            raise UniversityIngestionInspectionError(
                "LLMGuard did not return a valid sanitized document."
            )
        document["content"] = sanitized
        document["content_hash"] = hashlib.sha256(
            sanitized.encode("utf-8")
        ).hexdigest()
        return document
    if result.action in {"QUARANTINE", "REJECT"}:
        return None
    raise UniversityIngestionInspectionError(
        "LLMGuard returned an unsupported document inspection action."
    )


def _inspection_filename(source_id: str) -> str:
    stem = re.sub(r"[^a-zA-Z0-9._-]+", "-", source_id).strip(".-")
    return f"{(stem or 'university-source')[:240]}.txt"


def _required_source_text(
    document: Mapping[str, object],
    field_name: str,
) -> str:
    value = document.get(field_name)
    if not isinstance(value, str) or not value.strip():
        raise UniversityIngestionInspectionError(
            f"University source {field_name} is missing."
        )
    return value
