from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path
import re
from typing import Mapping, Sequence
from uuid import uuid4

from app.rag.chunking import chunk_text
from sdk.llmguard_client import DocumentInspectionResult, LLMGuardClient

from ..integration import (
    LLMGuardIntegrationConfigurationError,
    llmguard_client_from_env,
)


MAX_EXTRACTED_TEXT_BYTES = 128_000
MAX_FILENAME_LENGTH = 255
MAX_METADATA_FIELDS = 32
MAX_METADATA_BYTES = 8_192
MAX_DOCUMENT_SOURCE_ID_LENGTH = 155
CHUNK_ID_SEPARATOR = "::chunk:"
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
PERSISTED_SOURCE_FIELDS = {
    "source_id",
    "source_type",
    "title",
    "content",
    "portal_scope",
    "classification",
    "route",
    "department_id",
    "role_scope",
    "content_hash",
    "updated_at",
}


class UniversityIngestionInspectionError(RuntimeError):
    """Raised when prepared content cannot safely enter the University index."""


def inspect_sources_before_index(
    sources: Sequence[Mapping[str, object]],
) -> list[dict[str, object]]:
    """Validate and inspect University sources before persistence or vector writes."""
    documents = [dict(source) for source in sources]
    validated = [_validated_source(document) for document in documents]

    try:
        client = llmguard_client_from_env()
    except LLMGuardIntegrationConfigurationError as exc:
        raise UniversityIngestionInspectionError(
            "Configured LLMGuard document inspection is unavailable."
        ) from exc

    if client is None:
        return [_persisted_source(document) for document, _, _, _ in validated]

    batch_id = uuid4().hex
    inspected: list[dict[str, object]] = []
    for document_index, (document, filename, mime_type, metadata) in enumerate(
        validated
    ):
        whole_result = _request_inspection(
            client,
            document,
            request_id=f"uoh-ingestion-{batch_id}-{document_index}-document",
            filename=filename,
            mime_type=mime_type,
            metadata=metadata,
        )
        approved_document = _apply_result(document, whole_result)
        if approved_document is None:
            continue

        if whole_result.action == "BYPASSED":
            inspected.append(_persisted_source(approved_document))
            continue

        for chunk in _document_chunks(approved_document):
            chunk_index = chunk_index_from_source_id(str(chunk["source_id"]))
            chunk_metadata = {
                **metadata,
                "document_source_id": str(approved_document["source_id"]),
                "chunk_index": chunk_index,
            }
            chunk_result = _request_inspection(
                client,
                chunk,
                request_id=(
                    f"uoh-ingestion-{batch_id}-{document_index}-chunk-{chunk_index}"
                ),
                filename=filename,
                mime_type=mime_type,
                metadata=_bounded_metadata(chunk_metadata),
            )
            approved_chunk = _apply_result(chunk, chunk_result)
            if approved_chunk is not None:
                inspected.append(_persisted_source(approved_chunk))
    return inspected


def document_source_id_from_chunk_id(source_id: str) -> str:
    return source_id.split(CHUNK_ID_SEPARATOR, 1)[0]


def chunk_index_from_source_id(source_id: str) -> int:
    marker, separator, value = source_id.rpartition(CHUNK_ID_SEPARATOR)
    if not separator or not marker or not value.isdigit():
        raise UniversityIngestionInspectionError(
            "University chunk identity is malformed."
        )
    return int(value)


def _validated_source(
    document: dict[str, object],
) -> tuple[dict[str, object], str, str, dict[str, object]]:
    source_id = _required_source_text(document, "source_id")
    if (
        len(source_id) > MAX_DOCUMENT_SOURCE_ID_LENGTH
        or CHUNK_ID_SEPARATOR in source_id
    ):
        raise UniversityIngestionInspectionError(
            "University source identity is invalid or exceeds the supported length."
        )

    channel = _required_source_text(document, "portal_scope")
    if channel not in {"public", "student", "employee"}:
        raise UniversityIngestionInspectionError(
            "University source channel is not valid for LLMGuard inspection."
        )

    content = _required_source_text(document, "content", strip=False)
    _validate_extracted_text(content)
    _required_source_text(document, "source_type")
    _required_source_text(document, "classification")

    filename_value = document.get("filename")
    filename = (
        _inspection_filename(source_id)
        if filename_value is None
        else _validate_filename(filename_value)
    )
    mime_value = document.get("mime_type", "text/plain")
    if not isinstance(mime_value, str):
        raise UniversityIngestionInspectionError(
            "University source MIME type is invalid."
        )
    mime_type = mime_value.split(";", 1)[0].strip().lower()
    if mime_type not in SUPPORTED_TEXT_TYPES:
        raise UniversityIngestionInspectionError(
            "University source MIME type is not supported."
        )
    if Path(filename).suffix.lower() not in SUPPORTED_TEXT_TYPES[mime_type]:
        raise UniversityIngestionInspectionError(
            "University source filename extension does not match its MIME type."
        )

    supplied_metadata = document.get("metadata")
    if supplied_metadata is None:
        extra_metadata: dict[str, object] = {}
    elif isinstance(supplied_metadata, Mapping):
        extra_metadata = dict(supplied_metadata)
    else:
        raise UniversityIngestionInspectionError(
            "University source metadata must be an object."
        )
    if len(extra_metadata) > MAX_METADATA_FIELDS - 5:
        raise UniversityIngestionInspectionError(
            "University source metadata has too many fields."
        )
    metadata = _bounded_metadata(
        {
            **extra_metadata,
            "source_type": str(document["source_type"]),
            "classification": str(document["classification"]),
            "portal_scope": channel,
        }
    )
    _bounded_metadata(
        {
            **metadata,
            "document_source_id": source_id,
            "chunk_index": 0,
        }
    )
    return document, filename, mime_type, metadata


def _validate_filename(value: object) -> str:
    if not isinstance(value, str):
        raise UniversityIngestionInspectionError(
            "University source filename is invalid."
        )
    filename = value.strip()
    if (
        not filename
        or len(filename) > MAX_FILENAME_LENGTH
        or filename in {".", ".."}
        or "/" in filename
        or "\\" in filename
        or ":" in filename
        or "\x00" in filename
    ):
        raise UniversityIngestionInspectionError(
            "University source filename is invalid."
        )
    return filename


def _validate_extracted_text(text: str) -> None:
    try:
        encoded = text.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise UniversityIngestionInspectionError(
            "University source extraction contains malformed text."
        ) from exc
    if not text.strip():
        raise UniversityIngestionInspectionError(
            "University source extraction is empty."
        )
    if len(encoded) > MAX_EXTRACTED_TEXT_BYTES:
        raise UniversityIngestionInspectionError(
            "University source extraction exceeds the size limit."
        )
    if any(ord(character) < 32 and character not in "\t\n\r" for character in text):
        raise UniversityIngestionInspectionError(
            "University source extraction contains malformed text."
        )


def _bounded_metadata(metadata: Mapping[object, object]) -> dict[str, object]:
    if len(metadata) > MAX_METADATA_FIELDS:
        raise UniversityIngestionInspectionError(
            "University source metadata has too many fields."
        )
    normalized: dict[str, object] = {}
    for key, value in metadata.items():
        if not isinstance(key, str) or not key.strip() or len(key) > 100:
            raise UniversityIngestionInspectionError(
                "University source metadata contains an invalid field name."
            )
        normalized[key] = value
    try:
        encoded = json.dumps(
            normalized,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, UnicodeEncodeError, ValueError) as exc:
        raise UniversityIngestionInspectionError(
            "University source metadata is malformed."
        ) from exc
    if len(encoded) > MAX_METADATA_BYTES:
        raise UniversityIngestionInspectionError(
            "University source metadata exceeds the size limit."
        )
    return normalized


def _document_chunks(document: Mapping[str, object]) -> list[dict[str, object]]:
    source_id = str(document["source_id"])
    base = _persisted_source(document)
    chunks = chunk_text(
        str(document["content"]),
        {"document_source_id": source_id},
    )
    if not chunks:
        raise UniversityIngestionInspectionError(
            "University source extraction produced no indexable chunks."
        )
    prepared: list[dict[str, object]] = []
    for payload in chunks:
        chunk = dict(base)
        chunk_id = f"{source_id}{CHUNK_ID_SEPARATOR}{payload.chunk_index:04d}"
        if len(chunk_id) > 180:
            raise UniversityIngestionInspectionError(
                "University chunk identity exceeds the storage limit."
            )
        chunk["source_id"] = chunk_id
        chunk["content"] = payload.chunk_text
        chunk["content_hash"] = hashlib.sha256(
            payload.chunk_text.encode("utf-8")
        ).hexdigest()
        prepared.append(chunk)
    return prepared


def _request_inspection(
    client: LLMGuardClient,
    document: Mapping[str, object],
    *,
    request_id: str,
    filename: str,
    mime_type: str,
    metadata: Mapping[str, object],
) -> DocumentInspectionResult:
    try:
        return asyncio.run(
            client.inspect_document(
                request_id=request_id,
                channel=str(document["portal_scope"]),
                source_id=str(document["source_id"]),
                filename=filename,
                mime_type=mime_type,
                text=str(document["content"]),
                metadata=metadata,
            )
        )
    except Exception as exc:
        raise UniversityIngestionInspectionError(
            "Configured LLMGuard document inspection is unavailable."
        ) from exc


def _apply_result(
    document: Mapping[str, object],
    result: DocumentInspectionResult,
) -> dict[str, object] | None:
    source_id = str(document["source_id"])
    if not result.ok or result.source_id != source_id:
        raise UniversityIngestionInspectionError(
            "Configured LLMGuard document inspection failed closed."
        )

    approved = dict(document)
    if result.action in {"APPROVE", "BYPASSED"}:
        return approved
    if result.action == "SANITIZE":
        sanitized = result.sanitized_text
        if (
            not isinstance(sanitized, str)
            or not sanitized.strip()
            or sanitized == document["content"]
        ):
            raise UniversityIngestionInspectionError(
                "LLMGuard did not return a valid sanitized document."
            )
        _validate_extracted_text(sanitized)
        approved["content"] = sanitized
        approved["content_hash"] = hashlib.sha256(
            sanitized.encode("utf-8")
        ).hexdigest()
        return approved
    if result.action in {"QUARANTINE", "REJECT"}:
        return None
    raise UniversityIngestionInspectionError(
        "LLMGuard returned an unsupported document inspection action."
    )


def _persisted_source(document: Mapping[str, object]) -> dict[str, object]:
    return {
        field: document[field]
        for field in PERSISTED_SOURCE_FIELDS
        if field in document
    }


def _inspection_filename(source_id: str) -> str:
    stem = re.sub(r"[^a-zA-Z0-9._-]+", "-", source_id).strip(".-")
    return f"{(stem or 'university-source')[:240]}.txt"


def _required_source_text(
    document: Mapping[str, object],
    field_name: str,
    *,
    strip: bool = True,
) -> str:
    value = document.get(field_name)
    if not isinstance(value, str) or not value.strip():
        raise UniversityIngestionInspectionError(
            f"University source {field_name} is missing."
        )
    return value.strip() if strip else value
