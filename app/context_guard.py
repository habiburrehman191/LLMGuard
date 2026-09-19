from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal, Mapping, Sequence

from app.llmguard.context_firewall import inspect_retrieved_chunks


Decision = Literal["allow", "restrict"]
Classification = Literal["safe", "suspicious", "malicious"]
Severity = Literal["none", "medium", "high"]


@dataclass(frozen=True, slots=True)
class ContextGuardDecision:
    decision: Decision
    classification: Classification
    threat_type: str | None
    severity: Severity
    risk_score: float
    action: str
    reasons: tuple[str, ...]
    sanitized_chunks: tuple[dict[str, Any], ...] | None


def inspect_context_chunks(
    chunks: Sequence[Mapping[str, Any]],
) -> ContextGuardDecision:
    detector_chunks = [
        {
            "source_id": str(chunk["source_id"]),
            "chunk_id": str(chunk["chunk_id"]),
            "text": str(chunk["text"]),
            "metadata": dict(chunk["metadata"])
            if isinstance(chunk.get("metadata"), Mapping)
            else None,
        }
        for chunk in chunks
    ]
    assessment = inspect_retrieved_chunks(detector_chunks)
    classification: Classification = assessment.label
    sanitized_chunks = _actual_sanitized_chunks(
        detector_chunks,
        assessment.metadata.get("sanitized_chunks"),
        action=assessment.action,
    )
    return ContextGuardDecision(
        decision=(
            "allow" if assessment.action in {"allow", "log"} else "restrict"
        ),
        classification=classification,
        threat_type=(
            assessment.threat_source
            if assessment.threat_source != "none"
            else None
        ),
        severity={
            "safe": "none",
            "suspicious": "medium",
            "malicious": "high",
        }[classification],
        risk_score=assessment.score,
        action=assessment.action,
        reasons=tuple(assessment.reasons),
        sanitized_chunks=sanitized_chunks,
    )


def _actual_sanitized_chunks(
    original_chunks: list[dict[str, Any]],
    detector_output: object,
    *,
    action: str,
) -> tuple[dict[str, Any], ...] | None:
    if action != "sanitize" or not isinstance(detector_output, list):
        return None

    sanitized: list[dict[str, Any]] = []
    changed = False
    for index, original in enumerate(original_chunks):
        detector_chunk = (
            detector_output[index]
            if index < len(detector_output)
            and isinstance(detector_output[index], Mapping)
            else {}
        )
        sanitized_text = str(detector_chunk.get("chunk_text", original["text"]))
        changed = changed or sanitized_text != original["text"]
        item: dict[str, Any] = {
            "source_id": original["source_id"],
            "chunk_id": original["chunk_id"],
            "text": sanitized_text,
        }
        if original["metadata"] is not None:
            item["metadata"] = original["metadata"]
        sanitized.append(item)

    return tuple(sanitized) if changed else None
