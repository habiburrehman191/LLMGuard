from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from app.llmguard.context_firewall import inspect_context_text


IngestionAction = Literal["APPROVE", "SANITIZE", "QUARANTINE", "REJECT"]


@dataclass(frozen=True, slots=True)
class DocumentInspectionDecision:
    classification: Literal["safe", "suspicious", "malicious"]
    risk_score: float
    action: IngestionAction
    reasons: tuple[str, ...]
    sanitized_text: str | None
    normalization_applied: bool
    transformations: tuple[str, ...]


def inspect_document_text(
    *,
    source_id: str,
    text: str,
) -> DocumentInspectionDecision:
    """Adapt the existing retrieved-context firewall for pre-index documents."""
    decision = inspect_context_text(text, chunk_id=source_id)

    sanitized_text: str | None = None
    if decision.action in {"allow", "log"}:
        action: IngestionAction = "APPROVE"
    elif decision.action == "sanitize":
        detector_text = decision.metadata.get("sanitized_text")
        candidate = str(detector_text) if detector_text is not None else None
        if candidate is not None and candidate != text:
            action = "SANITIZE"
            sanitized_text = candidate
        else:
            action = "QUARANTINE"
    elif decision.action == "quarantine":
        action = "QUARANTINE"
    else:
        action = "REJECT"

    return DocumentInspectionDecision(
        classification=decision.label,
        risk_score=decision.score,
        action=action,
        reasons=tuple(decision.reasons),
        sanitized_text=sanitized_text,
        normalization_applied=bool(
            decision.metadata.get("normalization_applied")
        ),
        transformations=tuple(
            str(item) for item in decision.metadata.get("transformations", [])
        ),
    )
