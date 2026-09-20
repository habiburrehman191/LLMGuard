from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from app.hybrid_firewall import inspect_with_hybrid_firewall


Decision = Literal["allow", "restrict"]
Classification = Literal["safe", "suspicious", "malicious"]
Severity = Literal["none", "medium", "high"]


@dataclass(frozen=True, slots=True)
class InputGuardDecision:
    decision: Decision
    classification: Classification
    threat_type: None
    severity: Severity
    risk_score: float
    action: str
    reasons: tuple[str, ...]
    normalization_applied: bool
    transformations: tuple[str, ...]


def inspect_input_content(content: str) -> InputGuardDecision:
    assessment = inspect_with_hybrid_firewall(
        content,
        max_content_bytes=16_000,
    )
    classification: Classification = assessment.label
    return InputGuardDecision(
        decision=(
            "allow" if assessment.action in {"allow", "log"} else "restrict"
        ),
        classification=classification,
        threat_type=None,
        severity={
            "safe": "none",
            "suspicious": "medium",
            "malicious": "high",
        }[classification],
        risk_score=assessment.risk_score,
        action=assessment.action,
        reasons=tuple(assessment.reasons),
        normalization_applied=assessment.normalization_applied,
        transformations=assessment.transformations,
    )
