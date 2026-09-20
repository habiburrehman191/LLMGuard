from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Mapping

from app.llmguard.output_firewall import inspect_generated_output


Decision = Literal["allow", "restrict"]
Classification = Literal["safe", "suspicious", "malicious"]
Severity = Literal["none", "medium", "high"]


@dataclass(frozen=True, slots=True)
class OutputGuardDecision:
    decision: Decision
    classification: Classification
    threat_type: str | None
    severity: Severity
    risk_score: float
    action: str
    reasons: tuple[str, ...]
    sanitized_content: str | None


def inspect_output_content(
    content: str,
    security_context: Mapping[str, object],
) -> OutputGuardDecision:
    user_role = security_context.get("user_role")
    allowed_classifications = security_context.get("allowed_classifications")
    assessment = inspect_generated_output(
        content,
        user_role=user_role if isinstance(user_role, str) else None,
        allowed_classifications=(
            [item for item in allowed_classifications if isinstance(item, str)]
            if isinstance(allowed_classifications, list)
            else None
        ),
    )
    classification: Classification = assessment.label
    sanitized_content = _actual_sanitized_content(
        content,
        assessment.metadata.get("redacted_text"),
        action=assessment.action,
    )
    return OutputGuardDecision(
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
        sanitized_content=sanitized_content,
    )


def _actual_sanitized_content(
    original_content: str,
    detector_output: object,
    *,
    action: str,
) -> str | None:
    if action != "sanitize" or not isinstance(detector_output, str):
        return None
    return detector_output if detector_output != original_content else None
