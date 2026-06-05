from __future__ import annotations

from dataclasses import dataclass, field
import re

from app.access_control import can_access_classification, normalize_role
from app.dlp import detect_dlp

CANARY_MARKERS = (
    "CANARY_ADMIN_TOKEN_DEMO_ONLY",
    "CANARY_INTERNAL_BUDGET_MARKER",
    "CANARY_STUDENT_RECORD_MARKER",
)

RESTRICTED_OUTPUT_PATTERNS = (
    ".env",
    "api key",
    "admin token",
    "credential",
    "credentials",
    "hidden system instructions",
    "system prompt",
    "developer prompt",
    "restricted_secret",
)

CLASSIFICATION_PATTERNS = {
    "student_self": ("student record", "student portal record", "challan status", "merit status"),
    "exam_confidential": ("exam marks", "exam records", "result ledger", "grade sheet"),
    "finance_confidential": ("budget summary", "fee ledger", "finance record"),
    "contract_confidential": ("vendor contract", "contract value", "procurement contract"),
    "admin_only": ("admin notes", "portal rules", "internal admin"),
    "restricted_secret": ("admin token", "token placeholder", "secret placeholder"),
}


@dataclass(frozen=True)
class OutputFirewallDecision:
    action: str
    label: str
    blocked: bool
    risk_score: float
    reasons: list[str] = field(default_factory=list)
    redacted_text: str | None = None
    canary_markers: list[str] = field(default_factory=list)
    leaked_classifications: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, object]:
        return {
            "action": self.action,
            "label": self.label,
            "blocked": self.blocked,
            "risk_score": self.risk_score,
            "reasons": self.reasons,
            "redacted_text": self.redacted_text,
            "canary_markers": self.canary_markers,
            "leaked_classifications": self.leaked_classifications,
        }


def detect_canary_markers(text: str) -> list[str]:
    return [marker for marker in CANARY_MARKERS if marker in text]


def _redact_canaries(text: str) -> str:
    redacted = text
    for marker in CANARY_MARKERS:
        redacted = redacted.replace(marker, "[REDACTED CANARY]")
    return redacted


def inspect_output(
    text: str | None,
    *,
    user_role: str | None = None,
    allowed_classifications: list[str] | None = None,
) -> OutputFirewallDecision:
    if not text:
        return OutputFirewallDecision(
            action="allow",
            label="safe",
            blocked=False,
            risk_score=0.0,
            reasons=["No output text to inspect."],
            redacted_text=text,
        )

    role = normalize_role(user_role)
    lowered = " ".join(text.lower().split())
    reasons: list[str] = []
    leaked_classifications: list[str] = []
    canaries = detect_canary_markers(text)

    if canaries:
        reasons.append(f"Output contained canary marker(s): {', '.join(canaries)}.")

    for pattern in RESTRICTED_OUTPUT_PATTERNS:
        if pattern in lowered:
            reasons.append(f"Output matched restricted pattern: '{pattern}'.")

    for classification, patterns in CLASSIFICATION_PATTERNS.items():
        if any(pattern in lowered for pattern in patterns):
            if classification == "restricted_secret" or not can_access_classification(role, classification):
                leaked_classifications.append(classification)

    if leaked_classifications:
        reasons.append(
            "Output appeared to contain data outside role permissions: "
            f"{', '.join(dict.fromkeys(leaked_classifications))}."
        )

    dlp_assessment = detect_dlp(text, role)
    if dlp_assessment.action in {"block", "quarantine"}:
        reasons.extend(dlp_assessment.reasons)

    if canaries:
        return OutputFirewallDecision(
            action="quarantine",
            label="malicious",
            blocked=True,
            risk_score=0.99,
            reasons=reasons,
            redacted_text=_redact_canaries(text),
            canary_markers=canaries,
            leaked_classifications=list(dict.fromkeys(leaked_classifications)),
        )

    if reasons and (leaked_classifications or dlp_assessment.action in {"block", "quarantine"}):
        return OutputFirewallDecision(
            action="block",
            label="malicious",
            blocked=True,
            risk_score=0.94,
            reasons=reasons,
            redacted_text=re.sub(r"(?i)(token|credential|secret)[^.\n]*", "[REDACTED]", text),
            canary_markers=[],
            leaked_classifications=list(dict.fromkeys(leaked_classifications)),
        )

    return OutputFirewallDecision(
        action="allow",
        label="safe",
        blocked=False,
        risk_score=0.03,
        reasons=["Output firewall found no leakage."],
        redacted_text=text,
        canary_markers=[],
        leaked_classifications=[],
    )
