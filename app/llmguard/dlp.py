from __future__ import annotations

from app.dlp import detect_dlp as legacy_detect_dlp
from app.llmguard.risk_engine import StageSignal, signal
from app.output_firewall import detect_canary_markers

SENSITIVE_PATTERNS = {
    "student_records": ("student record", "student portal record", "student_private", "student id"),
    "employee_records": ("employee record", "employee_private", "staff ref"),
    "exam_records": ("exam marks", "exam record", "grade sheet", "result ledger"),
    "finance_budget_data": ("budget", "fee ledger", "fee status", "finance_confidential"),
    "contracts": ("contract", "vendor contract", "procurement"),
    "internal_admin_notes": ("admin notes", "internal admin", "portal rules"),
    "tokens": ("admin token", "api key", "secret token", "restricted_secret"),
    "credentials": ("password", "credential", ".env"),
}


def detect_sensitive_data(text: str, *, user_role: str | None = None, source: str = "prompt") -> StageSignal:
    lowered = " ".join(text.lower().split())
    categories: list[str] = []
    reasons: list[str] = []
    for category, patterns in SENSITIVE_PATTERNS.items():
        matched = next((pattern for pattern in patterns if pattern in lowered), None)
        if matched:
            categories.append(category)
            reasons.append(f"DLP matched {category}: '{matched}'.")

    canaries = detect_canary_markers(text)
    if canaries:
        categories.append("canary_markers")
        reasons.append(f"DLP detected canary marker(s): {', '.join(canaries)}.")

    legacy = legacy_detect_dlp(text, user_role)
    if legacy.label != "safe":
        reasons.extend(legacy.reasons)
        categories.extend(legacy.requested_classifications)

    categories = list(dict.fromkeys(categories))
    if not categories:
        return signal(
            "dlp",
            label="safe",
            action="allow",
            score=0.04,
            reasons=["No sensitive synthetic data category detected."],
            threat_source="none",
            metadata={"categories": []},
        )

    if canaries or "restricted_secret" in categories or legacy.action in {"block", "quarantine"}:
        label = "malicious"
        action = "block"
        score = max(0.94, legacy.risk_score)
    else:
        label = "suspicious"
        action = "sanitize"
        score = max(0.55, legacy.risk_score)

    return signal(
        "dlp",
        label=label,
        action=action,
        score=score,
        reasons=list(dict.fromkeys(reasons)),
        threat_source=source,
        metadata={
            "categories": categories,
            "legacy_attack_type": legacy.attack_type,
            "canary_markers": canaries,
        },
    )
