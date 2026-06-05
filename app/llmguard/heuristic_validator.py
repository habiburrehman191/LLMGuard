from __future__ import annotations

from app.llmguard.risk_engine import StageSignal, signal

ROLE_PHRASES = {
    "student": ("admin", "super admin", "employee portal", "finance admin", "exam controller"),
    "employee": ("student portal", "admin portal", "super admin", "finance admin", "exam controller"),
    "public_user": ("student portal", "employee portal", "admin portal", "internal data"),
}

CROSS_PORTAL_PHRASES = (
    "lateral movement",
    "switch portal",
    "use another portal role",
    "cross portal",
    "access employee module",
    "access student module",
    "access admin module",
)


def validate_prompt_context(prompt: str, *, user_role: str | None = None) -> StageSignal:
    role = (user_role or "public_user").lower()
    lowered = " ".join(prompt.lower().split())
    reasons: list[str] = []

    for phrase in ROLE_PHRASES.get(role, ()):
        if phrase in lowered and any(term in lowered for term in ("pretend", "act as", "login as", "access", "show", "use")):
            reasons.append(f"{role} prompt appears to request another role or portal: '{phrase}'.")

    if "student" in role and "pretend" in lowered and "admin" in lowered:
        reasons.append("Student pretending admin pattern detected.")
    if "employee" in role and "pretend" in lowered and "super admin" in lowered:
        reasons.append("Employee pretending super admin pattern detected.")
    if role == "public_user" and any(term in lowered for term in ("internal data", "admin notes", "budget", "contracts", "exam records")):
        reasons.append("Public prompt requests internal university data.")

    matched_cross_portal = next((phrase for phrase in CROSS_PORTAL_PHRASES if phrase in lowered), None)
    if matched_cross_portal:
        reasons.append(f"Cross-portal or lateral movement phrase detected: '{matched_cross_portal}'.")

    if not reasons:
        return signal(
            "heuristic_validator",
            label="safe",
            action="allow",
            score=0.04,
            reasons=["No dynamic role or portal heuristic violation detected."],
            metadata={"user_role": role},
        )

    return signal(
        "heuristic_validator",
        label="malicious",
        action="block",
        score=0.91,
        reasons=reasons,
        threat_source="access_control",
        metadata={"user_role": role},
    )
