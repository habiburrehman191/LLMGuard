from __future__ import annotations

from app.llmguard.risk_engine import StageSignal, signal

INTENT_KEYWORDS = {
    "privilege_escalation": (
        "act as admin",
        "pretend i am admin",
        "use admin privileges",
        "developer/admin mode",
        "super admin",
        "exam controller",
        "finance admin",
    ),
    "policy_bypass": (
        "ignore previous",
        "ignore role",
        "bypass access control",
        "override portal permissions",
        "unrestricted access",
        "policy says not to",
    ),
    "data_exfiltration": (
        "show all records",
        "export all",
        "dump",
        "exfiltrate",
        "retrieve internal data",
        "confidential documents",
    ),
    "indirect_prompt_injection": (
        "retrieved document overrides",
        "document overrides",
        "follow the retrieved document",
        "context overrides",
    ),
    "tool_misuse": (
        "admin_secret_lookup",
        "restricted_student_record_lookup",
        "call the tool",
        "use any tool",
    ),
    "unauthorized_record_lookup": (
        "private student records",
        "employee records",
        "admin notes",
        "exam records",
        "budget",
        "contracts",
        "token",
    ),
    "authorized_record_lookup": (
        "my record",
        "my application",
        "my challan",
        "my profile",
        "my status",
    ),
}


def classify_intent(prompt: str, *, user_role: str | None = None) -> StageSignal:
    lowered = " ".join(prompt.lower().split())
    matches: list[str] = []
    reasons: list[str] = []
    for intent, keywords in INTENT_KEYWORDS.items():
        matched = next((keyword for keyword in keywords if keyword in lowered), None)
        if matched:
            matches.append(intent)
            reasons.append(f"Intent {intent} matched phrase '{matched}'.")

    if not matches:
        return signal(
            "intent_classifier",
            label="safe",
            action="allow",
            score=0.05,
            reasons=["Intent classified as safe_information_request."],
            metadata={"intent": "safe_information_request", "user_role": user_role},
        )

    primary = matches[0]
    if any(intent in matches for intent in ("privilege_escalation", "policy_bypass", "data_exfiltration", "tool_misuse")):
        label = "malicious"
        action = "block"
        score = 0.90
    elif "indirect_prompt_injection" in matches or "unauthorized_record_lookup" in matches:
        label = "malicious"
        action = "quarantine"
        score = 0.82
    else:
        label = "suspicious"
        action = "sanitize"
        score = 0.42

    return signal(
        "intent_classifier",
        label=label,
        action=action,
        score=score,
        reasons=reasons,
        threat_source="prompt",
        metadata={"intent": primary, "all_intents": matches, "user_role": user_role},
    )
