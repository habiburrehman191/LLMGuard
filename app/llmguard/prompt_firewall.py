from __future__ import annotations

from app.firewall import rule_based_check
from app.llmguard.intent_classifier import classify_intent
from app.llmguard.risk_engine import StageSignal, aggregate_signals, signal
from app.llmguard.semantic_detector import inspect_semantic_intent

PROMPT_ATTACK_PATTERNS = {
    "role_impersonation": (
        "i am the admin",
        "i am admissions admin",
        "i am the exam controller",
        "pretend i am",
        "act as admin",
    ),
    "prompt_injection": (
        "ignore previous instructions",
        "disregard earlier rules",
        "override existing instructions",
        "decode and follow",
        "decode this instruction",
    ),
    "instruction_extraction": (
        "reveal system prompt",
        "hidden system instructions",
        "developer instructions",
        "show hidden instructions",
    ),
    "data_exfiltration": (
        "show all records",
        "dump records",
        "private student records",
        "confidential employee records",
        "internal admin notes",
    ),
    "privilege_escalation": (
        "use admin privileges",
        "super admin mode",
        "override portal permissions",
        "ignore student role",
    ),
    "policy_bypass": (
        "bypass access control",
        "unrestricted access",
        "policy says not to",
        "developer/admin mode",
    ),
    "tool_misuse": (
        "admin_secret_lookup",
        "restricted_student_record_lookup",
        "use any tool",
    ),
}


def _rule_signal(prompt: str) -> StageSignal:
    result = rule_based_check(prompt)
    label = str(result["label"])
    action = "block" if result["blocked"] else "sanitize" if label == "suspicious" else "allow"
    return signal(
        "prompt_firewall_rules",
        label=label,
        action=action,
        score=float(result["risk_score"]),
        reasons=[str(result["reason"])],
        threat_source="prompt" if label != "safe" else "none",
        metadata={"matched_pattern": result.get("matched_pattern")},
    )


def _category_signal(prompt: str) -> StageSignal:
    lowered = " ".join(prompt.lower().split())
    categories: list[str] = []
    reasons: list[str] = []
    for category, patterns in PROMPT_ATTACK_PATTERNS.items():
        matched = next((pattern for pattern in patterns if pattern in lowered), None)
        if matched:
            categories.append(category)
            reasons.append(f"Prompt matched {category}: '{matched}'.")

    if not categories:
        return signal("prompt_firewall_categories", score=0.03, reasons=["No prompt attack category matched."])

    score = min(0.98, 0.55 + (0.12 * len(categories)))
    label = "malicious" if score >= 0.75 else "suspicious"
    return signal(
        "prompt_firewall_categories",
        label=label,
        action="block" if label == "malicious" else "sanitize",
        score=score,
        reasons=reasons,
        threat_source="prompt",
        metadata={"categories": categories},
    )


def inspect_prompt(prompt: str, *, user_role: str | None = None) -> StageSignal:
    decision = aggregate_signals(
        [
            _rule_signal(prompt),
            _category_signal(prompt),
            inspect_semantic_intent(prompt),
            classify_intent(prompt, user_role=user_role),
        ]
    )
    return signal(
        "prompt_firewall",
        label=decision.label,
        action=decision.action,
        score=decision.risk_score,
        reasons=decision.reasons,
        threat_source=decision.threat_source,
        metadata={"stage_scores": decision.stage_scores},
    )
