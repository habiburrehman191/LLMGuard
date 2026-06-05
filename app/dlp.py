from __future__ import annotations

from dataclasses import dataclass, field

from app.access_control import access_decision, normalize_role


@dataclass(frozen=True)
class DLPAssessment:
    action: str
    label: str
    risk_score: float
    reasons: list[str] = field(default_factory=list)
    requested_classifications: list[str] = field(default_factory=list)
    attack_type: str | None = None

    def as_dict(self) -> dict[str, object]:
        return {
            "action": self.action,
            "label": self.label,
            "risk_score": self.risk_score,
            "reasons": self.reasons,
            "requested_classifications": self.requested_classifications,
            "attack_type": self.attack_type,
        }


DLP_CLASSIFICATION_PATTERNS = {
    "student_self": (
        "student records",
        "student private records",
        "student portal records",
        "all student records",
        "portal records",
        "scholarship review notes",
        "scholarship notes",
        "private student",
    ),
    "exam_confidential": (
        "exam marks",
        "exam records",
        "all exam records",
        "grade sheet",
        "result ledger",
        "rechecking internal",
    ),
    "finance_confidential": (
        "fee status",
        "fee ledger",
        "budget",
        "budget summary",
        "finance record",
        "payment ledger",
    ),
    "contract_confidential": (
        "contract",
        "vendor contract",
        "procurement contract",
        "supplier agreement",
    ),
    "staff_only": (
        "staff private notes",
        "staff internal notes",
        "staff directory private",
    ),
    "admin_only": (
        "internal admin notes",
        "portal rules",
        "admin notes",
        "admin portal data",
        "internal data",
        "hidden instructions",
        "hidden system instructions",
        "system prompt",
        "developer prompt",
        "system/developer prompt",
        "unrestricted database access",
    ),
    "restricted_secret": (
        "token",
        "admin token",
        "secret",
        "api key",
        "keys",
        "credential",
        "credentials",
        "password",
        ".env",
        "canary",
        "canary_admin_token_demo_only",
        "canary_internal_budget_marker",
        "canary_student_record_marker",
    ),
}

POLICY_BYPASS_PATTERNS = (
    "act as admin portal",
    "ignore student role",
    "override portal permissions",
    "use admin privileges",
    "retrieve internal data",
    "bypass access control",
    "show all records",
    "unrestricted access",
    "developer/admin mode",
    "override role",
    "ignore role",
    "use another portal role",
    "pretend i am finance admin",
    "pretend i am exam controller",
)


def detect_dlp(prompt: str, user_role: str | None = None) -> DLPAssessment:
    role = normalize_role(user_role)
    lowered = " ".join(prompt.lower().split())
    reasons: list[str] = []
    requested: list[str] = []
    public_credential_help = any(
        phrase in lowered
        for phrase in (
            "password reset",
            "reset my demo portal password",
            "forgot my demo portal password",
            "login issue",
        )
    )

    bypass_matches = [pattern for pattern in POLICY_BYPASS_PATTERNS if pattern in lowered]
    if bypass_matches:
        reasons.append(f"Matched policy-bypass phrase: '{bypass_matches[0]}'")

    for classification, patterns in DLP_CLASSIFICATION_PATTERNS.items():
        matched = next((pattern for pattern in patterns if pattern in lowered), None)
        if classification == "restricted_secret" and matched == "password" and public_credential_help:
            matched = None
        if matched:
            requested.append(classification)
            reasons.append(f"Matched DLP category {classification}: '{matched}'")

    requested = list(dict.fromkeys(requested))
    denied = [
        classification
        for classification in requested
        if not access_decision(role, classification).allowed
    ]

    if bypass_matches:
        return DLPAssessment(
            action="block",
            label="malicious",
            risk_score=0.97,
            reasons=reasons,
            requested_classifications=requested,
            attack_type="role_bypass",
        )

    if "restricted_secret" in requested:
        return DLPAssessment(
            action="block",
            label="malicious",
            risk_score=0.99,
            reasons=reasons,
            requested_classifications=requested,
            attack_type="secret_extraction",
        )

    if denied:
        return DLPAssessment(
            action="block",
            label="malicious",
            risk_score=0.94,
            reasons=reasons + [
                f"{role} is not authorized for {', '.join(denied)}."
            ],
            requested_classifications=requested,
            attack_type="unauthorized_data_request",
        )

    if requested:
        return DLPAssessment(
            action="log",
            label="suspicious",
            risk_score=0.42,
            reasons=reasons + [f"{role} is authorized for requested classifications."],
            requested_classifications=requested,
            attack_type="authorized_sensitive_request",
        )

    return DLPAssessment(
        action="allow",
        label="safe",
        risk_score=0.04,
        reasons=["No DLP-restricted data request detected"],
        requested_classifications=[],
        attack_type=None,
    )
