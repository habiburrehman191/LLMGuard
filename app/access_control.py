from __future__ import annotations

from dataclasses import dataclass

ROLES = {
    "public_user",
    "student",
    "teacher",
    "staff",
    "admission_officer",
    "exam_controller",
    "finance_admin",
    "super_admin",
}

CLASSIFICATIONS = {
    "public",
    "student_self",
    "staff_only",
    "teacher_only",
    "admission_internal",
    "exam_confidential",
    "finance_confidential",
    "contract_confidential",
    "admin_only",
    "restricted_secret",
}

ROLE_CLASSIFICATION_ACCESS = {
    "public_user": {"public"},
    "student": {"public", "student_self"},
    "teacher": {"public", "teacher_only", "staff_only"},
    "staff": {"public", "staff_only"},
    "admission_officer": {"public", "staff_only", "admission_internal"},
    "exam_controller": {"public", "staff_only", "teacher_only", "exam_confidential"},
    "finance_admin": {"public", "staff_only", "finance_confidential", "contract_confidential"},
    "super_admin": {
        "public",
        "student_self",
        "staff_only",
        "teacher_only",
        "admission_internal",
        "exam_confidential",
        "finance_confidential",
        "contract_confidential",
        "admin_only",
    },
}


@dataclass(frozen=True)
class AccessDecision:
    allowed: bool
    user_role: str
    classification: str
    reason: str

    def as_dict(self) -> dict[str, object]:
        return {
            "allowed": self.allowed,
            "user_role": self.user_role,
            "classification": self.classification,
            "reason": self.reason,
        }


def normalize_role(user_role: str | None) -> str:
    role = (user_role or "public_user").strip().lower()
    return role if role in ROLES else "public_user"


def normalize_classification(classification: str | None) -> str:
    value = (classification or "public").strip().lower()
    return value if value in CLASSIFICATIONS else "public"


def roles_for_classification(classification: str | None) -> list[str]:
    normalized = normalize_classification(classification)
    return sorted(
        role
        for role, classifications in ROLE_CLASSIFICATION_ACCESS.items()
        if normalized in classifications
    )


def can_access_classification(user_role: str | None, classification: str | None) -> bool:
    role = normalize_role(user_role)
    normalized = normalize_classification(classification)
    if normalized == "restricted_secret":
        return False
    return normalized in ROLE_CLASSIFICATION_ACCESS[role]


def access_decision(user_role: str | None, classification: str | None) -> AccessDecision:
    role = normalize_role(user_role)
    normalized = normalize_classification(classification)
    allowed = can_access_classification(role, normalized)
    if allowed:
        reason = f"{role} is allowed to access {normalized} documents."
    elif normalized == "restricted_secret":
        reason = "restricted_secret documents are blocked for every role in this demo."
    else:
        reason = f"{role} is not allowed to access {normalized} documents."
    return AccessDecision(
        allowed=allowed,
        user_role=role,
        classification=normalized,
        reason=reason,
    )


def classification_for_repository_path(source_path: str, filename: str = "") -> str:
    normalized = source_path.replace("\\", "/").lower()
    name = filename.lower()
    if "/university_repository/public/" in normalized:
        return "public"
    if "/university_repository/student_portal/" in normalized:
        return "student_self"
    if "/university_repository/staff/" in normalized:
        if "teacher" in name or "office_hours" in name:
            return "teacher_only"
        return "staff_only"
    if "/university_repository/exam_cell/" in normalized:
        return "exam_confidential"
    if "/university_repository/finance/" in normalized:
        return "finance_confidential"
    if "/university_repository/contracts/" in normalized:
        return "contract_confidential"
    if "/university_repository/admin/" in normalized:
        return "admin_only"
    if "/university_repository/restricted/" in normalized:
        return "restricted_secret"
    if "/uoh_demo/" in normalized:
        if "synthetic_student" in name:
            return "student_self"
        if "synthetic_internal" in name:
            return "admin_only"
        return "public"
    if "/education_demo/" in normalized:
        if "synthetic_student" in name:
            return "student_self"
        if "synthetic_internal" in name:
            return "admin_only"
        return "public"
    return "public"


def category_for_repository_path(source_path: str) -> str:
    normalized = source_path.replace("\\", "/").lower()
    marker = "/university_repository/"
    if marker in normalized:
        tail = normalized.split(marker, 1)[1]
        return tail.split("/", 1)[0]
    if "/uoh_demo/" in normalized:
        return "uoh_demo"
    if "/education_demo/" in normalized:
        return "education_demo"
    return "general"
