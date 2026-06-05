from __future__ import annotations

from app.access_control import (
    CLASSIFICATIONS,
    ROLE_CLASSIFICATION_ACCESS,
    ROLES,
    AccessDecision,
    access_decision,
    can_access_classification,
    category_for_repository_path,
    classification_for_repository_path,
    normalize_classification,
    normalize_role,
    roles_for_classification,
)

ACCESS_MATRIX = ROLE_CLASSIFICATION_ACCESS


def decide_access(user_role: str | None, classification: str | None) -> AccessDecision:
    return access_decision(user_role, classification)
