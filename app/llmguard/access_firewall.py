from __future__ import annotations

from typing import Any

from app.access_control import access_decision as role_access_decision
from app.llmguard.risk_engine import StageSignal, signal
from app.models import DataClassification, PortalScope, User, UserRole
from app.rbac import can_access_classification, can_access_portal


def _value(value: Any) -> str:
    return getattr(value, "value", str(value)) if value is not None else ""


def inspect_access(
    *,
    user: User | None = None,
    user_role: str | None = None,
    requested_portal_scope: str | PortalScope | None = None,
    requested_classification: str | DataClassification | None = None,
    owner_user_id: int | None = None,
) -> StageSignal:
    role = _value(user.role) if user is not None else (user_role or "public_user")
    reasons: list[str] = []
    score = 0.03

    if user is not None and requested_portal_scope and not can_access_portal(user, requested_portal_scope):
        reasons.append(f"{role} cannot cross into {_value(requested_portal_scope)} portal scope.")
        score = max(score, 0.93)

    if user is not None and requested_classification and not can_access_classification(user, requested_classification):
        reasons.append(f"{role} cannot access {_value(requested_classification)} classification.")
        score = max(score, 0.95)

    if user is None and requested_classification:
        role_decision = role_access_decision(role, _value(requested_classification))
        if not role_decision.allowed:
            reasons.append(role_decision.reason)
            score = max(score, 0.95)

    classification = _value(requested_classification)
    if user is not None and owner_user_id is not None:
        if user.role == UserRole.student and classification == DataClassification.student_private.value and owner_user_id != user.id:
            reasons.append("Student attempted to access another synthetic student record.")
            score = max(score, 0.94)
        if user.role == UserRole.employee and classification == DataClassification.employee_private.value and owner_user_id != user.id:
            reasons.append("Employee attempted to access another synthetic employee record.")
            score = max(score, 0.92)

    if classification == DataClassification.restricted_secret.value:
        reasons.append("restricted_secret is never sent to an LLM.")
        score = max(score, 0.99)

    if reasons:
        return signal(
            "access_firewall",
            label="malicious",
            action="block",
            score=score,
            reasons=reasons,
            threat_source="access_control",
            metadata={
                "user_role": role,
                "requested_portal_scope": _value(requested_portal_scope),
                "requested_classification": classification,
                "owner_user_id": owner_user_id,
            },
        )

    return signal(
        "access_firewall",
        label="safe",
        action="allow",
        score=score,
        reasons=["RBAC and portal-boundary checks passed."],
        metadata={
            "user_role": role,
            "requested_portal_scope": _value(requested_portal_scope),
            "requested_classification": classification,
        },
    )


def inspect_retrieval_metadata(
    chunks: list[dict[str, Any]],
    *,
    user: User | None = None,
    user_role: str | None = None,
) -> StageSignal:
    denied: list[dict[str, Any]] = []
    for chunk in chunks:
        check = inspect_access(
            user=user,
            user_role=user_role,
            requested_portal_scope=chunk.get("portal_scope"),
            requested_classification=chunk.get("classification"),
            owner_user_id=chunk.get("owner_user_id"),
        )
        if check.action == "block":
            denied.append(
                {
                    "chunk_id": chunk.get("chunk_id"),
                    "document_id": chunk.get("document_id"),
                    "classification": chunk.get("classification"),
                    "portal_scope": chunk.get("portal_scope"),
                    "reasons": check.reasons,
                }
            )

    if denied:
        return signal(
            "retrieval_metadata_inspection",
            label="malicious",
            action="block",
            score=0.96,
            reasons=["Retrieved candidates included chunks outside the user's allowed portal scope or classification."],
            threat_source="retrieval_metadata",
            metadata={"unauthorized_chunks": denied},
        )

    return signal(
        "retrieval_metadata_inspection",
        label="safe",
        action="allow",
        score=0.04,
        reasons=["All retrieved chunk metadata passed access filtering."],
        metadata={"checked_chunks": len(chunks)},
    )
