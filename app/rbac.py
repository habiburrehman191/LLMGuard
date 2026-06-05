from __future__ import annotations

from fastapi import HTTPException, status

from app.models import DataClassification, Document, PortalScope, User, UserRole


def _role_value(user: User) -> str:
    return user.role.value if isinstance(user.role, UserRole) else str(user.role)


def _scope_value(scope: PortalScope | str) -> str:
    return scope.value if isinstance(scope, PortalScope) else str(scope)


def _classification_value(classification: DataClassification | str) -> str:
    return classification.value if isinstance(classification, DataClassification) else str(classification)


def can_access_portal(user: User, portal_scope: PortalScope | str) -> bool:
    role = _role_value(user)
    scope = _scope_value(portal_scope)
    if role == UserRole.super_admin.value:
        return scope in {PortalScope.student.value, PortalScope.employee.value, PortalScope.admin.value}
    if role == UserRole.student.value:
        return scope == PortalScope.student.value
    if role == UserRole.employee.value:
        return scope == PortalScope.employee.value
    return False


def can_access_classification(user: User, classification: DataClassification | str) -> bool:
    role = _role_value(user)
    value = _classification_value(classification)
    if value == DataClassification.restricted_secret.value:
        return False
    if value == DataClassification.public.value:
        return True
    if role == UserRole.super_admin.value:
        return True
    if role == UserRole.student.value:
        return value == DataClassification.student_private.value
    if role == UserRole.employee.value:
        return value == DataClassification.employee_private.value
    return False


def can_access_document(user: User, document: Document) -> bool:
    if document.classification == DataClassification.restricted_secret:
        return False
    if document.portal_scope is not None and not can_access_portal(user, document.portal_scope):
        return False
    if not can_access_classification(user, document.classification):
        return False
    return True


def explain_denial(
    user: User,
    requested_scope: PortalScope | str | None,
    classification: DataClassification | str | None,
) -> str:
    role = _role_value(user)
    if classification and _classification_value(classification) == DataClassification.restricted_secret.value:
        return "restricted_secret is never accessible or sent to the LLM in protected mode."
    if requested_scope and not can_access_portal(user, requested_scope):
        return f"{role} cannot access the {_scope_value(requested_scope)} portal boundary."
    if classification and not can_access_classification(user, classification):
        return f"{role} cannot access {_classification_value(classification)} data."
    return f"{role} is not authorized for the requested resource."


def enforce_portal_boundary(user: User, requested_scope: PortalScope | str) -> None:
    if can_access_portal(user, requested_scope):
        return
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail=explain_denial(user, requested_scope, None),
    )
