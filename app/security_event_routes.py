from __future__ import annotations

from dataclasses import asdict
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel

from app.auth import get_current_user
from app.models import User, UserRole
from app.security_events import (
    InvalidIncidentTransitionError,
    get_incident,
    get_request_trace,
    list_incidents,
    list_security_events,
    update_incident_status,
)


router = APIRouter(prefix="/admin/api", tags=["soc-security"])


class IncidentStatusUpdate(BaseModel):
    status: Literal["OPEN", "ACKNOWLEDGED", "RESOLVED"]


def _require_security_reader(user: User) -> None:
    if user.role != UserRole.super_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Security operations access required.",
        )


def _require_incident_operator(user: User) -> None:
    if user.role != UserRole.super_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Super admin incident authority required.",
        )


@router.get("/security-events")
def security_events_api(
    application_id: str | None = None,
    channel: str | None = None,
    stage: str | None = None,
    classification: str | None = None,
    severity: str | None = None,
    action: str | None = None,
    event_type: str | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 100,
    user: User = Depends(get_current_user),
) -> dict[str, object]:
    _require_security_reader(user)
    events = list_security_events(
        application_id=application_id,
        channel=channel,
        stage=stage,
        classification=classification,
        severity=severity,
        action=action,
        event_type=event_type,
        limit=limit,
    )
    return {"events": [asdict(event) for event in events]}


@router.get("/security-events/trace/{request_id}")
def security_request_trace_api(
    request_id: str,
    application_id: str,
    user: User = Depends(get_current_user),
) -> dict[str, object]:
    _require_security_reader(user)
    events = get_request_trace(application_id, request_id)
    return {
        "application_id": application_id,
        "request_id": request_id,
        "events": [asdict(event) for event in events],
    }


@router.get("/incidents")
def incidents_api(
    application_id: str | None = None,
    incident_status: Literal["OPEN", "ACKNOWLEDGED", "RESOLVED"] | None = None,
    severity: str | None = None,
    category: str | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 100,
    user: User = Depends(get_current_user),
) -> dict[str, object]:
    _require_security_reader(user)
    incidents = list_incidents(
        application_id=application_id,
        status=incident_status,
        severity=severity,
        category=category,
        limit=limit,
    )
    return {"incidents": [asdict(incident) for incident in incidents]}


@router.get("/incidents/{incident_id}")
def incident_detail_api(
    incident_id: str,
    user: User = Depends(get_current_user),
) -> dict[str, object]:
    _require_security_reader(user)
    detail = get_incident(incident_id)
    if detail is None:
        raise HTTPException(status_code=404, detail="Incident not found.")
    return {
        "incident": asdict(detail.incident),
        "events": [asdict(event) for event in detail.events],
        "status_audit": [asdict(entry) for entry in detail.status_audit],
    }


@router.patch("/incidents/{incident_id}/status")
def update_incident_status_api(
    incident_id: str,
    payload: IncidentStatusUpdate,
    user: User = Depends(get_current_user),
) -> dict[str, object]:
    _require_incident_operator(user)
    try:
        incident = update_incident_status(
            incident_id,
            new_status=payload.status,
            actor=user.username,
        )
    except InvalidIncidentTransitionError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found.")
    return {"incident": asdict(incident)}
