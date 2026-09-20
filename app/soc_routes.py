from __future__ import annotations

from dataclasses import asdict
from typing import Literal, Sequence

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse

from app.application_registry import ApplicationRecord, list_applications
from app.auth import get_current_user
from app.config import get_settings
from app.models import User, UserRole
from app.portals.common import ASSET_VERSION, templates
from app.security_events import (
    InvalidIncidentTransitionError,
    SecurityEventRecord,
    find_request_traces,
    get_incident,
    get_request_trace,
    get_security_overview,
    list_incidents,
    list_quarantine_events,
    list_security_events,
    session_policy_codes_for,
    update_incident_status,
)


router = APIRouter(prefix="/admin", tags=["soc-console"])


def _require_soc_reader(user: User) -> None:
    if user.role != UserRole.super_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Security operations access required.",
        )


def _soc_context(user: User, active_soc_page: str) -> dict[str, object]:
    settings = get_settings()
    return {
        "asset_version": ASSET_VERSION,
        "user": user,
        "portal_scope": "admin",
        "firewall_active": settings.firewall_active,
        "redteam_enabled": settings.redteam_mode or settings.app_env == "local_redteam",
        "active_soc_page": active_soc_page,
    }


def _applications() -> tuple[list[ApplicationRecord], dict[str, str]]:
    applications = list_applications()
    return applications, {
        application.application_id: application.name for application in applications
    }


def _event_views(
    events: Sequence[SecurityEventRecord],
    application_names: dict[str, str],
) -> list[dict[str, object]]:
    policy_codes = session_policy_codes_for(tuple(events))
    rows: list[dict[str, object]] = []
    for event in events:
        row = asdict(event)
        row["application_name"] = application_names.get(
            event.application_id,
            event.application_id,
        )
        row["policy_code"] = policy_codes.get(event.event_id)
        row["operational_failure"] = (
            event.event_type.endswith("_FAILURE") or event.classification == "error"
        )
        rows.append(row)
    return rows


def _render(
    request: Request,
    template_name: str,
    context: dict[str, object],
    *,
    status_code: int = status.HTTP_200_OK,
) -> HTMLResponse:
    return templates.TemplateResponse(
        request=request,
        name=template_name,
        context=context,
        status_code=status_code,
        headers={"Cache-Control": "no-store"},
    )


@router.get("/security-dashboard", response_class=HTMLResponse)
def security_overview_page(
    request: Request,
    application_id: str | None = Query(default=None, max_length=160),
    user: User = Depends(get_current_user),
) -> HTMLResponse:
    _require_soc_reader(user)
    applications, application_names = _applications()
    overview = get_security_overview(application_id=application_id)
    application_breakdown = [
        {
            "application_id": app_id,
            "application_name": application_names.get(app_id, app_id),
            "event_count": count,
        }
        for app_id, count in overview.application_breakdown
    ]
    channel_breakdown = [
        {
            "application_id": app_id,
            "application_name": application_names.get(app_id, app_id),
            "channel": channel,
            "event_count": count,
        }
        for app_id, channel, count in overview.channel_breakdown
    ]
    return _render(
        request,
        "soc_overview.html",
        {
            **_soc_context(user, "overview"),
            "page_title": "Security Overview",
            "overview": overview,
            "recent_events": _event_views(
                overview.recent_events,
                application_names,
            ),
            "applications": applications,
            "selected_application_id": application_id or "",
            "application_breakdown": application_breakdown,
            "channel_breakdown": channel_breakdown,
        },
    )


@router.get("/soc", response_class=RedirectResponse)
def soc_root(user: User = Depends(get_current_user)) -> RedirectResponse:
    _require_soc_reader(user)
    return RedirectResponse(
        url="/admin/security-dashboard",
        status_code=status.HTTP_307_TEMPORARY_REDIRECT,
    )


@router.get("/soc/events", response_class=HTMLResponse)
def live_events_page(
    request: Request,
    application_id: str | None = Query(default=None, max_length=160),
    channel: str | None = Query(default=None, max_length=64),
    stage: str | None = Query(default=None, max_length=64),
    classification: str | None = Query(default=None, max_length=40),
    severity: str | None = Query(default=None, max_length=20),
    action: str | None = Query(default=None, max_length=80),
    event_type: str | None = Query(default=None, max_length=100),
    user: User = Depends(get_current_user),
) -> HTMLResponse:
    _require_soc_reader(user)
    applications, application_names = _applications()
    filters = {
        "application_id": application_id or "",
        "channel": channel or "",
        "stage": stage or "",
        "classification": classification or "",
        "severity": severity or "",
        "action": action or "",
        "event_type": event_type or "",
    }
    events = list_security_events(
        application_id=application_id,
        channel=channel,
        stage=stage,
        classification=classification,
        severity=severity,
        action=action,
        event_type=event_type,
        limit=200,
    )
    return _render(
        request,
        "soc_events.html",
        {
            **_soc_context(user, "events"),
            "page_title": "Live Security Events",
            "applications": applications,
            "events": _event_views(events, application_names),
            "filters": filters,
        },
    )


@router.get("/soc/incidents", response_class=HTMLResponse)
def incidents_page(
    request: Request,
    application_id: str | None = Query(default=None, max_length=160),
    incident_status: Literal["OPEN", "ACKNOWLEDGED", "RESOLVED"] | None = None,
    severity: str | None = Query(default=None, max_length=20),
    category: str | None = Query(default=None, max_length=80),
    user: User = Depends(get_current_user),
) -> HTMLResponse:
    _require_soc_reader(user)
    applications, application_names = _applications()
    incidents = list_incidents(
        application_id=application_id,
        status=incident_status,
        severity=severity,
        category=category,
        limit=200,
    )
    rows = []
    for incident in incidents:
        row = asdict(incident)
        row["application_name"] = application_names.get(
            incident.application_id,
            incident.application_id,
        )
        rows.append(row)
    return _render(
        request,
        "soc_incidents.html",
        {
            **_soc_context(user, "incidents"),
            "page_title": "Security Incidents",
            "applications": applications,
            "incidents": rows,
            "filters": {
                "application_id": application_id or "",
                "incident_status": incident_status or "",
                "severity": severity or "",
                "category": category or "",
            },
        },
    )


@router.get("/soc/incidents/{incident_id}", response_class=HTMLResponse)
def incident_detail_page(
    incident_id: str,
    request: Request,
    updated: str | None = Query(default=None, max_length=20),
    user: User = Depends(get_current_user),
) -> HTMLResponse:
    _require_soc_reader(user)
    detail = get_incident(incident_id)
    if detail is None:
        raise HTTPException(status_code=404, detail="Incident not found.")
    _, application_names = _applications()
    incident = asdict(detail.incident)
    incident["application_name"] = application_names.get(
        detail.incident.application_id,
        detail.incident.application_id,
    )
    return _render(
        request,
        "soc_incident_detail.html",
        {
            **_soc_context(user, "incidents"),
            "page_title": f"Incident {detail.incident.incident_id}",
            "incident": incident,
            "events": _event_views(detail.events, application_names),
            "status_audit": detail.status_audit,
            "updated_status": updated or "",
        },
    )


def _change_incident_status(
    incident_id: str,
    new_status: Literal["ACKNOWLEDGED", "RESOLVED"],
    user: User,
) -> RedirectResponse:
    _require_soc_reader(user)
    try:
        incident = update_incident_status(
            incident_id,
            new_status=new_status,
            actor=user.username,
        )
    except InvalidIncidentTransitionError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found.")
    return RedirectResponse(
        url=f"/admin/soc/incidents/{incident_id}?updated={new_status}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.post("/soc/incidents/{incident_id}/acknowledge")
def acknowledge_incident(
    incident_id: str,
    user: User = Depends(get_current_user),
) -> RedirectResponse:
    return _change_incident_status(incident_id, "ACKNOWLEDGED", user)


@router.post("/soc/incidents/{incident_id}/resolve")
def resolve_incident(
    incident_id: str,
    user: User = Depends(get_current_user),
) -> RedirectResponse:
    return _change_incident_status(incident_id, "RESOLVED", user)


@router.get("/soc/trace", response_class=HTMLResponse)
def request_trace_page(
    request: Request,
    request_id: str | None = Query(default=None, max_length=200),
    application_id: str | None = Query(default=None, max_length=160),
    user: User = Depends(get_current_user),
) -> HTMLResponse:
    _require_soc_reader(user)
    applications, application_names = _applications()
    normalized_request_id = request_id.strip() if request_id else ""
    trace_events: list[SecurityEventRecord] = []
    matching_applications: list[str] = []
    selected_application_id = application_id or ""
    if normalized_request_id and application_id:
        trace_events = get_request_trace(application_id, normalized_request_id)
    elif normalized_request_id:
        traces = find_request_traces(normalized_request_id)
        matching_applications = [trace.application_id for trace in traces]
        if len(traces) == 1:
            selected_application_id = traces[0].application_id
            trace_events = list(traces[0].events)

    recorded_stages = {event.stage for event in trace_events}
    stage_summary = [
        {
            "stage": stage_name,
            "recorded": stage_name in recorded_stages,
            "event_count": sum(event.stage == stage_name for event in trace_events),
        }
        for stage_name in ("input", "context", "output")
    ]
    return _render(
        request,
        "soc_trace.html",
        {
            **_soc_context(user, "trace"),
            "page_title": "Request Trace",
            "applications": applications,
            "application_names": application_names,
            "request_id": normalized_request_id,
            "selected_application_id": selected_application_id,
            "matching_applications": matching_applications,
            "events": _event_views(trace_events, application_names),
            "stage_summary": stage_summary,
            "other_stages": sorted(recorded_stages - {"input", "context", "output"}),
            "trace_searched": bool(normalized_request_id),
        },
    )


@router.get("/soc/quarantine", response_class=HTMLResponse)
def quarantine_page(
    request: Request,
    application_id: str | None = Query(default=None, max_length=160),
    user: User = Depends(get_current_user),
) -> HTMLResponse:
    _require_soc_reader(user)
    applications, application_names = _applications()
    quarantine_records = list_quarantine_events(
        application_id=application_id,
        limit=200,
    )
    rows = []
    for record in quarantine_records:
        rows.append(
            {
                "event_id": record.event.event_id,
                "application_id": record.event.application_id,
                "application_name": application_names.get(
                    record.event.application_id,
                    record.event.application_id,
                ),
                "request_id": record.event.request_id,
                "source_id": record.event.source_id,
                "chunk_id": record.event.chunk_id,
                "created_at": record.event.created_at,
                "incident_id": record.incident_id,
            }
        )
    return _render(
        request,
        "soc_quarantine.html",
        {
            **_soc_context(user, "quarantine"),
            "page_title": "Quarantine Metadata",
            "applications": applications,
            "selected_application_id": application_id or "",
            "quarantine_records": rows,
        },
    )
