from __future__ import annotations

from datetime import datetime
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select

from app.config import get_settings
from app.auth import get_current_user
from app.database import SessionLocal
from app.db import fetch_dashboard_metrics, fetch_recent_logs
from app.models import FirewallEvent, SecurityAction, User, UserRole

BASE_DIR = Path(__file__).resolve().parent.parent
TEMPLATES_DIR = BASE_DIR / "templates"

router = APIRouter()
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
ASSET_VERSION = "15"


def _risk_band(risk_score: float) -> str:
    if risk_score >= 0.92:
        return "critical"
    if risk_score >= 0.72:
        return "high"
    if risk_score >= 0.38:
        return "elevated"
    return "low"


@router.get("/", response_class=HTMLResponse)
def landing(request: Request) -> HTMLResponse:
    settings = get_settings()
    return templates.TemplateResponse(
        request=request,
        name="landing.html",
        context={
            "page_title": "LLMGuard Zero-Trust AI Firewall",
            "asset_version": ASSET_VERSION,
            "firewall_active": settings.firewall_active,
            "redteam_enabled": settings.redteam_mode or settings.app_env == "local_redteam",
        },
    )


@router.get("/favicon.ico", include_in_schema=False)
def favicon() -> FileResponse:
    return FileResponse(
        BASE_DIR / "static" / "favicon.svg",
        media_type="image/svg+xml",
    )


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={
            "page_title": "Sign in to LLMGuard",
            "asset_version": ASSET_VERSION,
        },
    )


@router.get("/app", response_class=RedirectResponse)
def user_console() -> RedirectResponse:
    return RedirectResponse(url="/login", status_code=307)


def _require_super_admin(user: User) -> None:
    if user.role != UserRole.super_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Super admin access required.",
        )


@router.get("/admin/security-dashboard", response_class=HTMLResponse)
def admin_dashboard(
    request: Request,
    user: User = Depends(get_current_user),
) -> HTMLResponse:
    _require_super_admin(user)
    metrics = fetch_dashboard_metrics(limit=50)
    recent_logs = metrics["recent_logs"]
    with SessionLocal() as db:
        stage_counts = {
            "dlp_blocks": db.scalar(
                select(func.count()).select_from(FirewallEvent).where(
                    FirewallEvent.detector.like("%dlp%"),
                    FirewallEvent.action == SecurityAction.block,
                )
            ) or 0,
            "critical_events": db.scalar(
                select(func.count()).select_from(FirewallEvent).where(FirewallEvent.score >= 0.9)
            ) or 0,
        }

    return templates.TemplateResponse(
        request=request,
        name="security_dashboard.html",
        context={
            "page_title": "Security Dashboard",
            "asset_version": ASSET_VERSION,
            "user": user,
            "portal_scope": "admin",
            "firewall_active": get_settings().firewall_active,
            "redteam_enabled": get_settings().redteam_mode or get_settings().app_env == "local_redteam",
            "metrics": metrics,
            "recent_logs": recent_logs,
            "risk_points": metrics["risk_history"],
            "latest_event": recent_logs[0] if recent_logs else None,
            "risk_band": _risk_band(float(recent_logs[0]["risk_score"])) if recent_logs else "low",
            "stage_counts": stage_counts,
            "session_started_at": datetime.now().isoformat(timespec="seconds"),
        },
    )


@router.get("/admin/dashboard/data", response_class=JSONResponse)
def dashboard_data(user: User = Depends(get_current_user)) -> JSONResponse:
    _require_super_admin(user)
    return JSONResponse(
        fetch_dashboard_metrics(limit=50),
        headers={
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
            "Pragma": "no-cache",
            "Expires": "0",
        },
    )


@router.get("/admin/logs/recent", response_class=JSONResponse)
def recent_logs(
    limit: int = 25,
    user: User = Depends(get_current_user),
) -> JSONResponse:
    _require_super_admin(user)
    return JSONResponse({"logs": fetch_recent_logs(limit=limit)})
