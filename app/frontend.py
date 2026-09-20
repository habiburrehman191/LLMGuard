from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from app.config import get_settings
from app.auth import get_current_user
from app.db import fetch_dashboard_metrics, fetch_recent_logs
from app.models import User, UserRole

BASE_DIR = Path(__file__).resolve().parent.parent
TEMPLATES_DIR = BASE_DIR / "templates"

router = APIRouter()
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
ASSET_VERSION = "25"


def _safe_spline_scene_url(raw_url: str) -> str:
    if not raw_url:
        return ""
    parsed = urlparse(raw_url)
    hostname = (parsed.hostname or "").lower()
    if parsed.scheme != "https" or not (
        hostname == "spline.design" or hostname.endswith(".spline.design")
    ):
        return ""
    return raw_url


@router.get("/", response_class=HTMLResponse)
def landing(request: Request) -> HTMLResponse:
    settings = get_settings()
    return templates.TemplateResponse(
        request=request,
        name="landing.html",
        context={
            "page_title": "LLMGuard | AI Firewall Platform",
            "asset_version": ASSET_VERSION,
            "firewall_active": settings.firewall_active,
            "redteam_enabled": settings.redteam_mode or settings.app_env == "local_redteam",
            "spline_scene_url": _safe_spline_scene_url(settings.spline_scene_url),
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
