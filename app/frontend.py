from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from app.auth import decode_access_token, get_current_user
from app.db import fetch_dashboard_metrics, fetch_recent_logs
from app.models import User, UserRole

BASE_DIR = Path(__file__).resolve().parent.parent
TEMPLATES_DIR = BASE_DIR / "templates"

router = APIRouter()
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
ASSET_VERSION = "27"


@router.get("/", response_class=RedirectResponse)
def landing(request: Request) -> RedirectResponse:
    token = request.cookies.get("llmguard_token")
    if token:
        try:
            decode_access_token(token)
        except (HTTPException, ValueError, TypeError):
            pass
        else:
            return RedirectResponse(url="/admin/dashboard", status_code=307)
    return RedirectResponse(url="/login", status_code=307)


@router.get("/favicon.ico", include_in_schema=False)
def favicon() -> FileResponse:
    return FileResponse(
        BASE_DIR / "static" / "branding" / "llmguard-mark-32.png",
        media_type="image/png",
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
