from __future__ import annotations

from datetime import datetime
from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from app.db import fetch_dashboard_metrics, fetch_recent_logs

BASE_DIR = Path(__file__).resolve().parent.parent
TEMPLATES_DIR = BASE_DIR / "templates"

router = APIRouter()
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
ASSET_VERSION = "3"


def _risk_band(risk_score: float) -> str:
    if risk_score >= 0.92:
        return "critical"
    if risk_score >= 0.72:
        return "high"
    if risk_score >= 0.38:
        return "elevated"
    return "low"


@router.get("/app", response_class=HTMLResponse)
def user_console(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(
        request=request,
        name="app.html",
        context={
            "page_title": "LLMGuard Console",
            "asset_version": ASSET_VERSION,
        },
    )


@router.get("/admin/dashboard", response_class=HTMLResponse)
def admin_dashboard(request: Request) -> HTMLResponse:
    metrics = fetch_dashboard_metrics(limit=50)
    recent_logs = metrics["recent_logs"]

    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "page_title": "LLMGuard Dashboard",
            "asset_version": ASSET_VERSION,
            "metrics": metrics,
            "recent_logs": recent_logs,
            "risk_points": metrics["risk_history"],
            "latest_event": recent_logs[0] if recent_logs else None,
            "risk_band": _risk_band(float(recent_logs[0]["risk_score"])) if recent_logs else "low",
            "session_started_at": datetime.now().isoformat(timespec="seconds"),
        },
    )


@router.get("/admin/dashboard/data", response_class=JSONResponse)
def dashboard_data() -> JSONResponse:
    return JSONResponse(fetch_dashboard_metrics(limit=50))


@router.get("/admin/logs/recent", response_class=JSONResponse)
def recent_logs(limit: int = 25) -> JSONResponse:
    return JSONResponse({"logs": fetch_recent_logs(limit=limit)})
