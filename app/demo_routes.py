from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from app.db import insert_demo_event
from app.demo_university import (
    baseline_unprotected_answer,
    baseline_uoh_unprotected_answer,
    classify_demo_scenario,
    classify_uoh_demo_scenario,
)

from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

router = APIRouter()
ASSET_VERSION = "4"


class DemoAskRequest(BaseModel):
    prompt: str
    scenario: str | None = None
    demo_context: str | None = None


class DemoAuditRequest(BaseModel):
    prompt: str
    scenario: str | None = None
    mode: str
    action: str
    label: str
    blocked: bool
    risk_score: float
    threat_source: str | None = None
    tool_call: dict[str, object] | None = None
    qwen_called: bool | None = None
    reason: str | None = None


@router.get("/demo/university", response_class=HTMLResponse)
def university_demo(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(
        request=request,
        name="university_demo.html",
        context={
            "page_title": "Northbridge University Digital Twin",
            "asset_version": ASSET_VERSION,
        },
    )


@router.get("/demo/uoh", response_class=HTMLResponse)
def uoh_demo(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(
        request=request,
        name="uoh_demo.html",
        context={
            "page_title": "LLMGuard University Portal Security Demo",
            "asset_version": ASSET_VERSION,
        },
    )


@router.post("/demo/ask-unprotected", response_class=JSONResponse)
def ask_unprotected(request: DemoAskRequest) -> JSONResponse:
    is_uoh_demo = request.demo_context == "uoh" or (request.scenario or "").startswith("uoh_")
    payload = (
        baseline_uoh_unprotected_answer(request.prompt)
        if is_uoh_demo
        else baseline_unprotected_answer(request.prompt)
    )
    scenario = request.scenario or str(
        payload.get("scenario") or (
            classify_uoh_demo_scenario(request.prompt)
            if is_uoh_demo
            else classify_demo_scenario(request.prompt)
        )
    )
    tool_call = payload.get("tool_call") if isinstance(payload.get("tool_call"), dict) else {}
    insert_demo_event(
        scenario=scenario,
        mode="unprotected",
        prompt=request.prompt,
        action=str(payload["action"]),
        label=str(payload["label"]),
        blocked=bool(payload["blocked"]),
        risk_score=float(payload["risk_score"]),
        threat_source=str(payload.get("threat_source") or "none"),
        tool_name=str(tool_call.get("name")) if tool_call else None,
        tool_allowed=bool(tool_call.get("allowed")) if tool_call else None,
        qwen_called=bool(payload.get("qwen_called")),
        reason=str(payload.get("reason") or ""),
    )
    return JSONResponse(payload)


@router.post("/demo/audit", response_class=JSONResponse)
def audit_demo_event(request: DemoAuditRequest) -> JSONResponse:
    tool_call = request.tool_call or {}
    insert_demo_event(
        scenario=request.scenario or classify_demo_scenario(request.prompt),
        mode=request.mode,
        prompt=request.prompt,
        action=request.action,
        label=request.label,
        blocked=request.blocked,
        risk_score=request.risk_score,
        threat_source=request.threat_source,
        tool_name=str(tool_call.get("name")) if tool_call else None,
        tool_allowed=bool(tool_call.get("allowed")) if tool_call else None,
        qwen_called=request.qwen_called,
        reason=request.reason,
    )
    return JSONResponse({"status": "recorded"})
