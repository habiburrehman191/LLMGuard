from __future__ import annotations

from pathlib import Path

from fastapi import Depends, FastAPI
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session

from app.application_registry import bootstrap_default_application
from app.auth import router as auth_router
from app.ai.gateway import process_ai_request
from app.database import get_db, init_database
from app.db import init_db
from app.frontend import router as frontend_router
from app.guard_routes import router as guard_router
from app.ingestion_routes import router as ingestion_router
from app.integration_routes import router as integration_router
from app.portals.admin import router as admin_portal_router
from app.schemas import AskRequest, AskResponse

BASE_DIR = Path(__file__).resolve().parent.parent

app = FastAPI()
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
app.include_router(admin_portal_router)
app.include_router(frontend_router)
app.include_router(auth_router)
app.include_router(integration_router)
app.include_router(guard_router)
app.include_router(ingestion_router)


@app.on_event("startup")
def startup_event():
    init_db()
    bootstrap_default_application()
    init_database()


@app.get("/health")
def health():
    return {"message": "LLMGuard API is running"}


@app.post("/ask", response_model=AskResponse)
def ask_llm(request: AskRequest, db: Session = Depends(get_db)):
    return process_ai_request(
        None,
        request.prompt,
        None,
        request.user_role,
        user_id=request.user_id,
        session_id=request.session_id,
        firewall_active=True if request.firewall_active is None else request.firewall_active,
        db=db,
    )
