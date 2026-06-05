from __future__ import annotations

from pathlib import Path

from fastapi import Depends, FastAPI
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session

from app.auth import router as auth_router
from app.ai.gateway import process_ai_request
from app.database import get_db, init_database
from app.db import init_db
from app.demo_routes import router as demo_router
from app.frontend import router as frontend_router
from app.portals.admin import router as admin_portal_router
from app.portals.employee import router as employee_portal_router
from app.portals.student import router as student_portal_router
from app.schemas import AskRequest, AskResponse

BASE_DIR = Path(__file__).resolve().parent.parent

app = FastAPI()
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
app.include_router(student_portal_router)
app.include_router(employee_portal_router)
app.include_router(admin_portal_router)
app.include_router(frontend_router)
app.include_router(demo_router)
app.include_router(auth_router)


@app.on_event("startup")
def startup_event():
    init_db()
    init_database()


@app.get("/")
def root():
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
