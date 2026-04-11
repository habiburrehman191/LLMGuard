from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.config import get_settings
from app.db import init_db
from app.frontend import router as frontend_router
from app.pipeline import process_prompt
from app.schemas import AskRequest, AskResponse

BASE_DIR = Path(__file__).resolve().parent.parent

app = FastAPI()
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
app.include_router(frontend_router)


def query_vicuna(prompt: str) -> str:
    try:
        import requests
    except ImportError as exc:
        return f"LLM backend error: requests dependency is unavailable ({exc})"

    settings = get_settings()
    payload = {
        "model": settings.ollama_model,
        "messages": [
            {"role": "user", "content": prompt}
        ],
        "stream": False
    }

    try:
        response = requests.post(settings.ollama_url, json=payload, timeout=120)
        response.raise_for_status()
        return response.json()["message"]["content"]
    except requests.exceptions.RequestException as e:
        return f"LLM backend error: {str(e)}"

@app.on_event("startup")
def startup_event():
    init_db()


@app.get("/")
def root():
    return {"message": "LLMGuard API is running"}


@app.post("/ask", response_model=AskResponse)
def ask_llm(request: AskRequest):
    return process_prompt(request.prompt, query_vicuna)
