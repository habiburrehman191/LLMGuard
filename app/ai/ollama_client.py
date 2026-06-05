from __future__ import annotations

from app.config import get_settings


def call_qwen(prompt: str) -> str:
    try:
        import requests
    except ImportError as exc:
        return f"LLM backend error: requests dependency is unavailable ({exc})"

    settings = get_settings()
    payload = {
        "model": "qwen3:1.7b",
        "messages": [{"role": "user", "content": prompt}],
        "stream": False,
        "keep_alive": "30m",
        "options": {
            "num_predict": 25,
            "num_ctx": 768,
        },
    }

    try:
        response = requests.post(settings.ollama_url, json=payload, timeout=120)
        response.raise_for_status()
        return response.json()["message"]["content"]
    except requests.exceptions.RequestException as exc:
        return f"LLM backend error: {exc}"
