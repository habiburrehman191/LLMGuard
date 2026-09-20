from __future__ import annotations

import re

from .trusted_prompt import build_trusted_prompt


class LLMUnavailable(RuntimeError):
    pass


def generate_answer(portal_context: str, question: str, context: str, history: list[str]) -> str:
    try:
        import requests
        from app.config import get_settings
    except Exception as exc:
        raise LLMUnavailable("Local model dependencies are unavailable.") from exc

    settings = get_settings()
    if settings.ollama_model != "qwen3:1.7b":
        raise LLMUnavailable("The configured model is not the approved university demo model.")
    trusted_prompt = build_trusted_prompt(
        portal_context=portal_context,
        question=question,
        context=context,
        history=history,
    )
    payload = {
        "model": settings.ollama_model,
        "messages": trusted_prompt.to_messages(),
        "stream": False,
        "think": False,
        "keep_alive": "30m",
        "options": {"num_predict": 240, "num_ctx": 4096, "temperature": 0.1},
    }
    try:
        response = requests.post(settings.ollama_url, json=payload, timeout=60)
        response.raise_for_status()
        answer = str(response.json()["message"]["content"]).strip()
    except (requests.RequestException, KeyError, TypeError, ValueError) as exc:
        raise LLMUnavailable("The local Qwen service is unavailable.") from exc
    answer = re.sub(r"<think>.*?</think>", "", answer, flags=re.DOTALL | re.IGNORECASE).strip()
    if not answer or answer.lower().startswith("llm backend error"):
        raise LLMUnavailable("The local Qwen service did not return an answer.")
    return answer
