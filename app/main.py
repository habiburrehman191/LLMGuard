from fastapi import FastAPI
import requests
from app.firewall import rule_based_check, sanitize_text
from app.semantic_firewall import semantic_check
from app.schemas import AskRequest, AskResponse
from app.retriever import retrieve_document
from app.db import init_db, insert_log

app = FastAPI()

OLLAMA_URL = "http://localhost:11434/api/chat"


def query_vicuna(prompt: str):
    payload = {
        "model": "vicuna",
        "messages": [
            {"role": "user", "content": prompt}
        ],
        "stream": False
    }

    try:
        response = requests.post(OLLAMA_URL, json=payload, timeout=120)
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
    user_prompt = request.prompt

    retrieved_doc = retrieve_document(user_prompt)
    if not retrieved_doc:
        result = AskResponse(
            prompt=user_prompt,
            retrieved_document=None,
            action="block",
            blocked=True,
            reason="No document retrieved",
            risk_score=1.0,
            response=None
        )
        insert_log(
            result.prompt,
            result.retrieved_document,
            result.action,
            result.blocked,
            result.reason,
            result.risk_score,
            result.response
        )
        return result

    original_content = retrieved_doc["content"]

    rule_result = rule_based_check(original_content)
    semantic_result = semantic_check(original_content)

    action = "allow"
    final_content = original_content
    reason = "No dangerous content detected"
    risk_score = max(rule_result["risk_score"], semantic_result["score"])

    if rule_result["blocked"]:
        action = "sanitize"
        final_content = sanitize_text(original_content)
        reason = rule_result["reason"]

    elif semantic_result["is_attack"]:
        action = "sanitize"
        final_content = sanitize_text(original_content)
        reason = f"Semantic match with attack pattern: '{semantic_result['matched_pattern']}'"

    combined_prompt = f"""
Use the following context to answer the user question.

Context:
{final_content}

Question:
{user_prompt}
"""

    answer = query_vicuna(combined_prompt)

    result = AskResponse(
        prompt=user_prompt,
        retrieved_document=retrieved_doc["filename"],
        action=action,
        blocked=False,
        reason=reason,
        risk_score=risk_score,
        response=answer
    )

    insert_log(
        result.prompt,
        result.retrieved_document,
        result.action,
        result.blocked,
        result.reason,
        result.risk_score,
        result.response
    )

    return result