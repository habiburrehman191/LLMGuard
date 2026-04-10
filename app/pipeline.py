from __future__ import annotations

from collections.abc import Callable

from app.db import insert_log
from app.firewall import rule_based_check, sanitize_text
from app.retriever import SemanticRetriever, retrieve_document
from app.schemas import AskResponse, RetrievedChunk
from app.semantic_firewall import SemanticFirewall, semantic_check

SANITIZED_PLACEHOLDER = "[REMOVED: malicious content detected]"
LogWriter = Callable[
    [str, str | None, list[str] | None, list[dict[str, object]] | None, str, bool, str, float, str | None],
    None,
]
LLMQuery = Callable[[str], str]


def build_combined_prompt(user_prompt: str, context: str) -> str:
    return (
        "Use the following context to answer the user question.\n\n"
        f"Context:\n{context}\n\n"
        f"Question:\n{user_prompt}"
    )


def _log_result(result: AskResponse, log_writer: LogWriter) -> None:
    log_writer(
        result.prompt,
        result.retrieved_document,
        result.retrieved_sources,
        [chunk.model_dump() for chunk in result.retrieved_chunks],
        result.action,
        result.blocked,
        result.reason,
        result.risk_score,
        result.response,
    )


def _blocked_result(
    prompt: str,
    reason: str,
    risk_score: float,
    retrieved_document: str | None = None,
    retrieved_sources: list[str] | None = None,
    retrieved_chunks: list[RetrievedChunk] | None = None,
) -> AskResponse:
    return AskResponse(
        prompt=prompt,
        retrieved_document=retrieved_document,
        retrieved_sources=retrieved_sources or [],
        retrieved_chunks=retrieved_chunks or [],
        action="block",
        blocked=True,
        reason=reason,
        risk_score=risk_score,
        response=None,
    )


def process_prompt(
    user_prompt: str,
    llm_query: LLMQuery,
    *,
    retriever: SemanticRetriever | None = None,
    semantic_firewall: SemanticFirewall | None = None,
    log_writer: LogWriter = insert_log,
) -> AskResponse:
    retrieved_doc = retrieve_document(user_prompt, retriever=retriever)
    if not retrieved_doc:
        result = _blocked_result(
            prompt=user_prompt,
            reason="No relevant document retrieved",
            risk_score=1.0,
        )
        _log_result(result, log_writer)
        return result

    chunks = retrieved_doc.get("chunks") or [
        {
            "document_name": retrieved_doc["filename"],
            "source_path": retrieved_doc["filename"],
            "chunk_id": retrieved_doc["filename"],
            "chunk_index": 0,
            "text": retrieved_doc["content"],
            "score": retrieved_doc.get("score", 0.0),
        }
    ]
    retrieved_sources = retrieved_doc.get("source_paths") or []
    response_chunks = [
        RetrievedChunk(
            document_name=chunk["document_name"],
            source_path=chunk["source_path"],
            chunk_id=chunk["chunk_id"],
            chunk_index=chunk["chunk_index"],
            text=chunk["text"],
            score=float(chunk.get("score", 0.0)),
        )
        for chunk in chunks
    ]
    action = "allow"
    reason = "No dangerous content detected"
    risk_score = 0.0
    reasons: list[str] = []
    safe_context_parts: list[str] = []

    for chunk in chunks:
        chunk_text = chunk["text"]
        rule_result = rule_based_check(chunk_text)
        semantic_result = semantic_check(chunk_text, firewall=semantic_firewall)
        risk_score = max(risk_score, rule_result["risk_score"], semantic_result["score"])
        final_chunk = chunk_text

        if rule_result["blocked"]:
            action = "sanitize"
            final_chunk = sanitize_text(chunk_text)
            reasons.append(rule_result["reason"])
        elif semantic_result["is_attack"]:
            action = "sanitize"
            final_chunk = sanitize_text(chunk_text)
            reasons.append(
                "Semantic match with attack pattern: "
                f"'{semantic_result['matched_pattern']}' via {semantic_result['backend']}"
            )

        if final_chunk == SANITIZED_PLACEHOLDER:
            continue

        safe_context_parts.append(
            f"[Source: {chunk['source_path']} | Chunk {chunk.get('chunk_index', 0) + 1} | Score {chunk.get('score', 0.0):.3f}]\n"
            f"{final_chunk}"
        )

    if not safe_context_parts:
        result = _blocked_result(
            prompt=user_prompt,
            retrieved_document=retrieved_doc["filename"],
            retrieved_sources=retrieved_sources,
            retrieved_chunks=response_chunks,
            reason=(
                "; ".join(dict.fromkeys(reasons))
                if reasons
                else "All retrieved content was removed during sanitization"
            ),
            risk_score=risk_score,
        )
        _log_result(result, log_writer)
        return result

    if reasons:
        reason = "; ".join(dict.fromkeys(reasons))

    final_content = "\n\n".join(safe_context_parts)

    response = llm_query(build_combined_prompt(user_prompt, final_content))
    result = AskResponse(
        prompt=user_prompt,
        retrieved_document=retrieved_doc["filename"],
        retrieved_sources=retrieved_sources,
        retrieved_chunks=response_chunks,
        action=action,
        blocked=False,
        reason=reason,
        risk_score=risk_score,
        response=response,
    )
    _log_result(result, log_writer)
    return result
