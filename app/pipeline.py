from __future__ import annotations

from collections.abc import Callable

from app.db import insert_log
from app.hybrid_firewall import ACTION_PRIORITY, HybridFirewall, inspect_with_hybrid_firewall
from app.retriever import SemanticRetriever, retrieve_document
from app.schemas import AskResponse, RetrievedChunk
from app.semantic_firewall import SemanticFirewall

SANITIZED_PLACEHOLDER = "[REMOVED: malicious content detected]"
LogWriter = Callable[
    [
        str,
        str | None,
        list[str] | None,
        list[dict[str, object]] | None,
        str,
        str,
        bool,
        str,
        float,
        float,
        float,
        str,
        str,
        str,
        float,
        str | None,
    ],
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
        result.label,
        result.blocked,
        result.reason,
        result.rule_score,
        result.semantic_score,
        result.ml_score,
        result.rule_label,
        result.semantic_label,
        result.ml_label,
        result.risk_score,
        result.response,
    )


def _blocked_result(
    prompt: str,
    reason: str,
    risk_score: float,
    *,
    retrieved_document: str | None = None,
    retrieved_sources: list[str] | None = None,
    retrieved_chunks: list[RetrievedChunk] | None = None,
    action: str = "block",
    label: str = "malicious",
    rule_score: float = 0.0,
    semantic_score: float = 0.0,
    ml_score: float = 0.0,
    rule_label: str = "safe",
    semantic_label: str = "safe",
    ml_label: str = "safe",
) -> AskResponse:
    return AskResponse(
        prompt=prompt,
        retrieved_document=retrieved_document,
        retrieved_sources=retrieved_sources or [],
        retrieved_chunks=retrieved_chunks or [],
        action=action,
        blocked=action in {"block", "quarantine"},
        label=label,
        reason=reason,
        rule_score=rule_score,
        semantic_score=semantic_score,
        ml_score=ml_score,
        rule_label=rule_label,
        semantic_label=semantic_label,
        ml_label=ml_label,
        risk_score=risk_score,
        response=None,
    )


def process_prompt(
    user_prompt: str,
    llm_query: LLMQuery,
    *,
    retriever: SemanticRetriever | None = None,
    semantic_firewall: SemanticFirewall | None = None,
    hybrid_firewall: HybridFirewall | None = None,
    log_writer: LogWriter = insert_log,
) -> AskResponse:
    retrieved_doc = retrieve_document(user_prompt, retriever=retriever)
    if not retrieved_doc:
        result = _blocked_result(
            prompt=user_prompt,
            reason="No relevant document retrieved",
            risk_score=1.0,
            action="block",
            label="malicious",
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
    active_hybrid_firewall = hybrid_firewall or HybridFirewall(
        semantic_firewall=semantic_firewall,
    )

    action = "allow"
    label = "safe"
    reason = "No dangerous content detected"
    rule_score = 0.0
    semantic_score = 0.0
    ml_score = 0.0
    rule_label = "safe"
    semantic_label = "safe"
    ml_label = "safe"
    risk_score = 0.0
    reasons: list[str] = []
    safe_context_parts: list[str] = []
    response_chunks: list[RetrievedChunk] = []

    for chunk in chunks:
        assessment = inspect_with_hybrid_firewall(
            chunk["text"],
            firewall=active_hybrid_firewall,
        )
        response_chunks.append(
            RetrievedChunk(
                document_name=chunk["document_name"],
                source_path=chunk["source_path"],
                chunk_id=chunk["chunk_id"],
                chunk_index=chunk["chunk_index"],
                text=chunk["text"],
                score=float(chunk.get("score", 0.0)),
                rule_score=assessment.rule_score,
                semantic_score=assessment.semantic_score,
                ml_score=assessment.ml_score,
                risk_score=assessment.risk_score,
                rule_label=assessment.rule_label,
                semantic_label=assessment.semantic_label,
                ml_label=assessment.ml_label,
                label=assessment.label,
                action=assessment.action,
                reasons=assessment.reasons,
            )
        )

        if ACTION_PRIORITY[assessment.action] > ACTION_PRIORITY[action]:
            action = assessment.action
        if assessment.label == "malicious":
            label = "malicious"
        elif assessment.label == "suspicious" and label == "safe":
            label = "suspicious"

        rule_score = max(rule_score, assessment.rule_score)
        semantic_score = max(semantic_score, assessment.semantic_score)
        ml_score = max(ml_score, assessment.ml_score)
        risk_score = max(risk_score, assessment.risk_score)

        if assessment.rule_label == "malicious" or (
            assessment.rule_label == "suspicious" and rule_label == "safe"
        ):
            rule_label = assessment.rule_label
        if assessment.semantic_label == "malicious" or (
            assessment.semantic_label == "suspicious" and semantic_label == "safe"
        ):
            semantic_label = assessment.semantic_label
        if assessment.ml_label == "malicious" or (
            assessment.ml_label == "suspicious" and ml_label == "safe"
        ):
            ml_label = assessment.ml_label

        reasons.extend(assessment.reasons)

        if assessment.action in {"block", "quarantine"}:
            continue

        final_chunk = (
            assessment.sanitized_text
            if assessment.action == "sanitize"
            else assessment.original_text
        )
        if final_chunk == SANITIZED_PLACEHOLDER:
            continue

        safe_context_parts.append(
            f"[Source: {chunk['source_path']} | Chunk {chunk.get('chunk_index', 0) + 1} | Score {chunk.get('score', 0.0):.3f}]\n"
            f"{final_chunk}"
        )

    if action in {"block", "quarantine"} or not safe_context_parts:
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
            action="quarantine" if action == "quarantine" else "block",
            label=label if label != "safe" else "malicious",
            rule_score=rule_score,
            semantic_score=semantic_score,
            ml_score=ml_score,
            rule_label=rule_label,
            semantic_label=semantic_label,
            ml_label=ml_label,
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
        label=label,
        reason=reason,
        rule_score=rule_score,
        semantic_score=semantic_score,
        ml_score=ml_score,
        rule_label=rule_label,
        semantic_label=semantic_label,
        ml_label=ml_label,
        risk_score=risk_score,
        response=response,
    )
    _log_result(result, log_writer)
    return result
