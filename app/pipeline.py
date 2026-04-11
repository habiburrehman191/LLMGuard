from __future__ import annotations

from collections.abc import Callable
import re

from app.db import insert_log
from app.hybrid_firewall import ACTION_PRIORITY, HybridFirewall, inspect_with_hybrid_firewall
from app.retriever import SemanticRetriever, retrieve_document
from app.schemas import AskResponse, RetrievedChunk
from app.semantic_firewall import SemanticFirewall

SANITIZED_PLACEHOLDER = "[REMOVED: malicious content detected]"
USER_VISIBLE_INTERNAL_PATTERNS = (
    "clean",
    "poisoned",
    "chunk",
    "score",
    "source path",
    "retrieval",
    "docs/",
)
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
        "Answer the user question using the policy context below.\n"
        "Keep the answer concise, natural, and policy-focused.\n"
        "Do not mention internal retrieval details, source paths, chunk numbers, scores, or implementation terms.\n\n"
        f"Policy context:\n{context}\n\n"
        f"User question:\n{user_prompt}"
    )


def _clean_user_visible_text(text: str) -> str:
    normalized = " ".join(text.split())
    if not normalized:
        return ""

    cleaned = re.sub(
        r"(?i)\b(?:according to|based on|from)\s+(?:the\s+)?(?:retrieved|provided|internal)\s+(?:context|evidence)\b[:,]?\s*",
        "",
        normalized,
    )
    sentences = re.split(r"(?<=[.!?])\s+", cleaned)
    safe_sentences = [
        sentence.strip()
        for sentence in sentences
        if sentence.strip() and not any(pattern in sentence.lower() for pattern in USER_VISIBLE_INTERNAL_PATTERNS)
    ]
    if safe_sentences:
        return " ".join(safe_sentences).strip()

    fallback = re.sub(r"(?i)\b(?:clean|poisoned|chunk|retrieval|score)\b", "", cleaned)
    fallback = re.sub(r"(?i)\bsource path\b[:\s]*\S*", "", fallback)
    fallback = re.sub(r"\bdocs/\S+\b", "", fallback)
    fallback = re.sub(r"(?i)\bthe\s+document\s+says\b", "the policy states", fallback)
    fallback = re.sub(r"\s{2,}", " ", fallback).strip(" ,;:-")
    return fallback


def _build_evidence_summary(context_chunks: list[dict[str, object]]) -> str | None:
    summary_sentences: list[str] = []
    for item in context_chunks:
        candidate = _clean_user_visible_text(str(item["text"]))
        if not candidate:
            continue
        for sentence in re.split(r"(?<=[.!?])\s+", candidate):
            sentence = sentence.strip()
            if sentence and sentence not in summary_sentences:
                summary_sentences.append(sentence)
            if len(summary_sentences) == 2:
                return " ".join(summary_sentences)
    return " ".join(summary_sentences) if summary_sentences else None


def _format_user_response(response: str | None, *, fallback_summary: str | None) -> str | None:
    if response is None:
        return None

    cleaned = _clean_user_visible_text(response)
    if cleaned:
        return cleaned
    return fallback_summary


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
    evidence_summary: str | None = None,
) -> AskResponse:
    return AskResponse(
        prompt=prompt,
        retrieved_document=retrieved_document,
        retrieved_sources=retrieved_sources or [],
        retrieved_chunks=retrieved_chunks or [],
        evidence_summary=evidence_summary,
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
    context_candidates: list[dict[str, object]] = []
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
                source_set=str(chunk.get("source_set", "unknown")),
                is_poisoned=bool(chunk.get("is_poisoned", False)),
                chunk_id=chunk["chunk_id"],
                chunk_index=chunk["chunk_index"],
                text=chunk["text"],
                score=float(chunk.get("score", 0.0)),
                raw_score=float(chunk.get("raw_score", chunk.get("score", 0.0))),
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
        if bool(chunk.get("is_poisoned", False)):
            response_chunks[-1].reasons.append("Retrieved from a known poisoned source set")

        if assessment.action in {"block", "quarantine"}:
            continue

        final_chunk = (
            assessment.sanitized_text
            if assessment.action == "sanitize"
            else assessment.original_text
        )
        if final_chunk == SANITIZED_PLACEHOLDER:
            continue

        context_candidates.append(
            {
                "document_name": chunk["document_name"],
                "source_path": chunk["source_path"],
                "source_set": str(chunk.get("source_set", "unknown")),
                "is_poisoned": bool(chunk.get("is_poisoned", False)),
                "text": final_chunk,
            }
        )

    clean_context_candidates = [
        item for item in context_candidates
        if not bool(item["is_poisoned"])
    ]
    selected_context_candidates = clean_context_candidates or context_candidates
    evidence_summary = _build_evidence_summary(selected_context_candidates)

    if action in {"block", "quarantine"} or not selected_context_candidates:
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
            evidence_summary=evidence_summary,
        )
        _log_result(result, log_writer)
        return result

    if reasons:
        reason = "; ".join(dict.fromkeys(reasons))

    final_content = "\n\n".join(str(item["text"]) for item in selected_context_candidates)
    response = _format_user_response(
        llm_query(build_combined_prompt(user_prompt, final_content)),
        fallback_summary=evidence_summary,
    )

    result = AskResponse(
        prompt=user_prompt,
        retrieved_document=retrieved_doc["filename"],
        retrieved_sources=retrieved_sources,
        retrieved_chunks=response_chunks,
        evidence_summary=evidence_summary,
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
