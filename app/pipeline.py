from __future__ import annotations

from collections.abc import Callable
import re

from app.access_control import access_decision, normalize_role
from app.db import insert_access_event, insert_log
from app.dlp import detect_dlp
from app.hybrid_firewall import ACTION_PRIORITY, HybridFirewall, inspect_with_hybrid_firewall
from app.output_firewall import inspect_output
from app.retriever import SemanticRetriever, retrieve_document
from app.schemas import AskResponse, RetrievedChunk
from app.semantic_firewall import SemanticFirewall
from app.tool_firewall import tool_firewall_decision

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
        result.threat_source,
        str(result.tool_call.get("name")) if result.tool_call else None,
        bool(result.tool_call.get("allowed")) if result.tool_call else None,
        str(result.output_firewall.get("action")) if result.output_firewall else None,
        list(result.output_firewall.get("canary_markers", [])) if result.output_firewall else [],
    )


def _blocked_result(
    prompt: str,
    reason: str,
    risk_score: float,
    *,
    user_role: str = "public_user",
    user_id: str | None = None,
    session_id: str | None = None,
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
    threat_source: str = "retrieved_content",
    qwen_called: bool = False,
    tool_call: dict[str, object] | None = None,
    access_control: dict[str, object] | None = None,
    dlp: dict[str, object] | None = None,
    output_firewall: dict[str, object] | None = None,
    unauthorized_retrievals: list[dict[str, object]] | None = None,
) -> AskResponse:
    return AskResponse(
        prompt=prompt,
        user_role=user_role,
        user_id=user_id,
        session_id=session_id,
        retrieved_document=retrieved_document,
        retrieved_sources=retrieved_sources or [],
        retrieved_chunks=retrieved_chunks or [],
        evidence_summary=evidence_summary,
        threat_source=threat_source,
        qwen_called=qwen_called,
        tool_call=tool_call,
        access_control=access_control,
        dlp=dlp,
        output_firewall=output_firewall,
        unauthorized_retrievals=unauthorized_retrievals or [],
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
    user_role: str = "public_user",
    user_id: str | None = None,
    session_id: str | None = None,
    retriever: SemanticRetriever | None = None,
    semantic_firewall: SemanticFirewall | None = None,
    hybrid_firewall: HybridFirewall | None = None,
    log_writer: LogWriter = insert_log,
) -> AskResponse:
    active_hybrid_firewall = hybrid_firewall or HybridFirewall(
        semantic_firewall=semantic_firewall,
    )
    active_role = normalize_role(user_role)
    tool_decision = tool_firewall_decision(
        user_prompt,
        user_role=active_role,
        user_id=user_id,
    )
    tool_call = tool_decision.as_dict()
    dlp_assessment = detect_dlp(user_prompt, active_role)
    dlp_payload = dlp_assessment.as_dict()

    if not tool_decision.allowed:
        result = _blocked_result(
            prompt=user_prompt,
            user_role=active_role,
            user_id=user_id,
            session_id=session_id,
            reason=tool_decision.reason,
            risk_score=tool_decision.risk_score,
            action=tool_decision.action,
            label=tool_decision.label,
            rule_score=tool_decision.risk_score,
            rule_label=tool_decision.label,
            threat_source="tool_call",
            tool_call=tool_call,
            access_control={
                "allowed": False,
                "user_role": active_role,
                "reason": tool_decision.reason,
            },
            dlp=dlp_payload,
        )
        _log_result(result, log_writer)
        return result

    if dlp_assessment.action in {"block", "quarantine"}:
        result = _blocked_result(
            prompt=user_prompt,
            user_role=active_role,
            user_id=user_id,
            session_id=session_id,
            reason="; ".join(dict.fromkeys(dlp_assessment.reasons)),
            risk_score=dlp_assessment.risk_score,
            action=dlp_assessment.action,
            label=dlp_assessment.label,
            rule_score=dlp_assessment.risk_score,
            rule_label=dlp_assessment.label,
            threat_source="access_control",
            tool_call=tool_call,
            access_control={
                "allowed": False,
                "user_role": active_role,
                "requested_classifications": dlp_assessment.requested_classifications,
                "reason": "Prompt requests data outside the selected role permissions.",
            },
            dlp=dlp_payload,
        )
        _log_result(result, log_writer)
        return result

    prompt_assessment = inspect_with_hybrid_firewall(
        user_prompt,
        firewall=active_hybrid_firewall,
    )
    if prompt_assessment.action in {"block", "quarantine"}:
        result = _blocked_result(
            prompt=user_prompt,
            user_role=active_role,
            user_id=user_id,
            session_id=session_id,
            reason="; ".join(dict.fromkeys(prompt_assessment.reasons)),
            risk_score=prompt_assessment.risk_score,
            action=prompt_assessment.action,
            label=prompt_assessment.label,
            rule_score=prompt_assessment.rule_score,
            semantic_score=prompt_assessment.semantic_score,
            ml_score=prompt_assessment.ml_score,
            rule_label=prompt_assessment.rule_label,
            semantic_label=prompt_assessment.semantic_label,
            ml_label=prompt_assessment.ml_label,
            threat_source="prompt",
            tool_call=tool_call,
            access_control={
                "allowed": True,
                "user_role": active_role,
                "reason": "Prompt blocked by firewall before document access.",
            },
            dlp=dlp_payload,
        )
        _log_result(result, log_writer)
        return result

    retrieval_prompt = (
        prompt_assessment.sanitized_text
        if prompt_assessment.action == "sanitize"
        else user_prompt
    )
    if retrieval_prompt == SANITIZED_PLACEHOLDER:
        retrieval_prompt = user_prompt
    retrieved_doc = retrieve_document(retrieval_prompt, retriever=retriever)
    if not retrieved_doc:
        result = _blocked_result(
            prompt=user_prompt,
            user_role=active_role,
            user_id=user_id,
            session_id=session_id,
            reason="No relevant document retrieved",
            risk_score=1.0,
            action="block",
            label="malicious",
            threat_source="retrieval",
            tool_call=tool_call,
            access_control={
                "allowed": False,
                "user_role": active_role,
                "reason": "No relevant controlled repository document was retrieved.",
            },
            dlp=dlp_payload,
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
    action = "log" if dlp_assessment.action == "log" else "allow"
    label = "suspicious" if dlp_assessment.label == "suspicious" else "safe"
    reason = (
        "; ".join(dict.fromkeys(dlp_assessment.reasons))
        if dlp_assessment.action == "log"
        else "No dangerous content detected"
    )
    rule_score = 0.0
    semantic_score = 0.0
    ml_score = 0.0
    rule_label = "safe"
    semantic_label = "safe"
    ml_label = "safe"
    risk_score = dlp_assessment.risk_score if dlp_assessment.action == "log" else 0.0
    reasons: list[str] = []
    context_candidates: list[dict[str, object]] = []
    response_chunks: list[RetrievedChunk] = []
    unauthorized_retrievals: list[dict[str, object]] = []

    for chunk in chunks:
        classification = str(chunk.get("classification", "public"))
        access = access_decision(active_role, classification)
        if not access.allowed:
            denied = {
                "document_id": str(chunk.get("document_id", chunk.get("chunk_id", ""))),
                "title": str(chunk.get("title", chunk.get("document_name", ""))),
                "classification": classification,
                "source_path": str(chunk.get("source_path", "")),
                "chunk_id": str(chunk.get("chunk_id", "")),
                "reason": access.reason,
            }
            unauthorized_retrievals.append(denied)
            insert_access_event(
                prompt=user_prompt,
                user_role=active_role,
                user_id=user_id,
                session_id=session_id,
                document_id=denied["document_id"],
                title=denied["title"],
                classification=classification,
                source_path=denied["source_path"],
                allowed=False,
                reason=access.reason,
            )
            continue

        assessment = inspect_with_hybrid_firewall(
            chunk["text"],
            firewall=active_hybrid_firewall,
        )
        response_chunks.append(
            RetrievedChunk(
                document_id=str(chunk.get("document_id", "")),
                title=str(chunk.get("title", chunk["document_name"])),
                category=str(chunk.get("category", "general")),
                classification=classification,
                allowed_roles=list(chunk.get("allowed_roles", [])),
                is_synthetic=bool(chunk.get("is_synthetic", False)),
                canary_markers=list(chunk.get("canary_markers", [])),
                document_name=chunk["document_name"],
                source_path=chunk["source_path"],
                source_set=str(chunk.get("source_set", "unknown")),
                is_poisoned=bool(chunk.get("is_poisoned", False)),
                chunk_id=chunk["chunk_id"],
                chunk_index=chunk["chunk_index"],
                text=chunk["text"],
                chunk_text=str(chunk.get("chunk_text", chunk["text"])),
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

    if not response_chunks and unauthorized_retrievals:
        result = _blocked_result(
            prompt=user_prompt,
            user_role=active_role,
            user_id=user_id,
            session_id=session_id,
            retrieved_document=retrieved_doc["filename"],
            retrieved_sources=retrieved_sources,
            reason="Retrieved documents were outside the selected role permissions.",
            action="block",
            label="malicious",
            rule_score=0.94,
            rule_label="malicious",
            risk_score=0.94,
            threat_source="access_control",
            tool_call=tool_call,
            access_control={
                "allowed": False,
                "user_role": active_role,
                "reason": "All relevant retrieved chunks were unauthorized for this role.",
            },
            dlp=dlp_payload,
            unauthorized_retrievals=unauthorized_retrievals,
        )
        _log_result(result, log_writer)
        return result

    if action in {"block", "quarantine"} or not selected_context_candidates:
        result = _blocked_result(
            prompt=user_prompt,
            user_role=active_role,
            user_id=user_id,
            session_id=session_id,
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
            threat_source="retrieved_content",
            tool_call=tool_call,
            access_control={
                "allowed": len(unauthorized_retrievals) == 0,
                "user_role": active_role,
                "reason": "Retrieved content firewall blocked or removed all authorized content.",
            },
            dlp=dlp_payload,
            unauthorized_retrievals=unauthorized_retrievals,
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
    output_decision = inspect_output(
        response,
        user_role=active_role,
        allowed_classifications=list(
            dict.fromkeys(str(chunk.classification) for chunk in response_chunks)
        ),
    )
    output_payload = output_decision.as_dict()
    if output_decision.blocked:
        result = _blocked_result(
            prompt=user_prompt,
            user_role=active_role,
            user_id=user_id,
            session_id=session_id,
            retrieved_document=retrieved_doc["filename"],
            retrieved_sources=retrieved_sources,
            retrieved_chunks=response_chunks,
            reason="; ".join(dict.fromkeys(output_decision.reasons)),
            action=output_decision.action,
            label=output_decision.label,
            rule_score=rule_score,
            semantic_score=semantic_score,
            ml_score=ml_score,
            rule_label=rule_label,
            semantic_label=semantic_label,
            ml_label=ml_label,
            risk_score=max(risk_score, output_decision.risk_score),
            evidence_summary=evidence_summary,
            threat_source="output_firewall",
            qwen_called=True,
            tool_call=tool_call,
            access_control={
                "allowed": len(unauthorized_retrievals) == 0,
                "user_role": active_role,
                "reason": "Output firewall blocked the generated answer before release.",
            },
            dlp=dlp_payload,
            output_firewall=output_payload,
            unauthorized_retrievals=unauthorized_retrievals,
        )
        _log_result(result, log_writer)
        return result

    result = AskResponse(
        prompt=user_prompt,
        user_role=active_role,
        user_id=user_id,
        session_id=session_id,
        retrieved_document=retrieved_doc["filename"],
        retrieved_sources=retrieved_sources,
        retrieved_chunks=response_chunks,
        evidence_summary=evidence_summary,
        threat_source="retrieved_content" if reasons else "none",
        qwen_called=True,
        tool_call=tool_call,
        access_control={
            "allowed": len(unauthorized_retrievals) == 0,
            "user_role": active_role,
            "reason": (
                "All retrieved chunks were authorized for this role."
                if not unauthorized_retrievals
                else "Unauthorized chunks were filtered before content firewall and Qwen context."
            ),
        },
        dlp=dlp_payload,
        output_firewall=output_payload,
        unauthorized_retrievals=unauthorized_retrievals,
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
