from __future__ import annotations

from typing import Callable, Any

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.ai.ollama_client import call_qwen
from app.ai.prompts import build_protected_prompt, build_vulnerable_prompt
from app.config import get_settings
from app.db import init_db, insert_log
from app.llmguard.pipeline import (
    inspect_output,
    inspect_retrieved_context,
    run_full_firewall,
)
from app.models import AIInteraction, PortalScope, SecurityAction, ThreatLabel, User, UserRole
from app.rag.retriever import RetrievalResult, retrieve as retrieve_role_scoped
from app.retriever import retrieve_document
from app.schemas import AskResponse, RetrievedChunk

LLMQuery = Callable[[str], str]


def _role_for_gateway(user: User | None, user_role: str | None) -> str:
    if user is None:
        return user_role or "public_user"
    if user.role == UserRole.student:
        return "student"
    if user.role == UserRole.employee:
        return "staff"
    return "super_admin"


def _portal_value(portal_scope: PortalScope | str | None) -> str | None:
    return portal_scope.value if isinstance(portal_scope, PortalScope) else portal_scope


def _action_enum(action: str) -> SecurityAction:
    return SecurityAction(action) if action in SecurityAction._value2member_map_ else SecurityAction.allow


def _label_enum(label: str) -> ThreatLabel:
    return ThreatLabel(label) if label in ThreatLabel._value2member_map_ else ThreatLabel.safe


def _result_to_chunk(result: RetrievalResult) -> dict[str, Any]:
    return {
        "document_id": result.document_id,
        "title": str(result.metadata.get("title") or result.source_filename),
        "category": str(result.metadata.get("category") or "portal_upload"),
        "classification": result.classification,
        "allowed_roles": result.allowed_roles,
        "is_synthetic": bool(result.metadata.get("is_synthetic", True)),
        "canary_markers": list(result.metadata.get("canary_markers") or []),
        "document_name": result.source_filename or result.document_id,
        "source_path": str(result.metadata.get("source_path") or result.source_filename),
        "source_set": "controlled_upload",
        "is_poisoned": False,
        "chunk_id": result.chunk_id,
        "chunk_index": result.chunk_index,
        "text": result.chunk_text,
        "chunk_text": result.chunk_text,
        "score": result.score,
        "raw_score": result.score,
        "portal_scope": result.portal_scope,
        "owner_user_id": result.owner_user_id,
    }


def _retrieved_chunk_model(chunk: dict[str, Any], *, action: str = "allow", label: str = "safe") -> RetrievedChunk:
    return RetrievedChunk(
        document_id=str(chunk.get("document_id") or ""),
        title=str(chunk.get("title") or chunk.get("document_name") or ""),
        category=str(chunk.get("category") or "general"),
        classification=str(chunk.get("classification") or "public"),
        allowed_roles=list(chunk.get("allowed_roles") or []),
        is_synthetic=bool(chunk.get("is_synthetic", False)),
        canary_markers=list(chunk.get("canary_markers") or []),
        document_name=str(chunk.get("document_name") or chunk.get("source_filename") or ""),
        source_path=str(chunk.get("source_path") or chunk.get("source_filename") or ""),
        source_set=str(chunk.get("source_set") or "controlled_upload"),
        is_poisoned=bool(chunk.get("is_poisoned", False)),
        chunk_id=str(chunk.get("chunk_id") or ""),
        chunk_index=int(chunk.get("chunk_index") or 0),
        text=str(chunk.get("text") or chunk.get("chunk_text") or ""),
        chunk_text=str(chunk.get("chunk_text") or chunk.get("text") or ""),
        score=float(chunk.get("score") or 0.0),
        raw_score=float(chunk.get("raw_score") or chunk.get("score") or 0.0),
        risk_score=float(chunk.get("risk_score") or 0.0),
        label=label,
        action=action,
        reasons=list(chunk.get("reasons") or []),
    )


def _synthetic_legacy_chunks(retrieved_doc: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not retrieved_doc:
        return []
    chunks = retrieved_doc.get("chunks") or []
    return [
        chunk for chunk in chunks
        if bool(chunk.get("is_synthetic", False)) and str(chunk.get("classification")) != "restricted_secret"
    ]


def _retrieve_chunks(
    prompt: str,
    *,
    user: User | None,
    vulnerable_mode: bool,
) -> list[dict[str, Any]]:
    if user is not None:
        return [
            _result_to_chunk(result)
            for result in retrieve_role_scoped(
                prompt,
                user,
                top_k=4,
                vulnerable_mode=vulnerable_mode,
            )
        ]

    retrieved_doc = retrieve_document(prompt, top_k=4)
    if vulnerable_mode:
        return _synthetic_legacy_chunks(retrieved_doc)
    if not retrieved_doc:
        return []
    return list(retrieved_doc.get("chunks") or [])


def _context_from_chunks(chunks: list[dict[str, Any]]) -> str:
    return "\n\n".join(str(chunk.get("chunk_text") or chunk.get("text") or "") for chunk in chunks)


def _sources_from_chunks(chunks: list[dict[str, Any]]) -> list[str]:
    return list(dict.fromkeys(str(chunk.get("source_path") or chunk.get("source_filename") or "") for chunk in chunks if chunk.get("source_path") or chunk.get("source_filename")))


def _tool_decisions(decision) -> list[dict[str, object]]:
    return [
        signal.metadata
        for signal in getattr(decision, "signals", [])
        if getattr(signal, "stage", "") == "tool_call_inspection"
    ]


def _blocked_stage(decision) -> str | None:
    blocked = [
        signal for signal in getattr(decision, "signals", [])
        if getattr(signal, "action", "") in {"block", "quarantine"}
    ]
    if blocked:
        return blocked[0].stage
    return getattr(decision, "threat_source", None)


def _log_interaction(
    db: Session | None,
    *,
    user: User | None,
    user_role: str,
    portal_scope: PortalScope | str | None,
    prompt: str,
    response: AskResponse,
) -> None:
    if db is not None:
        db.add(
            AIInteraction(
                session_id=response.session_id,
                user_id=user.id if user is not None else None,
                user_role=user_role,
                portal_scope=_portal_value(portal_scope),
                prompt=prompt,
                response_preview=(response.answer or response.response or "")[:500],
                action=_action_enum(response.action),
                label=_label_enum(response.label),
                risk_score=response.risk_score,
                qwen_called=response.llm_called,
                retrieved_chunk_ids=[chunk.chunk_id for chunk in response.retrieved_chunks],
                unauthorized_chunk_ids=[
                    str(item.get("chunk_id"))
                    for item in response.unauthorized_retrievals
                    if isinstance(item, dict) and item.get("chunk_id")
                ],
            )
        )
        db.commit()

    init_db()
    insert_log(
        prompt,
        response.retrieved_document,
        response.sources or response.retrieved_sources,
        [chunk.model_dump() for chunk in response.retrieved_chunks],
        response.action,
        response.label,
        response.blocked,
        response.reason,
        response.rule_score,
        response.semantic_score,
        response.ml_score,
        response.rule_label,
        response.semantic_label,
        response.ml_label,
        response.risk_score,
        response.answer or response.response,
        response.threat_source,
        str(response.tool_decisions[0].get("name")) if response.tool_decisions else None,
        bool(response.tool_decisions[0].get("allowed")) if response.tool_decisions else None,
        response.output_firewall_action,
        list(response.output_firewall.get("canary_markers", [])) if response.output_firewall else [],
    )


def _response(
    *,
    prompt: str,
    user_role: str,
    user_id: str | None,
    session_id: str | None,
    action: str,
    label: str,
    risk_score: float,
    reason: str,
    reasons: list[str],
    threat_source: str,
    answer: str | None,
    llm_called: bool,
    mode: str,
    firewall_active: bool,
    chunks: list[dict[str, Any]] | None = None,
    blocked_stage: str | None = None,
    output_firewall_action: str | None = None,
    sanitized: bool = False,
    tool_decisions: list[dict[str, object]] | None = None,
    output_firewall: dict[str, object] | None = None,
) -> AskResponse:
    chunk_models = [_retrieved_chunk_model(chunk, action=action, label=label) for chunk in (chunks or [])]
    sources = _sources_from_chunks(chunks or [])
    return AskResponse(
        prompt=prompt,
        user_role=user_role,
        user_id=user_id,
        session_id=session_id,
        retrieved_document=", ".join(dict.fromkeys(chunk.document_name for chunk in chunk_models)) or None,
        retrieved_sources=sources,
        retrieved_chunks=chunk_models,
        evidence_summary=None,
        threat_source=threat_source,
        qwen_called=llm_called,
        output_firewall=output_firewall,
        action=action,
        blocked=action in {"block", "quarantine"},
        label=label,
        reason=reason,
        risk_score=risk_score,
        response=answer,
        answer=answer,
        sources=sources,
        llm_called=llm_called,
        mode=mode,
        firewall_active=firewall_active,
        blocked_stage=blocked_stage,
        output_firewall_action=output_firewall_action,
        sanitized=sanitized,
        tool_decisions=tool_decisions or [],
        reasons=reasons,
    )


def process_ai_request(
    user: User | None,
    prompt: str,
    portal_scope: PortalScope | str | None,
    user_role: str,
    user_id: str | None = None,
    session_id: str | None = None,
    firewall_active: bool = True,
    *,
    db: Session | None = None,
    llm_query: LLMQuery | None = None,
) -> AskResponse:
    settings = get_settings()
    active_firewall = bool(firewall_active and settings.firewall_active)
    active_role = _role_for_gateway(user, user_role)
    active_user_id = user_id or (user.synthetic_ref if user is not None else None)
    qwen = llm_query or call_qwen

    if not active_firewall:
        if not (settings.redteam_mode or settings.app_env == "local_redteam"):
            response = _response(
                prompt=prompt,
                user_role=active_role,
                user_id=active_user_id,
                session_id=session_id,
                action="block",
                label="malicious",
                risk_score=0.98,
                reason="Vulnerable mode is disabled unless REDTEAM_MODE=true or APP_ENV=local_redteam.",
                reasons=["Rejected unsafe vulnerable-mode request outside local red-team configuration."],
                threat_source="configuration",
                answer=None,
                llm_called=False,
                mode="vulnerable_rejected",
                firewall_active=False,
                blocked_stage="configuration",
            )
            _log_interaction(db, user=user, user_role=active_role, portal_scope=portal_scope, prompt=prompt, response=response)
            return response

        chunks = _retrieve_chunks(prompt, user=user, vulnerable_mode=True)
        raw_context = _context_from_chunks(chunks) or "SYNTHETIC DEMO DATA — NOT REAL UNIVERSITY DATA. No uploaded synthetic context matched."
        answer = qwen(build_vulnerable_prompt(prompt=prompt, context=raw_context))
        response = _response(
            prompt=prompt,
            user_role=active_role,
            user_id=active_user_id,
            session_id=session_id,
            action="allow",
            label="suspicious",
            risk_score=0.65,
            reason="Vulnerable red-team mode: LLMGuard bypassed.",
            reasons=["Vulnerable red-team mode: LLMGuard bypassed."],
            threat_source="vulnerable_mode",
            answer=answer,
            llm_called=True,
            mode="vulnerable_red_team",
            firewall_active=False,
            chunks=chunks,
            tool_decisions=[],
        )
        _log_interaction(db, user=user, user_role=active_role, portal_scope=portal_scope, prompt=prompt, response=response)
        return response

    prompt_decision = run_full_firewall(
        prompt=prompt,
        user=user,
        user_role=active_role,
        user_id=active_user_id,
        requested_portal_scope=_portal_value(portal_scope),
        db=db,
    )
    if prompt_decision.action in {"block", "quarantine"}:
        response = _response(
            prompt=prompt,
            user_role=active_role,
            user_id=active_user_id,
            session_id=session_id,
            action=prompt_decision.action,
            label=prompt_decision.label,
            risk_score=prompt_decision.risk_score,
            reason="; ".join(prompt_decision.reasons),
            reasons=prompt_decision.reasons,
            threat_source=prompt_decision.threat_source,
            answer=None,
            llm_called=False,
            mode="protected",
            firewall_active=True,
            blocked_stage=_blocked_stage(prompt_decision),
            tool_decisions=_tool_decisions(prompt_decision),
        )
        _log_interaction(db, user=user, user_role=active_role, portal_scope=portal_scope, prompt=prompt, response=response)
        return response

    chunks = _retrieve_chunks(prompt, user=user, vulnerable_mode=False)
    context_decision = inspect_retrieved_context(chunks, user=user, user_role=active_role, db=db)
    sanitized = context_decision.action == "sanitize"
    if context_decision.action in {"block", "quarantine"}:
        response = _response(
            prompt=prompt,
            user_role=active_role,
            user_id=active_user_id,
            session_id=session_id,
            action=context_decision.action,
            label=context_decision.label,
            risk_score=max(prompt_decision.risk_score, context_decision.score),
            reason="; ".join(context_decision.reasons),
            reasons=context_decision.reasons,
            threat_source=context_decision.threat_source,
            answer=None,
            llm_called=False,
            mode="protected",
            firewall_active=True,
            chunks=chunks,
            blocked_stage="retrieved_context_inspection",
            sanitized=sanitized,
            tool_decisions=_tool_decisions(prompt_decision),
        )
        _log_interaction(db, user=user, user_role=active_role, portal_scope=portal_scope, prompt=prompt, response=response)
        return response

    sanitized_chunks = context_decision.metadata.get("context", {}).get("sanitized_chunks") if isinstance(context_decision.metadata.get("context"), dict) else None
    final_chunks = sanitized_chunks if isinstance(sanitized_chunks, list) else chunks
    final_context = _context_from_chunks(final_chunks)
    if not final_context:
        final_context = "No authorized context was retrieved."

    answer = qwen(build_protected_prompt(prompt=prompt, context=final_context))
    output_decision = inspect_output(
        answer,
        user_role=active_role,
        allowed_classifications=list(dict.fromkeys(str(chunk.get("classification")) for chunk in final_chunks if chunk.get("classification"))),
        db=db,
    )
    if output_decision.action in {"block", "quarantine"}:
        output_payload = output_decision.metadata
        response = _response(
            prompt=prompt,
            user_role=active_role,
            user_id=active_user_id,
            session_id=session_id,
            action=output_decision.action,
            label=output_decision.label,
            risk_score=max(prompt_decision.risk_score, context_decision.score, output_decision.score),
            reason="; ".join(output_decision.reasons),
            reasons=output_decision.reasons,
            threat_source="output_firewall",
            answer=None,
            llm_called=True,
            mode="protected",
            firewall_active=True,
            chunks=final_chunks,
            blocked_stage="output_inspection",
            output_firewall_action=output_decision.action,
            sanitized=sanitized,
            tool_decisions=_tool_decisions(prompt_decision),
            output_firewall=output_payload,
        )
        _log_interaction(db, user=user, user_role=active_role, portal_scope=portal_scope, prompt=prompt, response=response)
        return response

    response = _response(
        prompt=prompt,
        user_role=active_role,
        user_id=active_user_id,
        session_id=session_id,
        action="sanitize" if sanitized else "allow",
        label="suspicious" if sanitized else "safe",
        risk_score=max(prompt_decision.risk_score, context_decision.score, output_decision.score),
        reason="No dangerous content detected" if not sanitized else "Retrieved context was sanitized before model use.",
        reasons=["Protected mode completed all LLMGuard checks."],
        threat_source="none" if not sanitized else "retrieved_context",
        answer=answer,
        llm_called=True,
        mode="protected",
        firewall_active=True,
        chunks=final_chunks,
        output_firewall_action=output_decision.action,
        sanitized=sanitized,
        tool_decisions=_tool_decisions(prompt_decision),
        output_firewall=output_decision.metadata,
    )
    _log_interaction(db, user=user, user_role=active_role, portal_scope=portal_scope, prompt=prompt, response=response)
    return response
