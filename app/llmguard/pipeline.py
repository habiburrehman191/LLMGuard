from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.llmguard.access_firewall import inspect_access, inspect_retrieval_metadata
from app.llmguard.context_firewall import inspect_retrieved_chunks
from app.llmguard.dlp import detect_sensitive_data
from app.llmguard.heuristic_validator import validate_prompt_context
from app.llmguard.output_firewall import inspect_generated_output
from app.llmguard.prompt_firewall import inspect_prompt as prompt_stage
from app.llmguard.risk_engine import FirewallDecision, StageSignal, aggregate_signals, signal
from app.llmguard.tool_firewall import inspect_tool_call as tool_stage
from app.models import FirewallEvent, SecurityAction, ThreatLabel, User


def _enum_action(action: str) -> SecurityAction:
    return SecurityAction(action) if action in SecurityAction._value2member_map_ else SecurityAction.allow


def _enum_label(label: str) -> ThreatLabel:
    return ThreatLabel(label) if label in ThreatLabel._value2member_map_ else ThreatLabel.safe


def _log_stage(
    db: Session | None,
    stage_signal: StageSignal,
    *,
    source: str | None = None,
    ai_interaction_id: int | None = None,
) -> None:
    if db is None:
        return
    db.add(
        FirewallEvent(
            ai_interaction_id=ai_interaction_id,
            detector=stage_signal.stage,
            action=_enum_action(stage_signal.action),
            label=_enum_label(stage_signal.label),
            score=stage_signal.score,
            reason="; ".join(stage_signal.reasons)[:4000] or "No reason provided.",
            source=source or stage_signal.threat_source,
            metadata_json=stage_signal.metadata,
        )
    )


def _commit_logs(db: Session | None) -> None:
    if db is not None:
        db.commit()


def inspect_prompt(
    prompt: str,
    *,
    user_role: str | None = None,
    db: Session | None = None,
) -> StageSignal:
    signals = [
        prompt_stage(prompt, user_role=user_role),
        validate_prompt_context(prompt, user_role=user_role),
        detect_sensitive_data(prompt, user_role=user_role, source="prompt"),
    ]
    decision = aggregate_signals(signals)
    result = signal(
        "prompt_inspection",
        label=decision.label,
        action=decision.action,
        score=decision.risk_score,
        reasons=decision.reasons,
        threat_source=decision.threat_source,
        metadata={"stage_scores": decision.stage_scores},
    )
    for item in signals + [result]:
        _log_stage(db, item)
    _commit_logs(db)
    return result


def inspect_retrieved_context(
    chunks: list[dict[str, Any]],
    *,
    user: User | None = None,
    user_role: str | None = None,
    db: Session | None = None,
) -> StageSignal:
    metadata_signal = inspect_retrieval_metadata(chunks, user=user, user_role=user_role)
    context_signal = inspect_retrieved_chunks(chunks)
    decision = aggregate_signals([metadata_signal, context_signal])
    result = signal(
        "retrieved_context_full_inspection",
        label=decision.label,
        action=decision.action,
        score=decision.risk_score,
        reasons=decision.reasons,
        threat_source=decision.threat_source,
        metadata={
            "stage_scores": decision.stage_scores,
            "metadata": metadata_signal.metadata,
            "context": context_signal.metadata,
        },
    )
    for item in (metadata_signal, context_signal, result):
        _log_stage(db, item)
    _commit_logs(db)
    return result


def inspect_tool_call(
    prompt: str,
    *,
    user_role: str | None = None,
    user_id: str | None = None,
    tool_name: str | None = None,
    db: Session | None = None,
) -> StageSignal:
    result = tool_stage(prompt, user_role=user_role, user_id=user_id, tool_name=tool_name)
    _log_stage(db, result)
    _commit_logs(db)
    return result


def inspect_output(
    text: str | None,
    *,
    user_role: str | None = None,
    allowed_classifications: list[str] | None = None,
    db: Session | None = None,
) -> StageSignal:
    result = inspect_generated_output(
        text,
        user_role=user_role,
        allowed_classifications=allowed_classifications,
        db=db,
    )
    _log_stage(db, result, source="output")
    _commit_logs(db)
    return result


def run_full_firewall(
    *,
    prompt: str,
    user: User | None = None,
    user_role: str | None = None,
    user_id: str | None = None,
    retrieved_chunks: list[dict[str, Any]] | None = None,
    requested_portal_scope: str | None = None,
    requested_classification: str | None = None,
    tool_name: str | None = None,
    output_text: str | None = None,
    db: Session | None = None,
) -> FirewallDecision:
    active_role = user.role.value if user is not None else user_role
    signals: list[StageSignal] = []

    signals.append(inspect_prompt(prompt, user_role=active_role))
    signals.append(
        inspect_access(
            user=user,
            user_role=active_role,
            requested_portal_scope=requested_portal_scope,
            requested_classification=requested_classification,
        )
    )
    if retrieved_chunks is not None:
        signals.append(inspect_retrieved_context(retrieved_chunks, user=user))
    signals.append(inspect_tool_call(prompt, user_role=active_role, user_id=user_id, tool_name=tool_name))
    if output_text is not None:
        allowed = [
            str(chunk.get("classification"))
            for chunk in (retrieved_chunks or [])
            if chunk.get("classification")
        ]
        signals.append(inspect_output(output_text, user_role=active_role, allowed_classifications=allowed))

    decision = aggregate_signals(signals)
    final_signal = signal(
        "full_firewall_decision",
        label=decision.label,
        action=decision.action,
        score=decision.risk_score,
        reasons=decision.reasons,
        threat_source=decision.threat_source,
        metadata={"stage_scores": decision.stage_scores},
    )
    for item in signals + [final_signal]:
        _log_stage(db, item)
    _commit_logs(db)
    return aggregate_signals(signals, metadata={"stage_scores": decision.stage_scores})
