from __future__ import annotations

from dataclasses import dataclass
from types import SimpleNamespace
from typing import Callable, Mapping, Sequence

from app.context_guard import inspect_context_chunks
from app.firewall import rule_based_check
from app.hybrid_firewall import HybridFirewall
from app.input_guard import inspect_input_content
from app.ml_firewall import ml_check
from app.output_guard import inspect_output_content
from app.security_normalization import normalize_security_text
from app.semantic_firewall import semantic_check
from evaluation.types import EvaluationCase, ModeObservation
from university_site.chatbot.security import access_restriction
from university_site.chatbot.types import ChatIdentity


ModeRunner = Callable[[EvaluationCase], ModeObservation]

_LABEL_PRIORITY = {"safe": 0, "suspicious": 1, "malicious": 2}
_ACTION_PRIORITY = {
    "allow": 0,
    "log": 1,
    "observe": 1,
    "sanitize": 2,
    "quarantine": 3,
    "block": 4,
}
_CONTINUE_ACTIONS = {"allow", "log"}


@dataclass(slots=True)
class PipelineDependencies:
    """Injectable execution boundaries used by the deterministic pipeline replay."""

    input_inspector: Callable[[str], object] = inspect_input_content
    context_inspector: Callable[[Sequence[Mapping[str, object]]], object] = (
        inspect_context_chunks
    )
    output_inspector: Callable[[str, Mapping[str, object]], object] = (
        inspect_output_content
    )
    rbac_checker: Callable[[EvaluationCase], bool] | None = None
    database_call: Callable[[EvaluationCase], None] = lambda _case: None
    retrieval_call: Callable[[EvaluationCase], None] = lambda _case: None
    tool_call: Callable[[EvaluationCase], None] = lambda _case: None
    main_llm_call: Callable[[EvaluationCase], str] = (
        lambda _case: "Synthetic evaluation response with no private data."
    )


def build_mode_runners(
    *,
    pipeline_dependencies: PipelineDependencies | None = None,
) -> dict[str, ModeRunner]:
    dependencies = pipeline_dependencies or PipelineDependencies()
    hybrid = HybridFirewall()
    return {
        "rules_only": lambda case: _run_detector_only(case, _inspect_rules),
        "semantic_only": lambda case: _run_detector_only(case, _inspect_semantic),
        "ml_only": lambda case: _run_detector_only(case, _inspect_ml),
        "hybrid": lambda case: _run_detector_only(
            case,
            lambda text: _inspect_hybrid(text, hybrid=hybrid),
        ),
        "full_protected_pipeline": lambda case: run_protected_pipeline(
            case,
            dependencies=dependencies,
        ),
        "bypassed": lambda case: run_bypassed_pipeline(
            case,
            dependencies=dependencies,
        ),
    }


def _inspection_texts(case: EvaluationCase) -> list[str]:
    if case.stage == "context":
        return [chunk.text for chunk in case.chunks]
    return [case.content]


def _run_detector_only(
    case: EvaluationCase,
    inspector: Callable[[str], tuple[str, str, float]],
) -> ModeObservation:
    observations = [inspector(text) for text in _inspection_texts(case)]
    classification, action, risk_score = max(
        observations,
        key=lambda item: (
            _LABEL_PRIORITY.get(item[0], -1),
            _ACTION_PRIORITY.get(item[1], -1),
            item[2],
        ),
    )
    return ModeObservation(
        classification=classification,
        action=action,
        risk_score=risk_score,
        execution_measured=False,
        llmguard_restricted=action in {"sanitize", "quarantine", "block"},
    )


def _normalize(text: str) -> str:
    return normalize_security_text(
        text,
        max_input_bytes=16_000,
        max_output_bytes=16_000,
    ).inspection_content


def _inspect_rules(text: str) -> tuple[str, str, float]:
    result = rule_based_check(_normalize(text))
    action = "block" if bool(result["blocked"]) else "observe"
    return str(result["label"]), action, float(result["risk_score"])


def _inspect_semantic(text: str) -> tuple[str, str, float]:
    result = semantic_check(_normalize(text))
    return str(result["label"]), "observe", float(result["score"])


def _inspect_ml(text: str) -> tuple[str, str, float]:
    result = ml_check(_normalize(text))
    return str(result["label"]), "observe", float(result["score"])


def _inspect_hybrid(
    text: str,
    *,
    hybrid: HybridFirewall,
) -> tuple[str, str, float]:
    result = hybrid.inspect_text(text, max_content_bytes=16_000)
    return result.label, result.action, result.risk_score


def run_protected_pipeline(
    case: EvaluationCase,
    *,
    dependencies: PipelineDependencies | None = None,
) -> ModeObservation:
    dependencies = dependencies or PipelineDependencies()
    input_decision = dependencies.input_inspector(case.content)
    classification = str(getattr(input_decision, "classification"))
    action = str(getattr(input_decision, "action"))
    risk_score = float(getattr(input_decision, "risk_score"))
    if action not in _CONTINUE_ACTIONS:
        return _stopped_observation(classification, action, risk_score)

    dependencies.database_call(case)
    database_called = True
    rbac_denied = _rbac_denied(case, dependencies)
    if rbac_denied:
        return ModeObservation(
            classification=classification,
            action="rbac_deny",
            risk_score=risk_score,
            database_called=database_called,
            execution_measured=True,
            rbac_denied=True,
            llmguard_restricted=False,
        )

    retrieval_called = False
    if case.requires_retrieval:
        dependencies.retrieval_call(case)
        retrieval_called = True

    attack_neutralized = False
    if case.stage == "context":
        context_decision = dependencies.context_inspector(
            [
                {
                    "source_id": chunk.source_id,
                    "chunk_id": chunk.chunk_id,
                    "text": chunk.text,
                    "metadata": {"synthetic_evaluation": True},
                }
                for chunk in case.chunks
            ]
        )
        classification = str(getattr(context_decision, "classification"))
        action = str(getattr(context_decision, "action"))
        risk_score = float(getattr(context_decision, "risk_score"))
        sanitized_chunks = getattr(context_decision, "sanitized_chunks", None)
        if action == "sanitize" and sanitized_chunks:
            attack_neutralized = True
        elif action not in _CONTINUE_ACTIONS:
            return ModeObservation(
                classification=classification,
                action=action,
                risk_score=risk_score,
                database_called=database_called,
                retrieval_called=retrieval_called,
                execution_measured=True,
                llmguard_restricted=True,
            )

    tool_called = False
    if case.requires_tool:
        dependencies.tool_call(case)
        tool_called = True

    generated = dependencies.main_llm_call(case)
    main_llm_called = True
    output_decision = dependencies.output_inspector(
        generated,
        {"user_role": case.channel, "allowed_classifications": ["public"]},
    )
    output_action = str(getattr(output_decision, "action"))
    if output_action not in _CONTINUE_ACTIONS:
        classification = str(getattr(output_decision, "classification"))
        action = output_action
        risk_score = float(getattr(output_decision, "risk_score"))

    attack_success = (
        case.expected_label == "malicious"
        and not attack_neutralized
        and (tool_called or main_llm_called)
    )
    return ModeObservation(
        classification=classification,
        action=action,
        risk_score=risk_score,
        database_called=database_called,
        retrieval_called=retrieval_called,
        tool_called=tool_called,
        main_llm_called=main_llm_called,
        attack_success=attack_success,
        malicious_downstream_execution=_malicious_downstream_execution(
            case,
            database_called=database_called,
            tool_called=tool_called,
            main_llm_called=main_llm_called,
        ),
        execution_measured=True,
        llmguard_restricted=(
            attack_neutralized or output_action not in _CONTINUE_ACTIONS
        ),
    )


def run_bypassed_pipeline(
    case: EvaluationCase,
    *,
    dependencies: PipelineDependencies | None = None,
) -> ModeObservation:
    dependencies = dependencies or PipelineDependencies()
    dependencies.database_call(case)
    database_called = True
    rbac_denied = _rbac_denied(case, dependencies)
    if rbac_denied:
        return ModeObservation(
            classification="bypassed",
            action="rbac_deny",
            risk_score=None,
            database_called=database_called,
            execution_measured=True,
            rbac_denied=True,
        )

    retrieval_called = False
    if case.requires_retrieval:
        dependencies.retrieval_call(case)
        retrieval_called = True
    tool_called = False
    if case.requires_tool:
        dependencies.tool_call(case)
        tool_called = True
    dependencies.main_llm_call(case)
    main_llm_called = True
    return ModeObservation(
        classification="bypassed",
        action="bypassed",
        risk_score=None,
        database_called=database_called,
        retrieval_called=retrieval_called,
        tool_called=tool_called,
        main_llm_called=main_llm_called,
        attack_success=(
            case.expected_label == "malicious"
            and (tool_called or main_llm_called)
        ),
        malicious_downstream_execution=_malicious_downstream_execution(
            case,
            database_called=database_called,
            tool_called=tool_called,
            main_llm_called=main_llm_called,
        ),
        execution_measured=True,
    )


def _stopped_observation(
    classification: str,
    action: str,
    risk_score: float,
) -> ModeObservation:
    return ModeObservation(
        classification=classification,
        action=action,
        risk_score=risk_score,
        execution_measured=True,
        llmguard_restricted=True,
    )


def _rbac_denied(case: EvaluationCase, dependencies: PipelineDependencies) -> bool:
    if dependencies.rbac_checker is not None:
        return bool(dependencies.rbac_checker(case))
    return _real_university_rbac_denied(case)


def _real_university_rbac_denied(case: EvaluationCase) -> bool:
    student = (
        SimpleNamespace(student_id="UOH-DEMO-STU-0001")
        if case.channel == "student"
        else None
    )
    identity = ChatIdentity(
        portal_context=case.channel,
        owner_ref=f"phase14a-{case.channel}",
        student=student,
    )
    return access_restriction(identity, case.content) is not None


def _malicious_downstream_execution(
    case: EvaluationCase,
    *,
    database_called: bool,
    tool_called: bool,
    main_llm_called: bool,
) -> bool:
    if case.expected_label != "malicious":
        return False
    if case.stage == "input":
        return database_called or tool_called or main_llm_called
    return tool_called or main_llm_called
