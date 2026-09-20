from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ContextChunk:
    source_id: str
    chunk_id: str
    text: str


@dataclass(frozen=True, slots=True)
class EvaluationCase:
    case_id: str
    category: str
    expected_label: str
    stage: str
    channel: str
    content: str
    chunks: tuple[ContextChunk, ...]
    rbac_expected_denial: bool
    requires_retrieval: bool
    requires_tool: bool
    origin: str


@dataclass(frozen=True, slots=True)
class ModeObservation:
    classification: str
    action: str
    risk_score: float | None
    database_called: bool = False
    retrieval_called: bool = False
    tool_called: bool = False
    main_llm_called: bool = False
    attack_success: bool = False
    malicious_downstream_execution: bool = False
    execution_measured: bool = False
    rbac_denied: bool = False
    llmguard_restricted: bool = False


@dataclass(frozen=True, slots=True)
class CaseResult:
    mode: str
    case_id: str
    category: str
    expected_label: str
    actual_classification: str
    actual_action: str
    risk_score: float | None
    database_called: bool
    retrieval_called: bool
    tool_called: bool
    main_llm_called: bool
    attack_success: bool
    latency_ms: float
    false_positive: bool
    false_negative: bool
    execution_measured: bool
    rbac_expected_denial: bool
    rbac_denied: bool
    llmguard_restricted: bool
    malicious_downstream_execution: bool
