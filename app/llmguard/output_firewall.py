from __future__ import annotations

from sqlalchemy.orm import Session

from app.llmguard.dlp import detect_sensitive_data
from app.llmguard.risk_engine import StageSignal, aggregate_signals, signal
from app.llmguard.sanitizer import redact_sensitive_output
from app.output_firewall import inspect_output as legacy_inspect_output


def inspect_generated_output(
    text: str | None,
    *,
    user_role: str | None = None,
    allowed_classifications: list[str] | None = None,
    db: Session | None = None,
) -> StageSignal:
    legacy = legacy_inspect_output(
        text,
        user_role=user_role,
        allowed_classifications=allowed_classifications,
    )
    legacy_signal = signal(
        "output_firewall_legacy",
        label=legacy.label,
        action=legacy.action,
        score=legacy.risk_score,
        reasons=legacy.reasons,
        threat_source="output" if legacy.blocked else "none",
        metadata=legacy.as_dict(),
    )
    dlp_signal = detect_sensitive_data(text or "", user_role=user_role, source="output")
    decision = aggregate_signals(
        [legacy_signal, dlp_signal],
        sanitized_text=redact_sensitive_output(text or "") if text else text,
        metadata={
            "allowed_classifications": allowed_classifications or [],
            "redacted_text": redact_sensitive_output(text or "") if text else text,
            "legacy_output_firewall": legacy.as_dict(),
            "dlp": dlp_signal.as_dict(),
            "canary_markers": legacy.canary_markers,
            "leaked_classifications": legacy.leaked_classifications,
        },
    )
    return signal(
        "output_inspection",
        label=decision.label,
        action=decision.action,
        score=decision.risk_score,
        reasons=decision.reasons,
        threat_source="output" if decision.label != "safe" else "none",
        metadata=decision.metadata | {"stage_scores": decision.stage_scores},
    )
