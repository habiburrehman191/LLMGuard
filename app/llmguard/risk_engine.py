from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

ACTION_PRIORITY = {
    "allow": 0,
    "sanitize": 1,
    "quarantine": 2,
    "block": 3,
}


@dataclass(frozen=True)
class StageSignal:
    stage: str
    label: str
    action: str
    score: float
    reasons: list[str] = field(default_factory=list)
    threat_source: str = "none"
    metadata: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "stage": self.stage,
            "label": self.label,
            "action": self.action,
            "score": self.score,
            "reasons": self.reasons,
            "threat_source": self.threat_source,
            "metadata": self.metadata,
        }


@dataclass(frozen=True)
class FirewallDecision:
    label: str
    action: str
    risk_score: float
    reasons: list[str]
    threat_source: str
    stage_scores: dict[str, float]
    signals: list[StageSignal] = field(default_factory=list)
    sanitized_text: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def blocked(self) -> bool:
        return self.action in {"block", "quarantine"}

    def as_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "action": self.action,
            "risk_score": self.risk_score,
            "blocked": self.blocked,
            "reasons": self.reasons,
            "threat_source": self.threat_source,
            "stage_scores": self.stage_scores,
            "signals": [signal.as_dict() for signal in self.signals],
            "sanitized_text": self.sanitized_text,
            "metadata": self.metadata,
        }


def signal(
    stage: str,
    *,
    label: str = "safe",
    action: str = "allow",
    score: float = 0.0,
    reasons: list[str] | None = None,
    threat_source: str = "none",
    metadata: dict[str, Any] | None = None,
) -> StageSignal:
    return StageSignal(
        stage=stage,
        label=label,
        action=action,
        score=max(0.0, min(1.0, float(score))),
        reasons=reasons or [],
        threat_source=threat_source,
        metadata=metadata or {},
    )


def _label_from_score(score: float, labels: list[str]) -> str:
    if "malicious" in labels or score >= 0.82:
        return "malicious"
    if "suspicious" in labels or score >= 0.35:
        return "suspicious"
    return "safe"


def _action_from_score(score: float, actions: list[str], label: str) -> str:
    strongest = max(actions or ["allow"], key=lambda action: ACTION_PRIORITY.get(action, 0))
    if strongest in {"block", "quarantine"}:
        return strongest
    if score >= 0.90:
        return "block"
    if score >= 0.78:
        return "quarantine"
    if label == "suspicious" or score >= 0.35:
        return "sanitize"
    return "allow"


def aggregate_signals(
    signals: list[StageSignal],
    *,
    sanitized_text: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> FirewallDecision:
    if not signals:
        return FirewallDecision(
            label="safe",
            action="allow",
            risk_score=0.0,
            reasons=["No firewall signals were emitted."],
            threat_source="none",
            stage_scores={},
            sanitized_text=sanitized_text,
            metadata=metadata or {},
        )

    stage_scores = {item.stage: item.score for item in signals}
    weighted = (
        max((item.score for item in signals), default=0.0) * 0.65
        + min(1.0, sum(item.score for item in signals) / max(len(signals), 1)) * 0.35
    )
    if sum(item.label == "malicious" for item in signals) >= 2:
        weighted = max(weighted, 0.88)
    if any(item.action == "block" for item in signals):
        weighted = max(weighted, 0.92)
    elif any(item.action == "quarantine" for item in signals):
        weighted = max(weighted, 0.80)

    labels = [item.label for item in signals]
    label = _label_from_score(weighted, labels)
    action = _action_from_score(weighted, [item.action for item in signals], label)
    reasons = list(dict.fromkeys(reason for item in signals for reason in item.reasons))
    if not reasons:
        reasons = ["All advanced LLMGuard stages classified the request as safe."]
    threat_source = next(
        (item.threat_source for item in sorted(signals, key=lambda item: item.score, reverse=True) if item.threat_source != "none"),
        "none",
    )
    return FirewallDecision(
        label=label,
        action=action,
        risk_score=min(1.0, weighted),
        reasons=reasons,
        threat_source=threat_source,
        stage_scores=stage_scores,
        signals=signals,
        sanitized_text=sanitized_text,
        metadata=metadata or {},
    )
