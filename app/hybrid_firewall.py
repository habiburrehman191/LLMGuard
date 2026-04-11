from __future__ import annotations

from dataclasses import dataclass

from app.config import get_settings
from app.firewall import sanitize_text, rule_based_check
from app.ml_firewall import MLFirewallClassifier, ml_check
from app.semantic_firewall import SemanticFirewall, semantic_check

ACTION_PRIORITY = {
    "allow": 0,
    "log": 1,
    "sanitize": 2,
    "quarantine": 3,
    "block": 4,
}


@dataclass(frozen=True)
class ChunkAssessment:
    original_text: str
    sanitized_text: str
    rule_score: float
    semantic_score: float
    ml_score: float
    risk_score: float
    rule_label: str
    semantic_label: str
    ml_label: str
    label: str
    action: str
    reasons: list[str]


class HybridFirewall:
    def __init__(
        self,
        *,
        semantic_firewall: SemanticFirewall | None = None,
        ml_classifier: MLFirewallClassifier | None = None,
    ) -> None:
        self.semantic_firewall = semantic_firewall
        self.ml_classifier = ml_classifier
        self.settings = get_settings()

    def _calibrate_component_score(self, raw_score: float, label: str) -> float:
        if label == "safe":
            return raw_score * self.settings.hybrid_safe_score_multiplier
        if label == "suspicious":
            return max(self.settings.hybrid_suspicious_score_floor, raw_score)
        return max(self.settings.hybrid_malicious_score_floor, raw_score)

    def _final_risk_score(
        self,
        *,
        rule_score: float,
        semantic_score: float,
        ml_score: float,
        rule_label: str,
        semantic_label: str,
        ml_label: str,
    ) -> float:
        weighted_score = (
            (self.settings.hybrid_rule_weight * self._calibrate_component_score(rule_score, rule_label))
            + (self.settings.hybrid_semantic_weight * self._calibrate_component_score(semantic_score, semantic_label))
            + (self.settings.hybrid_ml_weight * self._calibrate_component_score(ml_score, ml_label))
        )
        malicious_votes = sum(
            label == "malicious"
            for label in (rule_label, semantic_label, ml_label)
        )
        suspicious_votes = sum(
            label in {"suspicious", "malicious"}
            for label in (rule_label, semantic_label, ml_label)
        )
        semantic_supports_attack = (
            semantic_label in {"suspicious", "malicious"}
            or semantic_score >= self.settings.hybrid_semantic_support_threshold
        )

        if rule_label == "malicious":
            weighted_score = max(weighted_score, self.settings.block_risk_threshold)
        elif malicious_votes >= 2:
            weighted_score = max(weighted_score, self.settings.quarantine_risk_threshold)
        elif ml_label == "malicious" and semantic_supports_attack:
            weighted_score = max(weighted_score, self.settings.hybrid_malicious_score_floor)
        elif suspicious_votes >= 2:
            weighted_score = max(
                weighted_score,
                max(
                    self.settings.hybrid_suspicious_score_floor,
                    self.settings.suspicious_risk_threshold + 0.06,
                ),
            )

        return min(1.0, weighted_score)

    def _final_label(
        self,
        *,
        risk_score: float,
        rule_label: str,
        semantic_label: str,
        ml_label: str,
    ) -> str:
        malicious_votes = sum(
            label == "malicious"
            for label in (rule_label, semantic_label, ml_label)
        )
        suspicious_votes = sum(
            label in {"suspicious", "malicious"}
            for label in (rule_label, semantic_label, ml_label)
        )
        semantic_supports_attack = semantic_label in {"suspicious", "malicious"}

        if (
            rule_label == "malicious" or
            malicious_votes >= 2 or
            (ml_label == "malicious" and semantic_supports_attack) or
            risk_score >= self.settings.malicious_risk_threshold
        ):
            return "malicious"
        if (
            rule_label == "suspicious" or
            suspicious_votes >= 2 or
            risk_score >= self.settings.suspicious_risk_threshold
        ):
            return "suspicious"
        return "safe"

    def _action_for_label(
        self,
        *,
        rule_label: str,
        label: str,
        risk_score: float,
        semantic_label: str,
        ml_label: str,
    ) -> str:
        if rule_label == "malicious" or risk_score >= self.settings.block_risk_threshold:
            return "block"
        if label == "malicious" and (
            risk_score >= self.settings.quarantine_risk_threshold or
            ml_label == "malicious" or
            semantic_label == "malicious"
        ):
            return "quarantine"
        if label in {"suspicious", "malicious"}:
            return "sanitize"
        if risk_score >= 0.18:
            return "log"
        return "allow"

    def inspect_text(self, text: str) -> ChunkAssessment:
        rule_result = rule_based_check(text)
        semantic_result = semantic_check(text, firewall=self.semantic_firewall)
        ml_result = ml_check(text, classifier=self.ml_classifier)

        risk_score = self._final_risk_score(
            rule_score=float(rule_result["risk_score"]),
            semantic_score=float(semantic_result["score"]),
            ml_score=float(ml_result["score"]),
            rule_label=str(rule_result["label"]),
            semantic_label=str(semantic_result["label"]),
            ml_label=str(ml_result["label"]),
        )
        label = self._final_label(
            risk_score=risk_score,
            rule_label=str(rule_result["label"]),
            semantic_label=str(semantic_result["label"]),
            ml_label=str(ml_result["label"]),
        )
        action = self._action_for_label(
            rule_label=str(rule_result["label"]),
            label=label,
            risk_score=risk_score,
            semantic_label=str(semantic_result["label"]),
            ml_label=str(ml_result["label"]),
        )

        reasons: list[str] = []
        if rule_result["label"] != "safe":
            reasons.append(str(rule_result["reason"]))
        if semantic_result["label"] != "safe":
            reasons.append(
                "Semantic signal matched "
                f"'{semantic_result['matched_pattern']}' via {semantic_result['backend']}"
            )
        if ml_result["label"] != "safe":
            reasons.append(
                "ML classifier labeled content as "
                f"{ml_result['label']} with confidence {ml_result['confidence']:.2f}"
            )
        if not reasons:
            reasons.append("All hybrid firewall layers classified the content as safe")

        sanitized_text = text
        if action in {"sanitize", "block", "quarantine"}:
            sanitized_text = sanitize_text(text)

        return ChunkAssessment(
            original_text=text,
            sanitized_text=sanitized_text,
            rule_score=float(rule_result["risk_score"]),
            semantic_score=float(semantic_result["score"]),
            ml_score=float(ml_result["score"]),
            risk_score=risk_score,
            rule_label=str(rule_result["label"]),
            semantic_label=str(semantic_result["label"]),
            ml_label=str(ml_result["label"]),
            label=label,
            action=action,
            reasons=reasons,
        )


_default_firewall: HybridFirewall | None = None


def get_hybrid_firewall() -> HybridFirewall:
    global _default_firewall

    if _default_firewall is None:
        _default_firewall = HybridFirewall()

    return _default_firewall


def inspect_with_hybrid_firewall(
    text: str,
    *,
    firewall: HybridFirewall | None = None,
) -> ChunkAssessment:
    active_firewall = firewall or get_hybrid_firewall()
    return active_firewall.inspect_text(text)
