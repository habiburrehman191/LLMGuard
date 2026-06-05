from __future__ import annotations

from app.llmguard.risk_engine import StageSignal, signal
from app.tool_firewall import ToolDecision, tool_firewall_decision


def inspect_tool_call(
    prompt: str,
    *,
    user_role: str | None = None,
    user_id: str | None = None,
    tool_name: str | None = None,
) -> StageSignal:
    target_prompt = f"{prompt} {tool_name or ''}".strip()
    normalized_role = "staff" if user_role == "employee" else user_role
    decision: ToolDecision = tool_firewall_decision(
        target_prompt,
        user_role=normalized_role,
        user_id=user_id,
    )
    return signal(
        "tool_call_inspection",
        label=decision.label,
        action=decision.action,
        score=decision.risk_score,
        reasons=[decision.reason],
        threat_source="tool_call" if not decision.allowed else "none",
        metadata=decision.as_dict(),
    )
