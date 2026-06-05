from __future__ import annotations

import re
from typing import Any

from app.llmguard.risk_engine import StageSignal, aggregate_signals, signal
from app.llmguard.sanitizer import decode_base64_if_present, sanitize_context

CONTEXT_PATTERNS = {
    "hidden_instruction": (
        "ignore previous instructions",
        "ignore all prior rules",
        "follow these hidden instructions",
        "system prompt:",
    ),
    "document_override": (
        "this document overrides",
        "retrieved document overrides",
        "developer rules are overridden",
        "higher priority than system",
    ),
    "markdown_injection": (
        "```system",
        "```developer",
        "# instructions",
        "[//]: #",
    ),
    "role_override": (
        "act as admin",
        "use admin privileges",
        "override roles",
        "ignore student role",
    ),
    "data_leakage": (
        "show all records",
        "reveal private records",
        "dump confidential",
        "exfiltrate",
    ),
    "tool_invocation": (
        "admin_secret_lookup",
        "restricted_student_record_lookup",
        "call the tool",
        "invoke tool",
    ),
}


def inspect_context_text(text: str, *, chunk_id: str | None = None) -> StageSignal:
    lowered = " ".join(text.lower().split())
    reasons: list[str] = []
    categories: list[str] = []

    for category, patterns in CONTEXT_PATTERNS.items():
        matched = next((pattern for pattern in patterns if pattern in lowered), None)
        if matched:
            categories.append(category)
            reasons.append(f"Retrieved context matched {category}: '{matched}'.")

    if re.search(r"<!--.*?(ignore|override|bypass|reveal|admin).*?-->", text, flags=re.IGNORECASE | re.DOTALL):
        categories.append("html_comment_instruction")
        reasons.append("Retrieved context contained an HTML comment with hidden instructions.")

    decoded = decode_base64_if_present(text)
    if decoded:
        categories.append("encoded_payload")
        reasons.append("Retrieved context contained base64-like encoded attack instruction.")

    if not categories:
        return signal(
            "context_firewall",
            label="safe",
            action="allow",
            score=0.04,
            reasons=["Retrieved context contains no hidden override instructions."],
            metadata={"chunk_id": chunk_id},
        )

    score = min(0.98, 0.70 + 0.08 * len(set(categories)))
    return signal(
        "context_firewall",
        label="malicious" if score >= 0.82 else "suspicious",
        action="quarantine" if score >= 0.82 else "sanitize",
        score=score,
        reasons=reasons,
        threat_source="retrieved_context",
        metadata={
            "chunk_id": chunk_id,
            "categories": list(dict.fromkeys(categories)),
            "decoded_payloads": decoded,
            "sanitized_text": sanitize_context(text),
        },
    )


def inspect_retrieved_chunks(chunks: list[dict[str, Any]]) -> StageSignal:
    signals = [
        inspect_context_text(
            str(chunk.get("chunk_text") or chunk.get("text") or ""),
            chunk_id=str(chunk.get("chunk_id") or ""),
        )
        for chunk in chunks
    ]
    decision = aggregate_signals(signals)
    sanitized_chunks = [
        {
            **chunk,
            "chunk_text": sanitize_context(str(chunk.get("chunk_text") or chunk.get("text") or "")),
        }
        for chunk in chunks
    ]
    return signal(
        "retrieved_context_inspection",
        label=decision.label,
        action=decision.action,
        score=decision.risk_score,
        reasons=decision.reasons,
        threat_source=decision.threat_source,
        metadata={
            "checked_chunks": len(chunks),
            "sanitized_chunks": sanitized_chunks,
            "stage_scores": decision.stage_scores,
        },
    )
