from __future__ import annotations

import re
from typing import Any

from app.llmguard.risk_engine import StageSignal, aggregate_signals, signal
from app.llmguard.sanitizer import (
    STRUCTURAL_CONTEXT_PATTERNS,
    sanitize_context,
)
from app.security_normalization import normalize_security_text

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

MAX_REASSEMBLED_CONTEXT_BYTES = 64_032
_CROSS_CHUNK_REDACTION = "[REMOVED: unsafe cross-chunk instruction]"


def inspect_context_text(
    text: str,
    *,
    chunk_id: str | None = None,
    max_content_bytes: int = 128_000,
) -> StageSignal:
    normalized = normalize_security_text(
        text,
        max_input_bytes=max_content_bytes,
        max_output_bytes=max_content_bytes,
    )
    inspection_text = normalized.inspection_content
    lowered = inspection_text.lower()
    reasons: list[str] = []
    categories: list[str] = []

    for category, patterns in CONTEXT_PATTERNS.items():
        matched = next((pattern for pattern in patterns if pattern in lowered), None)
        if matched:
            categories.append(category)
            reasons.append(f"Retrieved context matched {category}: '{matched}'.")

    for category, pattern in STRUCTURAL_CONTEXT_PATTERNS:
        if re.search(pattern, inspection_text, flags=re.DOTALL):
            if category == "instruction_override" and any(
                existing in categories
                for existing in (
                    "hidden_instruction",
                    "document_override",
                    "role_override",
                )
            ):
                continue
            if category == "bulk_sensitive_exfiltration" and "data_leakage" in categories:
                continue
            categories.append(category)
            reasons.append(
                f"Retrieved context matched structural category {category}."
            )

    if re.search(r"<!--.*?(ignore|override|bypass|reveal|admin).*?-->", inspection_text, flags=re.IGNORECASE | re.DOTALL):
        categories.append("html_comment_instruction")
        reasons.append("Retrieved context contained an HTML comment with hidden instructions.")

    if "base64_decode" in normalized.transformations:
        categories.append("encoded_payload")
        reasons.append("Retrieved context contained a confidently decoded attack instruction.")

    if not categories:
        return signal(
            "context_firewall",
            label="safe",
            action="allow",
            score=0.04,
            reasons=["Retrieved context contains no hidden override instructions."],
            metadata={
                "chunk_id": chunk_id,
                "normalization_applied": normalized.normalization_applied,
                "transformations": list(normalized.transformations),
            },
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
            "sanitized_text": sanitize_context(inspection_text),
            "normalization_applied": normalized.normalization_applied,
            "transformations": list(normalized.transformations),
        },
    )


def inspect_retrieved_chunks(
    chunks: list[dict[str, Any]],
    *,
    max_chunk_bytes: int = 128_000,
    max_reassembled_bytes: int = MAX_REASSEMBLED_CONTEXT_BYTES,
) -> StageSignal:
    signals = [
        inspect_context_text(
            str(chunk.get("chunk_text") or chunk.get("text") or ""),
            chunk_id=str(chunk.get("chunk_id") or ""),
            max_content_bytes=max_chunk_bytes,
        )
        for chunk in chunks
    ]
    reassembled_signal: StageSignal | None = None
    reassembled_contributed = False
    reassembled_metadata: dict[str, Any] | None = None
    if len(chunks) > 1:
        reassembled_text, truncated = _bounded_reassembled_text(
            chunks,
            max_bytes=max_reassembled_bytes,
        )
        inspected = inspect_context_text(
            reassembled_text,
            chunk_id="reassembled-context",
            max_content_bytes=max_reassembled_bytes,
        )
        reassembled_signal = signal(
            "reassembled_context_firewall",
            label=inspected.label,
            action=inspected.action,
            score=inspected.score,
            reasons=inspected.reasons,
            threat_source=inspected.threat_source,
            metadata={
                **inspected.metadata,
                "chunk_references": [
                    {
                        "source_id": str(chunk.get("source_id") or ""),
                        "chunk_id": str(chunk.get("chunk_id") or ""),
                    }
                    for chunk in chunks
                ],
                "reassembled_bytes": len(reassembled_text.encode("utf-8")),
                "truncated": truncated,
            },
        )
        individual_categories = {
            str(category)
            for item in signals
            for category in item.metadata.get("categories", [])
        }
        reassembled_categories = {
            str(category)
            for category in reassembled_signal.metadata.get("categories", [])
        }
        reassembled_contributed = (
            reassembled_signal.action not in {"allow", "log"}
            and (
                not any(item.action not in {"allow", "log"} for item in signals)
                or bool(reassembled_categories - individual_categories)
            )
        )
        if reassembled_contributed:
            signals.append(reassembled_signal)
        reassembled_metadata = {
            "label": reassembled_signal.label,
            "action": reassembled_signal.action,
            "score": reassembled_signal.score,
            "reassembled_bytes": reassembled_signal.metadata["reassembled_bytes"],
            "truncated": truncated,
            "contributed": reassembled_contributed,
            "chunk_references": reassembled_signal.metadata["chunk_references"],
        }

    decision = aggregate_signals(signals)
    sanitized_chunks = []
    for chunk, chunk_signal in zip(chunks, signals):
        raw_text = str(chunk.get("chunk_text") or chunk.get("text") or "")
        sanitized_text = str(
            chunk_signal.metadata.get("sanitized_text", raw_text)
        )
        if (
            reassembled_signal is not None
            and reassembled_contributed
            and reassembled_signal.action == "sanitize"
        ):
            # A reconstructed instruction cannot be mapped safely back to only one
            # chunk. Redact every participating fragment so no raw piece can be
            # rejoined after the security boundary.
            sanitized_text = _CROSS_CHUNK_REDACTION
        sanitized_chunks.append(
            {
                **chunk,
                "chunk_text": sanitized_text,
            }
        )
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
            "normalization_applied": any(
                bool(item.metadata.get("normalization_applied"))
                for item in signals
            ),
            "transformations": list(
                dict.fromkeys(
                    transformation
                    for item in signals
                    for transformation in item.metadata.get("transformations", [])
                )
            ),
            "reassembled_inspection": reassembled_metadata,
        },
    )


def _bounded_reassembled_text(
    chunks: list[dict[str, Any]],
    *,
    max_bytes: int,
) -> tuple[str, bool]:
    if max_bytes <= 0:
        raise ValueError("Reassembled context bound must be positive.")
    combined = " ".join(
        str(chunk.get("chunk_text") or chunk.get("text") or "")
        for chunk in chunks
    )
    encoded = combined.encode("utf-8")
    if len(encoded) <= max_bytes:
        return combined, False
    return encoded[:max_bytes].decode("utf-8", errors="ignore"), True
