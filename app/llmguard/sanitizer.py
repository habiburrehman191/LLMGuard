from __future__ import annotations

import re

from app.security_normalization import decode_confident_base64

MALICIOUS_CONTEXT_PATTERNS = (
    r"(?i)ignore (?:all )?(?:previous|prior|developer|system) instructions[^.!?\n]*[.!?]?",
    r"(?i)(?:this|the) document overrides[^.!?\n]*[.!?]?",
    r"(?i)override (?:portal )?(?:roles|permissions|rules)[^.!?\n]*[.!?]?",
    r"(?i)bypass access control[^.!?\n]*[.!?]?",
    r"(?i)reveal (?:hidden|system|developer) instructions[^.!?\n]*[.!?]?",
    r"(?i)use admin privileges[^.!?\n]*[.!?]?",
    r"(?i)call\s+(?:admin_secret_lookup|restricted_student_record_lookup)[^.!?\n]*[.!?]?",
    r"<!--.*?-->",
    r"```(?:prompt|system|developer)?\s*.*?(?:ignore|override|bypass|reveal).*?```",
)

# These patterns describe instruction structure rather than benchmark wording.
# The bounded spans prevent pathological matching while allowing an instruction
# reconstructed from adjacent chunks to be inspected as one sentence.
STRUCTURAL_CONTEXT_PATTERNS = (
    (
        "instruction_override",
        r"(?i)(?<!not )(?<!never )\b(?:ignore|disregard|bypass|override|set\s+aside)\b"
        r"[^.!?\n]{0,160}\b(?:instructions?|rules?|guardrails?|safeguards?|polic(?:y|ies))\b",
    ),
    (
        "bulk_sensitive_exfiltration",
        r"(?i)\b(?:reveal|show|return|dump|expose|exfiltrate|provide)\b"
        r"[^.!?\n]{0,160}\b(?:all|every)\b[^.!?\n]{0,80}"
        r"\b(?:private|confidential|restricted)\b[^.!?\n]{0,80}"
        r"\b(?:records?|data|credentials?|information)\b",
    ),
)


def decode_base64_if_present(text: str) -> list[str]:
    return list(decode_confident_base64(text))


def sanitize_context(text: str) -> str:
    sanitized = text
    for pattern in MALICIOUS_CONTEXT_PATTERNS:
        sanitized = re.sub(pattern, "[REMOVED: unsafe retrieved instruction]", sanitized, flags=re.DOTALL)
    for _, pattern in STRUCTURAL_CONTEXT_PATTERNS:
        sanitized = re.sub(
            pattern,
            "[REMOVED: unsafe retrieved instruction]",
            sanitized,
            flags=re.DOTALL,
        )
    for decoded in decode_base64_if_present(text):
        sanitized = sanitized.replace(decoded, "[REMOVED: decoded unsafe instruction]")
    sanitized = re.sub(r"\n{3,}", "\n\n", sanitized)
    return sanitized.strip()


def redact_sensitive_output(text: str) -> str:
    redacted = text
    redacted = re.sub(r"(?i)(admin token|api key|credential|password|secret)[^.\n]*", "[REDACTED SENSITIVE VALUE]", redacted)
    redacted = redacted.replace("CANARY_ADMIN_TOKEN_DEMO_ONLY", "[REDACTED CANARY]")
    redacted = redacted.replace("CANARY_INTERNAL_BUDGET_MARKER", "[REDACTED CANARY]")
    redacted = redacted.replace("CANARY_STUDENT_RECORD_MARKER", "[REDACTED CANARY]")
    return redacted
