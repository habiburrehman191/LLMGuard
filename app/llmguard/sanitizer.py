from __future__ import annotations

import base64
import re

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


def decode_base64_if_present(text: str) -> list[str]:
    decoded: list[str] = []
    for token in re.findall(r"\b[A-Za-z0-9+/]{16,}={0,2}\b", text):
        try:
            value = base64.b64decode(token, validate=True).decode("utf-8", errors="ignore").strip()
        except Exception:
            continue
        if value and any(term in value.lower() for term in ("ignore", "bypass", "reveal", "admin", "system")):
            decoded.append(value)
    return decoded


def sanitize_context(text: str) -> str:
    sanitized = text
    for pattern in MALICIOUS_CONTEXT_PATTERNS:
        sanitized = re.sub(pattern, "[REMOVED: unsafe retrieved instruction]", sanitized, flags=re.DOTALL)
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
