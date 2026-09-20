from __future__ import annotations

import re


_AUTHORIZATION_ONLY_REQUESTS = (
    re.compile(
        r"\b(?:show|display|give|return|retrieve|view|access)\b.{0,80}"
        r"\b(?:another|other|different)\s+"
        r"(?:student|employee|user|customer|patient|account(?:\s+holder)?)(?:'s)?\b"
        r".{0,80}\b(?:cgpa|grades?|attendance|results?|fees?|records?|profile|data|information)\b",
        flags=re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:use|look\s+up|search|retrieve|show|display|access)\b.{0,60}"
        r"\b(?:student|employee|user|customer|patient|account|record)\s+"
        r"(?:id|number|identifier)\b.{0,100}"
        r"\b(?:request|lookup|records?|profile|data|information)\b",
        flags=re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:list|show|display|give|return|retrieve|view|access)\b.{0,40}"
        r"\b(?:all|every)\b.{0,80}"
        r"\b(?:students?|employees?|users?|customers?|patients?|accounts?)\b",
        flags=re.IGNORECASE,
    ),
)

_SECURITY_ATTACK_MARKERS = (
    re.compile(
        r"\b(?:ignore|disregard|override|bypass|circumvent|evade|disable|remove|skip|break)\b"
        r".{0,100}\b(?:instructions?|rules?|polic(?:y|ies)|controls?|authorization|"
        r"permissions?|access|guardrails?|restrictions?|roles?)\b",
        flags=re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:act|pretend|pose)\s+as\b.{0,40}"
        r"\b(?:admin|administrator|owner|superuser|registrar|controller)\b",
        flags=re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:unrestricted|unauthorized|without\s+(?:authorization|permission|access))\b",
        flags=re.IGNORECASE,
    ),
    re.compile(r"\b(?:dump|exfiltrate|leak)\b", flags=re.IGNORECASE),
    re.compile(
        r"\b(?:system|developer|hidden)\s+(?:prompts?|instructions?|directions?)\b",
        flags=re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:password\s+hash(?:es)?|database\s+credentials?|api\s+(?:keys?|credentials?)|"
        r"access\s+tokens?|private\s+(?:encryption\s+)?keys?|signing\s+secrets?|"
        r"environment\s+variables?)\b|\.env\b",
        flags=re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:call|invoke|execute|use)\b.{0,80}"
        r"\b(?:admin|restricted|privileged)\b.{0,40}\b(?:tool|function|lookup)\b",
        flags=re.IGNORECASE,
    ),
)


def is_authorization_only_request(text: str) -> bool:
    """Identify ownership/scope requests that must be decided by application RBAC.

    This is deliberately conservative: explicit security evasion, impersonation,
    secret extraction, prompt extraction, or privileged-tool language prevents the
    authorization-only classification.
    """

    normalized = " ".join(text.split())
    if not normalized:
        return False
    if any(pattern.search(normalized) for pattern in _SECURITY_ATTACK_MARKERS):
        return False
    return any(pattern.search(normalized) for pattern in _AUTHORIZATION_ONLY_REQUESTS)
