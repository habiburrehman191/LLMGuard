import re

DANGEROUS_PATTERNS = [
    "ignore previous instructions",
    "reveal system prompt",
    "bypass policy",
    "disclose confidential data",
    "ignore all prior rules",
    "leak confidential information",
    "show hidden instructions",
    "reveal confidential employee records",
    "disregard earlier rules",
    "show hidden system data",
    "override existing instructions",
    "expose private information",
]

SUSPICIOUS_PATTERNS = [
    "hidden instructions",
    "system instructions",
    "internal guidance",
    "confidential records",
    "private data",
    "protected records",
    "security controls",
    "prior constraints",
    "earlier guardrails",
    "bypass controls",
]


def rule_based_check(text: str):
    lowered = text.lower()

    for pattern in DANGEROUS_PATTERNS:
        if pattern in lowered:
            return {
                "blocked": True,
                "reason": f"Matched dangerous pattern: '{pattern}'",
                "risk_score": 0.98,
                "matched_pattern": pattern,
                "label": "malicious",
            }

    for pattern in SUSPICIOUS_PATTERNS:
        if pattern in lowered:
            return {
                "blocked": False,
                "reason": f"Matched suspicious pattern: '{pattern}'",
                "risk_score": 0.45,
                "matched_pattern": pattern,
                "label": "suspicious",
            }

    return {
        "blocked": False,
        "reason": "No dangerous rule-based pattern detected",
        "risk_score": 0.05,
        "matched_pattern": None,
        "label": "safe",
    }


def sanitize_text(text: str):
    sentences = re.split(r'(?<=[.!?])\s+', text)
    safe_sentences = []

    for sentence in sentences:
        sentence_lower = sentence.lower()
        is_dangerous = any(pattern in sentence_lower for pattern in DANGEROUS_PATTERNS)
        is_suspicious = any(pattern in sentence_lower for pattern in SUSPICIOUS_PATTERNS)

        if not is_dangerous and not is_suspicious:
            safe_sentences.append(sentence)

    if not safe_sentences:
        return "[REMOVED: malicious content detected]"

    return " ".join(safe_sentences)
