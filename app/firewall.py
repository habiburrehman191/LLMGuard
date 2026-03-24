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


def rule_based_check(text: str):
    lowered = text.lower()

    for pattern in DANGEROUS_PATTERNS:
        if pattern in lowered:
            return {
                "blocked": True,
                "reason": f"Matched dangerous pattern: '{pattern}'",
                "risk_score": 0.9,
                "matched_pattern": pattern,
            }

    return {
        "blocked": False,
        "reason": "No dangerous rule-based pattern detected",
        "risk_score": 0.1,
        "matched_pattern": None,
    }


def sanitize_text(text: str):
    sentences = re.split(r'(?<=[.!?])\s+', text)
    safe_sentences = []

    for sentence in sentences:
        sentence_lower = sentence.lower()
        is_dangerous = any(pattern in sentence_lower for pattern in DANGEROUS_PATTERNS)

        if not is_dangerous:
            safe_sentences.append(sentence)

    if not safe_sentences:
        return "[REMOVED: malicious content detected]"

    return " ".join(safe_sentences)
