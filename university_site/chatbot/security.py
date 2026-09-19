from __future__ import annotations

import re

from .types import ChatIdentity


APPLICATION_SECRET_PATTERNS = (
    r"password\s*hash(?:es)?",
    r"plain(?:text)?\s*passwords?",
    r"jwt\s+(?:signing\s+)?secret",
    r"session\s+cookies?",
    r"api\s+(?:key|credential|token)s?",
    r"private\s+(?:encryption\s+)?keys?",
    r"database\s+(?:password|credential)s?",
    r"environment\s+variables?",
    r"(?:system|developer|hidden)\s+(?:prompt|instructions?)",
    r"operating[- ]system\s+files?",
    r"\.env\b",
)

PUBLIC_PRIVATE_PATTERNS = (
    r"\bUOH-DEMO-STU-\d{4}\b",
    r"\bUOH-DEMO-20\d{2}-\d{4}\b",
    r"\bstudent\s+\d{1,4}(?:'s)?\s+(?:cgpa|grade|attendance|result|fee|record)",
    r"\b(?:employee|staff)\s+(?:attendance|leave|payroll|salary|private|confidential)",
    r"\b(?:internal|confidential|restricted|controlled)\s+(?:\w+\s+){0,3}(?:polic(?:y|ies)|records?|reports?|incidents?)\b",
)

STUDENT_EMPLOYEE_PATTERNS = (
    r"\b(?:another|other)\s+student(?:'s)?\s+(?:cgpa|grade|attendance|result|fee|record|information)\b",
    r"\b(?:employee|staff)\s+(?:attendance|leave|payroll|salary|private|confidential|record)",
    r"\b(?:hr|finance|security|examination)\s+(?:records?|reports?|incidents?|payroll|files?)",
    r"\b(?:internal|controlled|confidential|restricted)\s+(?:university\s+|institutional\s+)?(?:records?|reports?|incidents?|polic(?:y|ies))",
    r"\b(?:vice chancellor|registrar|security officer)'?s?\s+confidential",
    r"\b(?:list|show|display|give)(?:\s+me)?\s+(?:all\s+)?(?:the\s+)?(?:\d+\s+)?students\b",
    r"\b(?:list|show|display|give)(?:\s+me)?\s+all\s+[a-z0-9 &/-]{1,50}\s+students\b",
    r"\b(?:all|every|\d+)\s+students?\b",
    r"\bstudent\s+directory\b",
    r"\bstudents?\s+(?:in|from|of)\s+[^?.!]+(?:department|program|engineering|science|semester)\b",
    r"\bstudents\s+with\s+(?:cgpa|grades?|attendance|fees?|results?)",
    r"\b(?:show|list|display)\s+(?:all\s+)?(?:cgpas?|grades?|attendance\s+records?|student\s+results?)\b",
)

IDENTITY_OVERRIDE_PATTERNS = (
    r"\bthis\s+is\s+my\s+portal\b",
    r"\bthis\s+is\s+me\b",
    r"\b(?:that|this)\s+is\s+my\s+student\s+id\b",
    r"\bi\s+(?:am|own)\s+(?:student\s+)?UOH-DEMO",
    r"\b(?:admin(?:istrator)?|registrar)\s+(?:has\s+)?(?:gave|given|authorized|approved|permitted)\b",
    r"\bpretend\s+(?:that\s+)?i\s+am\b",
    r"\b(?:use|change|switch)\s+(?:this|my|the)?\s*student\s+id\b",
    r"\bact\s+as\s+student\b",
    r"\bignore\s+(?:the\s+)?previous\s+restriction\b",
)

BENIGN_STUDENT_FEE_PATTERNS = (
    r"\b(?:what(?:'s|\s+is)|show)\s+my\s+(?:current\s+|semester\s+)?fee(?:\s+(?:payment|voucher|record))?\s+status\b",
    r"\bhave\s+i\s+(?:cleared|paid)\s+(?:my\s+)?(?:semester\s+)?fees?\b",
    r"\bdo\s+i\s+have\s+(?:any\s+)?outstanding\s+fees?\b",
    r"\bhow\s+much\s+(?:fee\s+)?(?:is\s+)?(?:due|outstanding)\b",
    r"\bwhat\s+is\s+my\s+outstanding\s+amount\b",
    r"\bwhen\s+is\s+my\s+(?:next\s+)?fee\s+due\b",
    r"\bshow\s+my\s+fee\s+(?:record|voucher)\b",
)


def _matches(patterns: tuple[str, ...], text: str) -> bool:
    return any(re.search(pattern, text, flags=re.IGNORECASE) for pattern in patterns)


def _requested_student_numbers(question: str) -> set[int]:
    values = {
        int(match)
        for match in re.findall(r"UOH-DEMO-STU-(\d{4})", question, flags=re.IGNORECASE)
    }
    values.update(
        int(match)
        for match in re.findall(
            r"\bstudent\s+(?:demo\s*)?0*(\d{1,4})\b",
            question,
            flags=re.IGNORECASE,
        )
    )
    values.update(
        int(match)
        for match in re.findall(r"\bUOH-DEMO-20\d{2}-(\d{4})\b", question, flags=re.IGNORECASE)
    )
    values.update(
        int(match)
        for match in re.findall(r"\bstudent\.demo0*(\d{1,4})\b", question, flags=re.IGNORECASE)
    )
    return values


def is_benign_student_fee_query(question: str) -> bool:
    return _matches(BENIGN_STUDENT_FEE_PATTERNS, question)


def access_restriction(identity: ChatIdentity, question: str) -> str | None:
    if _matches(APPLICATION_SECRET_PATTERNS, question):
        return "Application authentication and configuration secrets are not available through the University AI Assistant."

    if identity.portal_context == "public" and _matches(PUBLIC_PRIVATE_PATTERNS, question):
        return "That information is not available through the public university assistant."

    if identity.portal_context == "student":
        if _matches(IDENTITY_OVERRIDE_PATTERNS, question):
            return "Your Student Portal identity is fixed by your authenticated session and cannot be changed through chat."
        if _matches(STUDENT_EMPLOYEE_PATTERNS, question):
            return "I can't provide other students' or employee institutional records from your Student Portal access."
        requested = _requested_student_numbers(question)
        own_number = int(identity.student.student_id.rsplit("-", 1)[-1]) if identity.student else -1
        if requested and requested != {own_number}:
            return "I can't provide another student's private information from your Student Portal access."

    return None


def inspect_prompt_with_llmguard(question: str, identity: ChatIdentity) -> str | None:
    """Use the existing read-only detector without writing into LLMGuard storage."""
    try:
        from app.llmguard.pipeline import inspect_prompt

        role = {
            "public": "public_user",
            "student": "student",
            "employee": "super_admin",
        }[identity.portal_context]
        decision = inspect_prompt(question, user_role=role, db=None)
        if decision.action in {"block", "quarantine"}:
            reasons = [str(item).lower() for item in decision.reasons]
            benign_fee_false_positive = (
                identity.portal_context == "student"
                and is_benign_student_fee_query(question)
                and any("safe_information_request" in item for item in reasons)
                and any("dlp" in item and "fee status" in item for item in reasons)
                and any(item.startswith("no dangerous rule-based") for item in reasons)
                and any(item.startswith("no prompt attack") for item in reasons)
                and any(item.startswith("no semantic attack") for item in reasons)
                and any(item.startswith("no dynamic role") for item in reasons)
            )
            if benign_fee_false_positive:
                return None
            return "I can't process that request because it attempts to override or extract protected assistant instructions."
    except Exception:
        # The university module remains usable if optional LLMGuard ML dependencies
        # are unavailable; explicit authorization filtering still runs first.
        return None
    return None
