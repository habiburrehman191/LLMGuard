from __future__ import annotations

from dataclasses import dataclass

from app.access_control import normalize_role

APPROVED_SYNTHETIC_STUDENT_IDS = {
    "student": {"demo-uoh-app-2026-021", "uoh-demo-app-2026-021", "nbu-syn-24017"},
}

TOOL_DESCRIPTIONS = {
    "public_policy_search": "Search public university policy pages.",
    "public_program_lookup": "Lookup public university program information.",
    "public_helpdesk_info": "Return public portal help desk guidance.",
    "student_self_status_lookup": "Lookup an approved own synthetic student/application record.",
    "synthetic_student_self_lookup": "Legacy alias for approved own synthetic student/application lookup.",
    "staff_directory_lookup": "Lookup synthetic staff directory information.",
    "restricted_student_record_lookup": "Lookup restricted synthetic student records.",
    "exam_record_lookup": "Lookup synthetic confidential exam records.",
    "finance_budget_lookup": "Lookup synthetic confidential finance and budget records.",
    "finance_record_lookup": "Legacy alias for synthetic confidential finance records.",
    "contract_lookup": "Lookup synthetic confidential vendor contracts.",
    "admin_note_lookup": "Lookup synthetic admin-only notes.",
    "admin_secret_lookup": "Lookup synthetic admin token placeholders.",
}


@dataclass(frozen=True)
class ToolDecision:
    name: str
    allowed: bool
    action: str
    label: str
    risk_score: float
    reason: str
    result: str | None = None

    def as_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "description": TOOL_DESCRIPTIONS.get(self.name, ""),
            "allowed": self.allowed,
            "action": self.action,
            "label": self.label,
            "risk_score": self.risk_score,
            "reason": self.reason,
            "result": self.result,
        }


def infer_tool_name(prompt: str) -> str:
    lowered = prompt.lower()
    if any(term in lowered for term in ("admin_secret_lookup", "admin token", "api key", "credentials", ".env", "secret")):
        return "admin_secret_lookup"
    if any(term in lowered for term in ("admin_note_lookup", "admin notes", "internal admin notes", "portal rules", "admin portal")):
        return "admin_note_lookup"
    if any(term in lowered for term in ("contract_lookup", "vendor contract", "contracts", "procurement contract")):
        return "contract_lookup"
    if any(term in lowered for term in ("finance_budget_lookup", "finance_record_lookup", "budget", "budget summary", "fee status", "finance record", "fee ledger")):
        return "finance_budget_lookup"
    if any(term in lowered for term in ("exam_record_lookup", "exam records", "exam marks", "grade sheet", "result ledger")):
        return "exam_record_lookup"
    if any(term in lowered for term in ("restricted_student_record_lookup", "student private records", "all student records", "student portal records", "portal records")):
        return "restricted_student_record_lookup"
    if any(term in lowered for term in ("student_self_status_lookup", "synthetic_student_self_lookup", "application status", "my portal record", "my student record", "my challan")):
        return "student_self_status_lookup"
    if any(term in lowered for term in ("staff_directory_lookup", "staff directory", "teacher office", "office hours")):
        return "staff_directory_lookup"
    if any(term in lowered for term in ("program", "programs", "department", "bs ", "bachelor")):
        return "public_program_lookup"
    if any(term in lowered for term in ("help desk", "helpdesk", "portal help", "password reset", "login issue")):
        return "public_helpdesk_info"
    return "public_policy_search"


def _blocked(name: str, reason: str, risk_score: float = 0.94, label: str = "malicious") -> ToolDecision:
    return ToolDecision(
        name=name,
        allowed=False,
        action="block",
        label=label,
        risk_score=risk_score,
        reason=reason,
    )


def _allowed(name: str, reason: str, result: str | None = None) -> ToolDecision:
    return ToolDecision(
        name=name,
        allowed=True,
        action="allow",
        label="safe",
        risk_score=0.05,
        reason=reason,
        result=result,
    )


def _prompt_has_own_synthetic_id(prompt: str, user_id: str | None) -> bool:
    lowered = prompt.lower()
    candidates = set(APPROVED_SYNTHETIC_STUDENT_IDS["student"])
    if user_id:
        normalized_user_id = user_id.lower()
        if normalized_user_id in candidates and "all " not in lowered:
            return True
        candidates.add(normalized_user_id)
    return any(candidate in lowered for candidate in candidates)


def tool_firewall_decision(
    prompt: str,
    *,
    user_role: str | None = None,
    user_id: str | None = None,
) -> ToolDecision:
    role = normalize_role(user_role)
    tool_name = infer_tool_name(prompt)

    if tool_name in {"public_policy_search", "public_program_lookup", "public_helpdesk_info"}:
        return _allowed(tool_name, "Public tool is allowed for every role.")

    if tool_name == "admin_secret_lookup":
        return _blocked(
            tool_name,
            "admin_secret_lookup is always blocked; secrets and token placeholders are never exposed.",
            risk_score=0.99,
        )

    if tool_name == "restricted_student_record_lookup":
        return _blocked(
            tool_name,
            "Restricted student record lookup is blocked by default. Use own synthetic self lookup only where authorized.",
            risk_score=0.96,
        )

    if tool_name == "student_self_status_lookup":
        if role == "student" and _prompt_has_own_synthetic_id(prompt, user_id):
            return _allowed(
                tool_name,
                "Student role may access only the approved own synthetic demo record.",
                result=(
                    "SYNTHETIC DEMO DATA — NOT REAL UNIVERSITY DATA. "
                    "DEMO-UOH-APP-2026-021: application submitted; challan received; merit review pending."
                ),
            )
        if role == "super_admin":
            return _allowed(tool_name, "super_admin may inspect synthetic student self records in this demo.")
        return _blocked(
            tool_name,
                "student_self_status_lookup requires student role with the approved own synthetic ID.",
            risk_score=0.82,
            label="suspicious",
        )

    if tool_name == "staff_directory_lookup":
        if role in {"teacher", "staff", "admission_officer", "exam_controller", "finance_admin", "super_admin"}:
            return _allowed(tool_name, f"{role} may access synthetic staff directory information.")
        return _blocked(tool_name, f"{role} is not allowed to use staff_directory_lookup.", risk_score=0.78, label="suspicious")

    if tool_name == "exam_record_lookup":
        if role in {"exam_controller", "super_admin"}:
            return _allowed(tool_name, f"{role} may access synthetic exam records.")
        return _blocked(tool_name, f"{role} is not allowed to use exam_record_lookup.")

    if tool_name in {"finance_budget_lookup", "contract_lookup"}:
        if role in {"finance_admin", "super_admin"}:
            return _allowed(tool_name, f"{role} may access synthetic finance or contract records.")
        return _blocked(tool_name, f"{role} is not allowed to use {tool_name}.")

    if tool_name == "admin_note_lookup":
        if role == "super_admin":
            return _allowed(tool_name, "super_admin may access synthetic admin-only notes.")
        return _blocked(tool_name, f"{role} is not allowed to use admin_note_lookup.")

    return _allowed("public_policy_search", "Defaulted to public policy search.")
