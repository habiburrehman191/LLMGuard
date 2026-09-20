from __future__ import annotations

from datetime import datetime
import hashlib
import re

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from ..data import (
    BS_PROGRAMS,
    ELIGIBILITY_ROWS,
    FACILITIES,
    FEE_ROWS,
    MS_PROGRAMS,
    PHD_PROGRAMS,
    PUBLIC_INFORMATION_PAGES,
    SCHEDULE_ROWS,
    SCHOLARSHIPS,
)
from ..models import ChatKnowledgeChunk, ControlledRecord, Department, Notice, Policy, Program
from .ingestion_firewall import inspect_sources_before_index


STUDENT_POLICY_CATEGORIES = {
    "Student Academic",
    "Library",
    "Hostel",
    "Transport",
    "Health and Safety",
    "Laboratory",
}


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")


def _chunk(
    source_id: str,
    source_type: str,
    title: str,
    content: str,
    portal_scope: str,
    classification: str,
    route: str | None = None,
    department_id: int | None = None,
    role_scope: str = "",
) -> dict[str, object]:
    cleaned = " ".join(content.split())
    return {
        "source_id": source_id,
        "source_type": source_type,
        "title": title,
        "content": cleaned,
        "portal_scope": portal_scope,
        "classification": classification,
        "route": route,
        "department_id": department_id,
        "role_scope": role_scope,
        "content_hash": hashlib.sha256(cleaned.encode("utf-8")).hexdigest(),
        "updated_at": datetime(2026, 8, 19, 0, 0, 0),
    }


def source_documents(session: Session) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []

    for slug, (heading, paragraphs, items) in PUBLIC_INFORMATION_PAGES.items():
        rows.append(_chunk(
            f"public-page:{slug}", "public_page", heading,
            " ".join([*paragraphs, *items]), "public", "public",
            f"/university/information/{slug}",
        ))

    for level, groups, route in (
        ("BS", BS_PROGRAMS, "/university/admissions/bs-programs"),
        ("MS/MPhil", MS_PROGRAMS, "/university/admissions/ms-programs"),
        ("PhD", PHD_PROGRAMS, "/university/admissions/phd-programs"),
    ):
        for faculty, programs in groups.items():
            rows.append(_chunk(
                f"admissions:{level.lower()}:{_slug(faculty)}", "program", f"{level} Programs — {faculty}",
                f"{faculty} offers these {level} programs: {', '.join(programs)}.",
                "public", "public", route,
            ))

    for index, (department, program, criteria) in enumerate(ELIGIBILITY_ROWS, start=1):
        rows.append(_chunk(
            f"admissions:eligibility:{index:02d}", "admissions", f"Eligibility — {program}",
            f"Department: {department}. Program: {program}. Eligibility: {criteria}",
            "public", "public", "/university/admissions/eligibility",
        ))
    for index, (faculty, program, first, later) in enumerate(FEE_ROWS, start=1):
        rows.append(_chunk(
            f"admissions:fee:{index:02d}", "admissions", f"Fee Structure — {program}",
            f"Faculty: {faculty}. Program: {program}. First semester PKR {first}; subsequent semesters PKR {later}.",
            "public", "public", "/university/admissions/fee",
        ))
    for index, (activity, schedule_date) in enumerate(SCHEDULE_ROWS, start=1):
        rows.append(_chunk(
            f"admissions:schedule:{index:02d}", "admissions", activity,
            f"Admissions Fall 2026: {activity} — {schedule_date}.",
            "public", "public", "/university/admissions/schedule",
        ))
    for index, item in enumerate(SCHOLARSHIPS, start=1):
        rows.append(_chunk(
            f"admissions:scholarship:{index:02d}", "admissions", item, item,
            "public", "public", "/university/admissions/scholarships",
        ))
    for index, item in enumerate(FACILITIES, start=1):
        rows.append(_chunk(
            f"public:facility:{index:02d}", "public_page", f"University Facility {index}", item,
            "public", "public", "/university/admissions/facilities",
        ))

    departments = list(session.scalars(select(Department).order_by(Department.id)))
    for department in departments:
        rows.append(_chunk(
            f"department:{department.id}", "department", f"Department of {department.name}",
            f"{department.description} Academic office: {department.office}. Public contact: {department.contact_email}.",
            "public", "public", f"/university/departments/{department.slug}", department.id,
        ))
    for program in session.scalars(select(Program).order_by(Program.id)):
        rows.append(_chunk(
            f"program:{program.id}", "program", program.name,
            f"{program.name} is a {program.degree_level} program with a duration of {program.duration_years} years and status {program.status}.",
            "public", "public", f"/university/departments/{program.department.slug}" if program.department else "/university/academics", program.department_id,
        ))
    for notice in session.scalars(select(Notice).where(Notice.scope == "PUBLIC").order_by(Notice.id)):
        rows.append(_chunk(
            f"notice:public:{notice.id}", "notice", notice.title, notice.body,
            "public", "public", "/",
        ))

    for policy in session.scalars(select(Policy).order_by(Policy.policy_id)):
        content = " ".join([
            f"Policy {policy.policy_id}: {policy.title}.", f"Category: {policy.category}.",
            f"Purpose: {policy.purpose}", f"Scope: {policy.scope}",
            f"Responsibilities: {policy.responsibilities}", f"Rules: {policy.rules}",
            f"Procedures: {policy.procedures}", f"Violation handling: {policy.violation_handling}",
        ])
        if policy.classification == "PUBLIC":
            rows.append(_chunk(
                f"policy:public:{policy.policy_id}", "policy", policy.title, content,
                "public", "public", f"/university/policies/{policy.policy_id}",
            ))
        if policy.category in STUDENT_POLICY_CATEGORIES:
            rows.append(_chunk(
                f"policy:student:{policy.policy_id}", "policy", policy.title, content,
                "student", "student_self",
                f"/university/policies/{policy.policy_id}" if policy.classification == "PUBLIC" else None,
            ))
        rows.append(_chunk(
            f"policy:employee:{policy.policy_id}", "policy", policy.title, content,
            "employee", "admin_only",
            f"/university/policies/{policy.policy_id}" if policy.classification == "PUBLIC" else None,
            role_scope=policy.allowed_roles,
        ))

    for record in session.scalars(select(ControlledRecord).order_by(ControlledRecord.id)):
        rows.append(_chunk(
            f"controlled:{record.record_code}", "controlled_record", record.title,
            f"Record {record.record_code}. Category: {record.category}. Classification: {record.classification}. Summary: {record.summary} Details: {record.body}",
            "employee", "admin_only", None, role_scope=record.allowed_roles,
        ))
    return rows


def _prepared_documents(session: Session) -> list[dict[str, object]]:
    documents = source_documents(session)
    source_ids = [str(item["source_id"]) for item in documents]
    if len(source_ids) != len(set(source_ids)):
        raise RuntimeError("Duplicate chatbot source IDs were generated.")
    return inspect_sources_before_index(documents)


def _replace_knowledge_index(
    session: Session,
    documents: list[dict[str, object]],
) -> dict[str, int]:
    session.execute(delete(ChatKnowledgeChunk))
    if documents:
        session.add_all(ChatKnowledgeChunk(**item) for item in documents)
    session.commit()
    counts = {"public": 0, "student": 0, "employee": 0}
    for item in documents:
        counts[str(item["portal_scope"])] += 1
    return counts | {"total": len(documents), "duplicate_source_ids": 0}


def rebuild_knowledge_index(session: Session) -> dict[str, int]:
    return _replace_knowledge_index(session, _prepared_documents(session))


def ensure_knowledge_index(session: Session) -> dict[str, int]:
    expected = _prepared_documents(session)
    current = {
        item.source_id: item.content_hash
        for item in session.scalars(select(ChatKnowledgeChunk))
    }
    expected_hashes = {str(item["source_id"]): str(item["content_hash"]) for item in expected}
    if current != expected_hashes:
        return _replace_knowledge_index(session, expected)
    counts = {"public": 0, "student": 0, "employee": 0}
    for item in expected:
        counts[str(item["portal_scope"])] += 1
    return counts | {"total": len(expected), "duplicate_source_ids": 0}


if __name__ == "__main__":
    from ..database import SessionLocal
    from ..seed import ensure_seeded
    from .vector_store import rebuild_vector_indexes

    ensure_seeded()
    with SessionLocal() as database:
        counts = rebuild_knowledge_index(database)
        vectors = rebuild_vector_indexes(database)
    print({"knowledge": counts, "vectors": vectors})
