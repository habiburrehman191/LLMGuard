from __future__ import annotations

from dataclasses import dataclass, field

from ..models import Employee, Student


@dataclass(frozen=True)
class ChatIdentity:
    portal_context: str
    owner_ref: str
    user_id: int | None = None
    student: Student | None = None
    employee: Employee | None = None
    session_ref: str | None = None


@dataclass(frozen=True)
class SourceReference:
    source_type: str
    source_id: str
    title: str
    route: str | None = None
    classification: str = "public"
    portal_scope: str = "public"
    content: str = ""
    role_scope: str = ""


@dataclass
class RetrievalBundle:
    retrieval_type: str
    topic: str
    context: str
    sources: list[SourceReference] = field(default_factory=list)
    grounded_answer: str | None = None
    answer_status: str = "supported"
