from __future__ import annotations

from collections import Counter
from datetime import datetime
from functools import partial
import logging
import re
from time import perf_counter

from anyio import from_thread
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session, joinedload

from ..models import ChatConversation, ChatFeedback, ChatMessage, ChatSource
from .context_firewall import inspect_chat_context
from .input_firewall import GENERIC_BLOCKED_MESSAGE, GENERIC_FAILURE_MESSAGE
from .llm import LLMUnavailable, generate_answer
from .output_firewall import inspect_chat_output
from .retrieval import retrieve
from .security import access_restriction, inspect_prompt_with_llmguard
from .types import ChatIdentity, RetrievalBundle, SourceReference


LOGGER = logging.getLogger("university_site.chatbot")


def _conversation(session: Session, identity: ChatIdentity, conversation_id: int | None) -> ChatConversation:
    if conversation_id is not None:
        conversation = session.scalar(select(ChatConversation).where(
            ChatConversation.id == conversation_id,
            ChatConversation.portal_context == identity.portal_context,
            ChatConversation.owner_ref == identity.owner_ref,
        ))
        if conversation is None:
            raise PermissionError("Conversation is not available to this user.")
        return conversation
    now = datetime.now()
    conversation = ChatConversation(
        portal_context=identity.portal_context,
        owner_ref=identity.owner_ref,
        user_id=identity.user_id,
        title="New conversation",
        created_at=now,
        updated_at=now,
    )
    session.add(conversation)
    session.flush()
    return conversation


def create_conversation(session: Session, identity: ChatIdentity, title: str = "New conversation") -> ChatConversation:
    conversation = _conversation(session, identity, None)
    conversation.title = title.strip()[:180] or "New conversation"
    session.commit()
    return conversation


def _history(session: Session, conversation: ChatConversation) -> list[str]:
    messages = list(session.scalars(
        select(ChatMessage)
        .where(ChatMessage.conversation_id == conversation.id)
        .order_by(ChatMessage.id.desc())
        .limit(8)
    ))
    return [f"{item.role.title()}: {item.content[:700]}" for item in reversed(messages)]


def _llmguard_context_block(bundle: RetrievalBundle, identity: ChatIdentity) -> bool:
    if not bundle.sources:
        return False
    try:
        from app.llmguard.pipeline import inspect_retrieved_context

        role = {"public": "public_user", "student": "student", "employee": "super_admin"}[identity.portal_context]
        chunks = [
            {
                "chunk_id": item.source_id,
                "document_id": item.source_id,
                "chunk_text": item.content,
                "classification": item.classification,
                "portal_scope": item.portal_scope,
                "owner_user_id": None,
                "is_synthetic": True,
            }
            for item in bundle.sources
        ]
        return inspect_retrieved_context(chunks, user_role=role, db=None).action in {"block", "quarantine"}
    except Exception:
        return False


def _safe_output(answer: str, bundle: RetrievalBundle, identity: ChatIdentity) -> str | None:
    try:
        from app.llmguard.pipeline import inspect_output

        role = {"public": "public_user", "student": "student", "employee": "super_admin"}[identity.portal_context]
        decision = inspect_output(
            answer,
            user_role=role,
            allowed_classifications=list({item.classification for item in bundle.sources}),
            db=None,
        )
        if decision.action in {"block", "quarantine"}:
            return None
        if decision.action == "sanitize":
            redacted = decision.metadata.get("redacted_text")
            return str(redacted) if redacted else answer
    except Exception:
        pass
    return answer


def _output_security_context(
    bundle: RetrievalBundle,
    identity: ChatIdentity,
) -> dict[str, object]:
    role = {
        "public": "public_user",
        "student": "student",
        "employee": "super_admin",
    }[identity.portal_context]
    return {
        "user_role": role,
        "actor_ref": identity.owner_ref,
        "allowed_classifications": sorted(
            {item.classification for item in bundle.sources}
        ),
    }


def _authorized_source(item: SourceReference, identity: ChatIdentity) -> bool:
    if identity.portal_context == "public":
        return item.portal_scope == "public" and item.classification == "public" and not (item.route or "").startswith("/portal/")
    if identity.portal_context == "student":
        if item.portal_scope not in {"public", "student"} or item.classification not in {"public", "student_self"}:
            return False
        if (item.route or "").startswith("/portal/employee"):
            return False
        if item.source_id.startswith("student:") and identity.student and f"student:{identity.student.id}:" not in item.source_id:
            return False
        return True
    if item.portal_scope not in {"public", "student", "employee"}:
        return False
    if item.role_scope:
        role = identity.employee.role_key if identity.employee else ""
        return role in {part for part in item.role_scope.split(",") if part}
    return True


def _authorized_sources(sources: list[SourceReference], identity: ChatIdentity) -> list[SourceReference]:
    return [item for item in sources if _authorized_source(item, identity)]


def _context_from_sources(sources: list[SourceReference]) -> str:
    return "\n\n".join(
        f"SOURCE: {item.title}\n{item.content}"
        for item in sources
    )


def _model_history(history: list[str], identity: ChatIdentity) -> list[str]:
    if identity.portal_context != "student" or identity.student is None:
        return history
    own = identity.student.student_id.upper()
    safe: list[str] = []
    for item in history:
        safe.append(re.sub(
            r"UOH-DEMO-STU-\d{4}",
            lambda match: match.group(0) if match.group(0).upper() == own else "[unauthorized student reference removed]",
            item,
            flags=re.IGNORECASE,
        ))
    return safe


def _store_assistant(
    session: Session,
    conversation: ChatConversation,
    answer: str,
    status: str,
    answer_status: str,
    retrieval_type: str,
    topic: str,
    model_called: bool,
    latency_ms: int,
    sources: list[SourceReference],
) -> ChatMessage:
    message = ChatMessage(
        conversation_id=conversation.id,
        role="assistant",
        content=answer,
        status=status,
        answer_status=answer_status,
        retrieval_type=retrieval_type,
        topic=topic,
        model_called=model_called,
        latency_ms=latency_ms,
        created_at=datetime.now(),
    )
    session.add(message)
    session.flush()
    for source in dict.fromkeys(item.source_id for item in sources):
        item = next(candidate for candidate in sources if candidate.source_id == source)
        session.add(ChatSource(
            message_id=message.id,
            source_type=item.source_type,
            source_id=item.source_id,
            source_title=item.title,
            route=item.route,
        ))
    conversation.updated_at = datetime.now()
    session.commit()
    return message


def ask(
    session: Session,
    identity: ChatIdentity,
    question: str,
    conversation_id: int | None,
    current_page: str,
    page_title: str,
    *,
    request_id: str,
    protection_bypassed: bool = False,
) -> dict[str, object]:
    started = perf_counter()
    conversation = _conversation(session, identity, conversation_id)
    history = _history(session, conversation)
    user_message = ChatMessage(
        conversation_id=conversation.id,
        role="user",
        content=question,
        status="received",
        answer_status=None,
        retrieval_type=None,
        topic=None,
        model_called=False,
        latency_ms=None,
        created_at=datetime.now(),
    )
    session.add(user_message)
    if conversation.title == "New conversation":
        conversation.title = question[:72] + ("…" if len(question) > 72 else "")
    session.flush()

    restriction = access_restriction(identity, question)
    if restriction is None and not protection_bypassed:
        restriction = inspect_prompt_with_llmguard(question, identity)
    if restriction:
        latency = int((perf_counter() - started) * 1000)
        message = _store_assistant(session, conversation, restriction, "restricted", "access_restricted", "blocked", "security", False, latency, [])
        return response_payload(
            conversation,
            message,
            identity.portal_context,
            [],
            request_id=request_id,
        )

    bundle = retrieve(session, identity, question, history + [f"User: {question}"], current_page)
    bundle.sources = _authorized_sources(bundle.sources, identity)
    if bundle.sources:
        bundle.context = _context_from_sources(bundle.sources)
    if bundle.answer_status == "supported" and bundle.context and not bundle.sources:
        bundle = RetrievalBundle(
            retrieval_type="blocked", topic="security", context="", sources=[],
            grounded_answer="The retrieved record is not authorized for your current portal access.",
            answer_status="access_restricted",
        )
    model_called = False
    answer = bundle.grounded_answer
    status = bundle.answer_status
    if (
        answer is not None
        and not protection_bypassed
        and _llmguard_context_block(bundle, identity)
    ):
        answer = "I couldn't safely use the retrieved university record for this request."
        status = "access_restricted"
        bundle.sources = []
    elif answer is None:
        context_preflight = from_thread.run(
            partial(
                inspect_chat_context,
                request_id=request_id,
                channel=identity.portal_context,
                sources=bundle.sources,
            )
        )
        standalone_blocked = (
            not context_preflight.configured
            and _llmguard_context_block(bundle, identity)
        )
        if standalone_blocked:
            answer = "I couldn't safely use the retrieved university record for this request."
            status = "access_restricted"
            bundle.sources = []
        elif not context_preflight.allowed:
            answer = (
                GENERIC_FAILURE_MESSAGE
                if context_preflight.inspection_failed
                else GENERIC_BLOCKED_MESSAGE
            )
            status = (
                "unavailable"
                if context_preflight.inspection_failed
                else "access_restricted"
            )
            bundle.sources = []
        else:
            bundle.sources = list(context_preflight.sources)
            bundle.context = _context_from_sources(bundle.sources)
            try:
                page_context = f"Current local page: {page_title} ({current_page}).\n" if page_title else ""
                answer = generate_answer(identity.portal_context, question, page_context + bundle.context, _model_history(history, identity))
                model_called = True
                output_preflight = from_thread.run(
                    partial(
                        inspect_chat_output,
                        request_id=request_id,
                        channel=identity.portal_context,
                        content=answer,
                        security_context=_output_security_context(bundle, identity),
                    )
                )
                if not output_preflight.configured:
                    checked = _safe_output(answer, bundle, identity)
                    if checked is None:
                        answer = GENERIC_BLOCKED_MESSAGE
                        status = "access_restricted"
                        bundle.sources = []
                    else:
                        answer = checked
                elif not output_preflight.allowed:
                    answer = (
                        GENERIC_FAILURE_MESSAGE
                        if output_preflight.inspection_failed
                        else GENERIC_BLOCKED_MESSAGE
                    )
                    status = (
                        "unavailable"
                        if output_preflight.inspection_failed
                        else "access_restricted"
                    )
                    bundle.sources = []
                elif output_preflight.content is None:
                    answer = GENERIC_FAILURE_MESSAGE
                    status = "unavailable"
                    bundle.sources = []
                else:
                    answer = output_preflight.content
                    if output_preflight.sanitized:
                        bundle.sources = []
            except LLMUnavailable:
                answer = "The University AI Assistant is temporarily unavailable. Please try again shortly."
                status = "unavailable"
                bundle.sources = []
    latency = int((perf_counter() - started) * 1000)
    message = _store_assistant(
        session, conversation, answer or "I couldn't find that information in the university records available to me.",
        status, status, bundle.retrieval_type, bundle.topic, model_called, latency,
        _authorized_sources(bundle.sources, identity) if status == "supported" else [],
    )
    LOGGER.info(
        "chat request=%s conversation=%s portal=%s owner=%s retrieval=%s sources=%s status=%s latency_ms=%s",
        request_id, conversation.id, identity.portal_context, identity.owner_ref, bundle.retrieval_type,
        [item.source_id for item in bundle.sources], status, latency,
    )
    return response_payload(
        conversation,
        message,
        identity.portal_context,
        _authorized_sources(bundle.sources, identity) if status == "supported" else [],
        request_id=request_id,
    )


def response_payload(
    conversation: ChatConversation,
    message: ChatMessage,
    portal_context: str,
    sources: list[SourceReference],
    *,
    request_id: str,
) -> dict[str, object]:
    labels = {
        "supported": "Verified from University Records",
        "insufficient_data": "Information Not Found",
        "access_restricted": "Access Restricted",
        "unavailable": "Assistant temporarily unavailable",
    }
    status_label = labels.get(message.answer_status or "", "University assistant response")
    if message.answer_status == "supported" and len(sources) > 1:
        status_label = "Multiple University Sources"
    return {
        "conversation_id": conversation.id,
        "message_id": message.id,
        "answer": message.content,
        "status": message.answer_status,
        "status_label": status_label,
        "sources": [
            {"type": item.source_type, "category": item.source_type.replace("_", " ").title(), "id": item.source_id, "title": item.title, "route": item.route}
            for item in sources
        ],
        "portal_context": portal_context,
        "model_called": message.model_called,
        "request_id": request_id,
    }


def list_conversations(session: Session, identity: ChatIdentity) -> list[dict[str, object]]:
    rows = session.scalars(select(ChatConversation).where(
        ChatConversation.portal_context == identity.portal_context,
        ChatConversation.owner_ref == identity.owner_ref,
    ).order_by(ChatConversation.updated_at.desc()).limit(30))
    return [{"id": item.id, "title": item.title, "portal_context": item.portal_context, "created_at": item.created_at.isoformat(), "updated_at": item.updated_at.isoformat()} for item in rows]


def conversation_detail(session: Session, identity: ChatIdentity, conversation_id: int) -> dict[str, object]:
    conversation = session.scalar(
        select(ChatConversation)
        .options(joinedload(ChatConversation.messages).joinedload(ChatMessage.sources), joinedload(ChatConversation.messages).joinedload(ChatMessage.feedback))
        .where(ChatConversation.id == conversation_id, ChatConversation.portal_context == identity.portal_context, ChatConversation.owner_ref == identity.owner_ref)
    )
    if conversation is None:
        raise PermissionError("Conversation is not available to this user.")
    messages = sorted(conversation.messages, key=lambda item: item.id)
    return {
        "id": conversation.id,
        "title": conversation.title,
        "messages": [
            {
                "id": item.id,
                "role": item.role,
                "content": item.content,
                "status": item.answer_status,
                "created_at": item.created_at.isoformat(),
                "sources": [{"type": source.source_type, "id": source.source_id, "title": source.source_title, "route": source.route} for source in item.sources],
                "feedback": item.feedback[0].rating if item.feedback else None,
            }
            for item in messages
        ],
    }


def delete_conversation(session: Session, identity: ChatIdentity, conversation_id: int) -> bool:
    conversation = session.scalar(select(ChatConversation).where(
        ChatConversation.id == conversation_id,
        ChatConversation.portal_context == identity.portal_context,
        ChatConversation.owner_ref == identity.owner_ref,
    ))
    if conversation is None:
        return False
    session.delete(conversation)
    session.commit()
    return True


def record_feedback(
    session: Session,
    identity: ChatIdentity,
    message_id: int,
    rating: str,
    reason: str | None,
    comment: str | None,
) -> ChatFeedback:
    message = session.scalar(
        select(ChatMessage)
        .join(ChatConversation)
        .where(
            ChatMessage.id == message_id,
            ChatMessage.role == "assistant",
            ChatConversation.portal_context == identity.portal_context,
            ChatConversation.owner_ref == identity.owner_ref,
        )
    )
    if message is None:
        raise PermissionError("Message is not available to this user.")
    feedback = session.scalar(select(ChatFeedback).where(ChatFeedback.message_id == message_id, ChatFeedback.owner_ref == identity.owner_ref))
    if feedback is None:
        feedback = ChatFeedback(
            message_id=message_id,
            user_id=identity.user_id,
            owner_ref=identity.owner_ref,
            portal_context=identity.portal_context,
            rating=rating,
            reason=reason,
            comment=comment.strip() if comment else None,
            created_at=datetime.now(),
        )
        session.add(feedback)
    else:
        feedback.rating = rating
        feedback.reason = reason
        feedback.comment = comment.strip() if comment else None
        feedback.created_at = datetime.now()
    session.commit()
    return feedback


def analytics(session: Session) -> dict[str, object]:
    assistant_messages = list(session.scalars(select(ChatMessage).where(ChatMessage.role == "assistant")))
    feedback = list(session.scalars(select(ChatFeedback).order_by(ChatFeedback.created_at.desc())))
    portal_counts = dict(session.execute(
        select(ChatConversation.portal_context, func.count(ChatMessage.id))
        .join(ChatMessage)
        .where(ChatMessage.role == "user")
        .group_by(ChatConversation.portal_context)
    ).all())
    status_counts = Counter(item.answer_status for item in assistant_messages)
    topic_counts = Counter(item.topic for item in assistant_messages if item.topic)
    negative_reasons = Counter(item.reason for item in feedback if item.rating == "not_helpful" and item.reason)
    average_latency = round(sum(item.latency_ms or 0 for item in assistant_messages) / max(1, len(assistant_messages)))
    return {
        "total_questions": sum(portal_counts.values()),
        "portal_counts": {scope: int(portal_counts.get(scope, 0)) for scope in ("public", "student", "employee")},
        "helpful": sum(item.rating == "helpful" for item in feedback),
        "not_helpful": sum(item.rating == "not_helpful" for item in feedback),
        "no_answer_rate": round((status_counts["insufficient_data"] + status_counts["unavailable"]) * 100 / max(1, len(assistant_messages)), 1),
        "top_topics": topic_counts.most_common(8),
        "average_latency": average_latency,
        "negative_reasons": negative_reasons.most_common(8),
        "recent_feedback": feedback[:20],
    }
