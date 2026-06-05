from __future__ import annotations

from datetime import datetime
import enum

from sqlalchemy import Boolean, DateTime, Enum, Float, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class UserRole(str, enum.Enum):
    student = "student"
    employee = "employee"
    super_admin = "super_admin"


class PortalScope(str, enum.Enum):
    student = "student"
    employee = "employee"
    admin = "admin"


class DataClassification(str, enum.Enum):
    public = "public"
    student_private = "student_private"
    employee_private = "employee_private"
    admin_internal = "admin_internal"
    finance_confidential = "finance_confidential"
    exam_confidential = "exam_confidential"
    restricted_secret = "restricted_secret"


class SecurityAction(str, enum.Enum):
    allow = "allow"
    sanitize = "sanitize"
    quarantine = "quarantine"
    block = "block"


class ThreatLabel(str, enum.Enum):
    safe = "safe"
    suspicious = "suspicious"
    malicious = "malicious"


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(120), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[UserRole] = mapped_column(Enum(UserRole), index=True, nullable=False)
    portal_scope: Mapped[PortalScope] = mapped_column(Enum(PortalScope), index=True, nullable=False)
    synthetic_ref: Mapped[str | None] = mapped_column(String(160), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)

    portal_records: Mapped[list["PortalRecord"]] = relationship(back_populates="owner")


class Document(Base):
    __tablename__ = "documents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    document_id: Mapped[str] = mapped_column(String(180), unique=True, index=True, nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    category: Mapped[str] = mapped_column(String(120), index=True, nullable=False)
    classification: Mapped[DataClassification] = mapped_column(Enum(DataClassification), index=True, nullable=False)
    portal_scope: Mapped[PortalScope | None] = mapped_column(Enum(PortalScope), index=True, nullable=True)
    owner_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    allowed_roles: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    source_path: Mapped[str] = mapped_column(String(600), nullable=False)
    source_filename: Mapped[str | None] = mapped_column(String(255), nullable=True)
    sha256: Mapped[str | None] = mapped_column(String(80), nullable=True)
    is_synthetic: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_quarantined: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)

    chunks: Mapped[list["DocumentChunk"]] = relationship(back_populates="document", cascade="all, delete-orphan")


class DocumentChunk(Base):
    __tablename__ = "document_chunks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    chunk_id: Mapped[str] = mapped_column(String(220), unique=True, index=True, nullable=False)
    document_pk: Mapped[int] = mapped_column(ForeignKey("documents.id"), nullable=False)
    document_id: Mapped[str] = mapped_column(String(180), index=True, nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    category: Mapped[str] = mapped_column(String(120), index=True, nullable=False)
    classification: Mapped[DataClassification] = mapped_column(Enum(DataClassification), index=True, nullable=False)
    portal_scope: Mapped[PortalScope | None] = mapped_column(Enum(PortalScope), index=True, nullable=True)
    owner_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    allowed_roles: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    source_path: Mapped[str] = mapped_column(String(600), nullable=False)
    source_filename: Mapped[str | None] = mapped_column(String(255), nullable=True)
    is_synthetic: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    chunk_index: Mapped[int] = mapped_column(Integer, nullable=False)
    chunk_text: Mapped[str] = mapped_column(Text, nullable=False)
    canary_markers: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    vector_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)

    document: Mapped[Document] = relationship(back_populates="chunks")


class PortalRecord(Base):
    __tablename__ = "portal_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    record_id: Mapped[str] = mapped_column(String(180), unique=True, index=True, nullable=False)
    portal_scope: Mapped[PortalScope] = mapped_column(Enum(PortalScope), index=True, nullable=False)
    classification: Mapped[DataClassification] = mapped_column(Enum(DataClassification), index=True, nullable=False)
    owner_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    is_synthetic: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)

    owner: Mapped[User | None] = relationship(back_populates="portal_records")


class AIInteraction(Base):
    __tablename__ = "ai_interactions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    session_id: Mapped[str | None] = mapped_column(String(180), nullable=True, index=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    user_role: Mapped[str] = mapped_column(String(80), index=True, nullable=False)
    portal_scope: Mapped[str | None] = mapped_column(String(80), index=True, nullable=True)
    prompt: Mapped[str] = mapped_column(Text, nullable=False)
    response_preview: Mapped[str | None] = mapped_column(Text, nullable=True)
    action: Mapped[SecurityAction] = mapped_column(Enum(SecurityAction), index=True, nullable=False)
    label: Mapped[ThreatLabel] = mapped_column(Enum(ThreatLabel), index=True, nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    qwen_called: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    retrieved_chunk_ids: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    unauthorized_chunk_ids: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)


class FirewallEvent(Base):
    __tablename__ = "firewall_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ai_interaction_id: Mapped[int | None] = mapped_column(ForeignKey("ai_interactions.id"), nullable=True)
    detector: Mapped[str] = mapped_column(String(120), index=True, nullable=False)
    action: Mapped[SecurityAction] = mapped_column(Enum(SecurityAction), index=True, nullable=False)
    label: Mapped[ThreatLabel] = mapped_column(Enum(ThreatLabel), index=True, nullable=False)
    score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[str | None] = mapped_column(String(120), nullable=True)
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)


class ToolCall(Base):
    __tablename__ = "tool_calls"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ai_interaction_id: Mapped[int | None] = mapped_column(ForeignKey("ai_interactions.id"), nullable=True)
    tool_name: Mapped[str] = mapped_column(String(160), index=True, nullable=False)
    requested_by_role: Mapped[str] = mapped_column(String(80), index=True, nullable=False)
    allowed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    action: Mapped[SecurityAction] = mapped_column(Enum(SecurityAction), index=True, nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    arguments_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    result_preview: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)


class RedteamCase(Base):
    __tablename__ = "redteam_cases"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    case_id: Mapped[str] = mapped_column(String(180), unique=True, index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    prompt: Mapped[str] = mapped_column(Text, nullable=False)
    attack_type: Mapped[str] = mapped_column(String(120), index=True, nullable=False)
    severity: Mapped[str] = mapped_column(String(40), index=True, nullable=False)
    expected_action: Mapped[str] = mapped_column(String(80), nullable=False)
    expected_label: Mapped[str] = mapped_column(String(80), nullable=False)
    user_role: Mapped[str] = mapped_column(String(80), nullable=False)
    portal_scope: Mapped[str | None] = mapped_column(String(80), nullable=True)
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    actor_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    actor_role: Mapped[str | None] = mapped_column(String(80), nullable=True)
    event_type: Mapped[str] = mapped_column(String(120), index=True, nullable=False)
    entity_type: Mapped[str | None] = mapped_column(String(120), nullable=True)
    entity_id: Mapped[str | None] = mapped_column(String(180), nullable=True)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
