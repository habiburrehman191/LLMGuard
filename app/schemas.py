from typing import Optional

from pydantic import BaseModel, Field


class AskRequest(BaseModel):
    prompt: str
    user_role: str = "public_user"
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    firewall_active: Optional[bool] = None


class RetrievedChunk(BaseModel):
    document_id: str = ""
    title: str = ""
    category: str = "general"
    classification: str = "public"
    allowed_roles: list[str] = Field(default_factory=list)
    is_synthetic: bool = False
    canary_markers: list[str] = Field(default_factory=list)
    document_name: str
    source_path: str
    source_set: str = "unknown"
    is_poisoned: bool = False
    chunk_id: str
    chunk_index: int
    text: str
    chunk_text: str = ""
    score: float
    raw_score: float = 0.0
    rule_score: float = 0.0
    semantic_score: float = 0.0
    ml_score: float = 0.0
    risk_score: float = 0.0
    rule_label: str = "safe"
    semantic_label: str = "safe"
    ml_label: str = "safe"
    label: str = "safe"
    action: str = "allow"
    reasons: list[str] = Field(default_factory=list)


class AskResponse(BaseModel):
    prompt: str
    user_role: str = "public_user"
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    retrieved_document: Optional[str] = None
    retrieved_sources: list[str] = Field(default_factory=list)
    retrieved_chunks: list[RetrievedChunk] = Field(default_factory=list)
    evidence_summary: Optional[str] = None
    threat_source: str = "retrieved_content"
    qwen_called: bool = False
    tool_call: Optional[dict[str, object]] = None
    access_control: Optional[dict[str, object]] = None
    dlp: Optional[dict[str, object]] = None
    output_firewall: Optional[dict[str, object]] = None
    unauthorized_retrievals: list[dict[str, object]] = Field(default_factory=list)
    action: str
    blocked: bool
    label: str
    reason: str
    rule_score: float = 0.0
    semantic_score: float = 0.0
    ml_score: float = 0.0
    rule_label: str = "safe"
    semantic_label: str = "safe"
    ml_label: str = "safe"
    risk_score: float
    response: Optional[str] = None
    answer: Optional[str] = None
    sources: list[str] = Field(default_factory=list)
    llm_called: bool = False
    mode: str = "protected"
    firewall_active: bool = True
    blocked_stage: Optional[str] = None
    output_firewall_action: Optional[str] = None
    sanitized: bool = False
    tool_decisions: list[dict[str, object]] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)
