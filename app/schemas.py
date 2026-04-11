from typing import Optional

from pydantic import BaseModel, Field


class AskRequest(BaseModel):
    prompt: str


class RetrievedChunk(BaseModel):
    document_name: str
    source_path: str
    source_set: str = "unknown"
    is_poisoned: bool = False
    chunk_id: str
    chunk_index: int
    text: str
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
    retrieved_document: Optional[str] = None
    retrieved_sources: list[str] = Field(default_factory=list)
    retrieved_chunks: list[RetrievedChunk] = Field(default_factory=list)
    evidence_summary: Optional[str] = None
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
