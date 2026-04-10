from typing import Optional

from pydantic import BaseModel, Field


class AskRequest(BaseModel):
    prompt: str


class RetrievedChunk(BaseModel):
    document_name: str
    source_path: str
    chunk_id: str
    chunk_index: int
    text: str
    score: float


class AskResponse(BaseModel):
    prompt: str
    retrieved_document: Optional[str] = None
    retrieved_sources: list[str] = Field(default_factory=list)
    retrieved_chunks: list[RetrievedChunk] = Field(default_factory=list)
    action: str
    blocked: bool
    reason: str
    risk_score: float
    response: Optional[str] = None
