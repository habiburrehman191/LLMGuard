from pydantic import BaseModel
from typing import Optional


class AskRequest(BaseModel):
    prompt: str


class AskResponse(BaseModel):
    prompt: str
    retrieved_document: Optional[str] = None
    action: str
    blocked: bool
    reason: str
    risk_score: float
    response: Optional[str] = None