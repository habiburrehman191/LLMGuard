from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class ChatRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    question: str = Field(min_length=1, max_length=1200)
    conversation_id: int | None = Field(default=None, ge=1)
    current_page: str = Field(default="/", max_length=240)
    page_title: str = Field(default="", max_length=180)

    @field_validator("question")
    @classmethod
    def clean_question(cls, value: str) -> str:
        normalized = " ".join(value.replace("\x00", " ").split())
        if not normalized:
            raise ValueError("Question cannot be empty.")
        return normalized

    @field_validator("current_page")
    @classmethod
    def safe_route(cls, value: str) -> str:
        value = value.strip()
        return value if value.startswith("/") and not value.startswith("//") else "/"


class ConversationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    title: str = Field(default="New conversation", max_length=180)


class FeedbackRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    rating: Literal["helpful", "not_helpful"]
    reason: str | None = Field(default=None, max_length=80)
    comment: str | None = Field(default=None, max_length=1000)

    @field_validator("reason")
    @classmethod
    def valid_reason(cls, value: str | None) -> str | None:
        if value is None:
            return None
        allowed = {
            "Incorrect information",
            "Incorrect answer",
            "Incomplete answer",
            "Outdated information",
            "Didn't understand my question",
            "Could not understand question",
            "Wrong source",
            "Other",
        }
        normalized = value.strip()
        if normalized and normalized not in allowed:
            raise ValueError("Unsupported feedback reason.")
        return normalized or None
