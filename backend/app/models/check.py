"""Request/response models for POST /v1/check.

Matches docs/api-contract.md exactly. This module contains only data
shapes -- no business logic. See app.api.check for the endpoint that uses
these models.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field, field_validator

SourceType = Literal["TEXT", "URL", "EMAIL", "DOCUMENT"]

# POST /v1/check accepts these in the request body. DOCUMENT is a valid
# SourceType (used in CheckResponse.source_type for POST /v1/document
# responses) but is never a valid *request* value for /v1/check --
# document analysis has its own endpoint because it needs
# multipart/form-data for file upload, not JSON.
_CHECK_REQUEST_SOURCE_TYPES = ("TEXT", "URL", "EMAIL")


class CheckPayload(BaseModel):
    """Union-ish payload; which fields are required depends on source_type.

    docs/api-contract.md field rules:
    - text: required for TEXT
    - url: required for URL
    - sender, body: required for EMAIL; subject, attachments optional
    """

    text: str | None = None
    url: str | None = None
    sender: str | None = None
    subject: str = ""
    body: str | None = None
    attachments: list[str] = Field(default_factory=list)


class CheckRequest(BaseModel):
    source_type: SourceType
    payload: CheckPayload

    @field_validator("source_type")
    @classmethod
    def _reject_document_source_type(cls, value: str) -> str:
        if value not in _CHECK_REQUEST_SOURCE_TYPES:
            raise ValueError(
                f"source_type {value!r} is not valid for POST /v1/check. "
                f"Allowed values: {_CHECK_REQUEST_SOURCE_TYPES}. "
                "Document analysis uses POST /v1/document instead."
            )
        return value


class RiskInfo(BaseModel):
    score: int
    band: Literal["LOW", "UNCERTAIN", "MEDIUM", "HIGH"]


class EvidenceOut(BaseModel):
    """API-facing evidence shape, matching docs/api-contract.md.

    This mirrors app.risk.evidence.Evidence but is defined separately so
    the API contract and the internal engine model can evolve
    independently if needed.
    """

    signal: str
    category: Literal["rules", "url", "ml"]
    points: int
    reason: str
    source: str
    confidence: str
    availability: Literal["available", "unavailable"]
    correlationGroup: str
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]


class Explanation(BaseModel):
    summary: str
    why: list[str]
    next_action: str
    uncertainty: list[str] = Field(default_factory=list)


class CheckResponse(BaseModel):
    case_id: str
    source_type: SourceType
    risk: RiskInfo
    evidence: list[EvidenceOut]
    explanation: Explanation
    safe_actions: list[str]
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
