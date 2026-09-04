"""Request/response models for POST /v1/check.

Matches docs/api-contract.md exactly. This module contains only data
shapes -- no business logic. See app.api.check for the endpoint that uses
these models.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field

SourceType = Literal["TEXT", "URL", "EMAIL"]


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
