"""Request/response models for the /v1/recovery/* fraud-reporting endpoints.

Flow (per user's explicit spec): Analyze -> identify the relevant
organization -> find official reporting details -> generate email -> user
reviews -> user clicks Send. This module covers the last four steps;
"Analyze" is the existing POST /v1/check.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class OrgContactOut(BaseModel):
    key: str
    display_name: str
    email: str | None = None
    phone: str | None = None
    portal_url: str | None = None
    note: str = ""


class RecoveryDraftRequest(BaseModel):
    """Everything needed to identify an organization and draft a report.

    `context_text` is the user's own submitted content (message text,
    URL, or email subject+body) -- it is used only for local keyword
    matching against the static org directory and, in a bounded/redacted
    form, is never sent to the org-identification step's LLM (there is
    none; identification is deterministic). It IS included in the
    generated email body for the user to review/edit, not sent anywhere
    automatically.
    """

    case_id: str = Field(min_length=1, max_length=64)
    risk_score: int = Field(ge=0, le=100)
    risk_band: Literal["MEDIUM", "HIGH", "UNCERTAIN"]
    signals: list[str] = Field(min_length=1, max_length=12)
    context_text: str = Field(min_length=1, max_length=5000)
    org_key: str | None = Field(default=None, max_length=64)


class RecoveryDraftOut(BaseModel):
    report_id: str
    organization: OrgContactOut
    alternate_organizations: list[OrgContactOut]
    subject: str
    body: str
    status: str
    can_send: bool


class RecoveryConfirmRequest(BaseModel):
    confirmed: bool
    idempotency_key: str = Field(min_length=8, max_length=128)
    subject: str = Field(min_length=1, max_length=180)
    body: str = Field(min_length=1, max_length=4000)


class RecoveryConfirmResponse(BaseModel):
    report_id: str
    status: str
    gmail_message_id: str | None = None
    error: str | None = None
