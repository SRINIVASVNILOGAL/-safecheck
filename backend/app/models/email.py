"""Request/response models for the /v1/email/* endpoints."""
from __future__ import annotations

from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, field_validator
from app.models.check import CheckResponse


class EmailStatusResponse(BaseModel):
    connected: bool
    email_address: str | None = None
    last_checked_at: str | None = None


class ConnectStartResponse(BaseModel):
    authorization_url: str


class AnalysisCoverage(BaseModel):
    urls_found: int = 0
    urls_analyzed: int = 0
    attachments_found: int = 0
    attachments_analyzed: int = 0
    skipped_attachments: list["SkippedAttachmentOut"] = Field(default_factory=list)


class SkippedAttachmentOut(BaseModel):
    filename: str
    reason: str


class CheckedMessage(BaseModel):
    message_id: str
    from_: str = Field(serialization_alias="from")
    subject: str
    received_at: str
    analysis_coverage: AnalysisCoverage = Field(default_factory=AnalysisCoverage)
    check: CheckResponse
    model_config = ConfigDict(populate_by_name=True)


class CheckNowResponse(BaseModel):
    checked_count: int
    results: list[CheckedMessage]


class RecentSentContactOut(BaseModel):
    address: str
    display_name: str = ""
    last_sent_at: str


class WarningDraftRequest(BaseModel):
    gmail_message_id: str = Field(min_length=1, max_length=256)
    risk_score: int = Field(ge=0, le=100)
    risk_band: Literal["MEDIUM", "HIGH"]
    signals: list[str] = Field(min_length=1, max_length=8)
    recipient_addresses: list[str] = Field(min_length=1, max_length=20)

    @field_validator("recipient_addresses")
    @classmethod
    def normalize_recipients(cls, values: list[str]) -> list[str]:
        normalized = list(dict.fromkeys(value.strip().lower() for value in values if value.strip()))
        if not normalized or any("@" not in value for value in normalized):
            raise ValueError("Select one or more valid recent-contact email addresses.")
        return normalized


class WarningDraftOut(BaseModel):
    warning_id: str
    recipients: list[str]
    subject: str
    body: str
    status: str


class WarningConfirmRequest(BaseModel):
    confirmed: bool
    idempotency_key: str = Field(min_length=8, max_length=128)
    subject: str = Field(min_length=1, max_length=180)
    body: str = Field(min_length=1, max_length=3000)


class WarningDeliveryOut(BaseModel):
    recipient: str
    status: str
    gmail_message_id: str | None = None
    error: str | None = None


class WarningConfirmResponse(BaseModel):
    warning_id: str
    status: str
    deliveries: list[WarningDeliveryOut]
