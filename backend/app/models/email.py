"""Request/response models for the /v1/email/* endpoints.

Matches docs/api-contract.md's "Gmail integration (Phase 9)" section.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from app.models.check import CheckResponse


class EmailStatusResponse(BaseModel):
    connected: bool
    email_address: str | None = None
    last_checked_at: str | None = None


class ConnectStartResponse(BaseModel):
    authorization_url: str


class CheckedMessage(BaseModel):
    message_id: str
    # Gmail's own header is "From"; `from` is a reserved word in Python,
    # so the model field is from_ but serializes as "from" over the
    # wire, matching docs/api-contract.md exactly.
    from_: str = Field(serialization_alias="from")
    subject: str
    received_at: str
    check: CheckResponse

    model_config = ConfigDict(populate_by_name=True)


class CheckNowResponse(BaseModel):
    checked_count: int
    results: list[CheckedMessage]
