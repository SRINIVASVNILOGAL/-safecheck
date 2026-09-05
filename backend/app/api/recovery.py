"""POST /v1/recovery/* -- fraud-recovery / reporting-email feature.

Flow (per user's explicit spec): Analyze (existing POST /v1/check) ->
identify the relevant organization -> find official reporting details ->
generate email -> user reviews -> user clicks Send.

Organization identification and contact-detail lookup are both fully
deterministic (app.services.org_directory) -- never LLM-derived, since a
wrong helpline/email here is actively harmful. Only the email wording is
LLM-drafted (app.integrations.openrouter.generate_recovery_email), with a
deterministic fallback, and the user always reviews/can edit it before
any send.

Sending reuses the existing Gmail send-permission mechanism (the same one
WarningPanel/app.api.email uses) since that is already wired, tested, and
scoped to gmail.send with an explicit confirm-to-send flow -- there is no
reason to build a second send pathway. If no Gmail account is connected,
the draft is still generated but `can_send` is False and the frontend
must offer a copy/mailto fallback instead of a Send button.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from app.db import (
    claim_recovery_report,
    create_recovery_report,
    finish_recovery_report,
    get_gmail_account,
    get_recovery_report,
)
from app.integrations.gmail import GmailApiError, send_warning_message
from app.integrations.openrouter import generate_recovery_email
from app.models.recovery import (
    OrgContactOut,
    RecoveryConfirmRequest,
    RecoveryConfirmResponse,
    RecoveryDraftOut,
    RecoveryDraftRequest,
)
from app.services.org_directory import identify_organizations

router = APIRouter()


def _to_org_out(contact) -> OrgContactOut:
    return OrgContactOut(
        key=contact.key,
        display_name=contact.display_name,
        email=contact.email,
        phone=contact.phone,
        portal_url=contact.portal_url,
        note=contact.note,
    )


@router.post("/v1/recovery/draft", response_model=RecoveryDraftOut)
async def create_recovery_draft(request: RecoveryDraftRequest) -> RecoveryDraftOut:
    """Identify the relevant organization(s) and generate a reviewable report email.

    Never sends anything. `org_key` lets the frontend let the user pick a
    different detected organization (e.g. the message impersonates SBI but
    the user wants to report to the national portal instead) without
    re-running identification.
    """
    candidates = identify_organizations(request.context_text)
    if request.org_key is not None:
        selected = next((item for item in candidates if item.key == request.org_key), None)
        if selected is None:
            raise HTTPException(status_code=400, detail=f"org_key {request.org_key!r} was not among the identified organizations for this case.")
    else:
        selected = candidates[0]
    alternates = [item for item in candidates if item.key != selected.key]

    copy = await generate_recovery_email(
        org_display_name=selected.display_name,
        risk_score=request.risk_score,
        risk_band=request.risk_band,
        signals=request.signals,
    )

    account = await get_gmail_account()
    can_send = account is not None and selected.email is not None

    report = await create_recovery_report(
        case_id=request.case_id,
        org_key=selected.key,
        org_display_name=selected.display_name,
        recipient_email=selected.email,
        risk_score=request.risk_score,
        risk_band=request.risk_band,
        subject=copy.subject,
        body=copy.body,
    )

    return RecoveryDraftOut(
        report_id=report.id,
        organization=_to_org_out(selected),
        alternate_organizations=[_to_org_out(item) for item in alternates],
        subject=copy.subject,
        body=copy.body,
        status=report.status,
        can_send=can_send,
    )


@router.get("/v1/recovery/{report_id}", response_model=RecoveryDraftOut)
async def get_recovery_draft(report_id: str) -> RecoveryDraftOut:
    report = await get_recovery_report(report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Recovery report draft not found.")
    account = await get_gmail_account()
    can_send = account is not None and report.recipient_email is not None and report.status == "DRAFT"
    selected = OrgContactOut(key=report.org_key, display_name=report.org_display_name, email=report.recipient_email, phone=None, portal_url=None, note="")
    return RecoveryDraftOut(
        report_id=report.id,
        organization=selected,
        alternate_organizations=[],
        subject=report.subject,
        body=report.body,
        status=report.status,
        can_send=can_send,
    )


@router.post("/v1/recovery/{report_id}/confirm", response_model=RecoveryConfirmResponse)
async def confirm_recovery_report(report_id: str, request: RecoveryConfirmRequest) -> RecoveryConfirmResponse:
    """The only route that ever sends a recovery report, and only after an
    explicit confirmed=true plus a fresh idempotency key. Mirrors
    app.api.email.confirm_warning's duplicate-confirm semantics exactly.
    """
    if not request.confirmed:
        raise HTTPException(status_code=400, detail="confirmed must be true to send a recovery report.")
    if "http://" in request.body.lower() or "https://" in request.body.lower():
        raise HTTPException(status_code=400, detail="Recovery report body may not contain links.")

    report = await get_recovery_report(report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Recovery report draft not found.")
    if report.recipient_email is None:
        raise HTTPException(status_code=400, detail="This organization has no direct report-fraud email address on file. Use its phone helpline or web portal instead.")

    account = await get_gmail_account()
    if account is None:
        raise HTTPException(status_code=400, detail="No Gmail account is connected. Connect Gmail to send this report, or copy it and send manually.")

    claimed, is_new_claim = await claim_recovery_report(
        report_id, idempotency_key=request.idempotency_key, subject=request.subject, body=request.body
    )
    if claimed is None:
        raise HTTPException(status_code=404, detail="Recovery report draft not found.")
    if not is_new_claim:
        if claimed.idempotency_key and claimed.idempotency_key != request.idempotency_key:
            raise HTTPException(status_code=409, detail="This report was already confirmed with a different request.")
        if claimed.status == "DRAFT":
            raise HTTPException(status_code=409, detail="This report is already being processed by another request.")
        return RecoveryConfirmResponse(report_id=claimed.id, status=claimed.status, gmail_message_id=claimed.gmail_message_id, error=claimed.error)

    try:
        gmail_message_id = await send_warning_message(
            account.refresh_token,
            from_address=account.email_address,
            recipient=report.recipient_email,
            subject=request.subject,
            body=request.body,
            warning_id=report_id,
        )
        await finish_recovery_report(report_id, status="SENT", gmail_message_id=gmail_message_id)
        return RecoveryConfirmResponse(report_id=report_id, status="SENT", gmail_message_id=gmail_message_id)
    except GmailApiError as exc:
        await finish_recovery_report(report_id, status="FAILED", error=str(exc)[:200])
        return RecoveryConfirmResponse(report_id=report_id, status="FAILED", error=str(exc)[:200])
