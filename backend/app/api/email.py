"""GET/POST /v1/email/* -- Gmail on-demand polling integration (Phase 9).

On-demand only: there is no background scheduler in this phase. The user
explicitly connects a Gmail account (OAuth) and explicitly triggers a
check via POST /v1/email/check-now. See
docs/api-contract.md's "Gmail integration (Phase 9)" section for the
full contract.

Every fetched message is run through the exact same graph
(app.graph.pipeline.run_check_pipeline) and response-shaping
(app.api.check.build_check_response_from_result) as POST /v1/check with
source_type=EMAIL -- there is no separate scoring path for email
fetched via Gmail vs. email pasted manually.
"""

from __future__ import annotations

import secrets
from datetime import datetime, timezone
from uuid import uuid4

from fastapi import APIRouter, HTTPException
from fastapi.responses import RedirectResponse

from app.api.check import build_check_response_from_result
from app.config import settings
from app.db import get_gmail_account, update_last_checked_at, upsert_gmail_account
from app.graph.pipeline import run_email_pipeline
from app.integrations.gmail import (
    GmailApiError,
    build_authorization_url,
    exchange_code_for_tokens,
    fetch_recent_messages,
)
from app.models.check import CheckPayload
from app.models.email import (
    AnalysisCoverage,
    CheckedMessage,
    CheckNowResponse,
    ConnectStartResponse,
    EmailStatusResponse,
    SkippedAttachmentOut,
)

router = APIRouter()

# In-memory OAuth state store: state -> issued_at. This is a CSRF
# protection for the OAuth redirect (per RFC 6749 Section 10.12), not a
# session/identity store -- a single-process, in-memory dict is
# sufficient for a local single-user demo. It intentionally does not
# survive a server restart, which just means an in-flight OAuth attempt
# started before a restart will fail closed (callback rejects an unknown
# state) rather than silently succeeding.
_pending_oauth_states: set[str] = set()


@router.get("/v1/email/status", response_model=EmailStatusResponse)
async def email_status() -> EmailStatusResponse:
    account = await get_gmail_account()
    if account is None:
        return EmailStatusResponse(connected=False)
    return EmailStatusResponse(
        connected=True,
        email_address=account.email_address,
        last_checked_at=(
            account.last_checked_at.isoformat() if account.last_checked_at else None
        ),
    )


@router.post("/v1/email/connect/start", response_model=ConnectStartResponse)
async def connect_start() -> ConnectStartResponse:
    if not settings.google_client_id or not settings.google_client_secret:
        raise HTTPException(
            status_code=500,
            detail=(
                "Gmail integration is not configured. Set GOOGLE_CLIENT_ID "
                "and GOOGLE_CLIENT_SECRET in the backend .env file."
            ),
        )

    state = secrets.token_urlsafe(24)
    _pending_oauth_states.add(state)

    return ConnectStartResponse(authorization_url=build_authorization_url(state))


@router.get("/v1/email/connect/callback")
async def connect_callback(
    code: str | None = None, state: str | None = None, error: str | None = None
) -> RedirectResponse:
    """OAuth redirect target. Not meant to be called directly by frontend
    JS -- Google redirects the user's browser here after consent.

    Always redirects the browser back to the frontend (never returns raw
    JSON), since this endpoint is only ever hit via a full-page browser
    navigation, not a fetch() call.
    """
    if error is not None:
        return RedirectResponse(
            f"{settings.frontend_url}/email?connected=false&reason={error}"
        )

    if state is None or state not in _pending_oauth_states:
        return RedirectResponse(
            f"{settings.frontend_url}/email?connected=false&reason=invalid_state"
        )
    _pending_oauth_states.discard(state)

    if code is None:
        return RedirectResponse(
            f"{settings.frontend_url}/email?connected=false&reason=missing_code"
        )

    try:
        result = await exchange_code_for_tokens(code)
    except GmailApiError as exc:
        return RedirectResponse(
            f"{settings.frontend_url}/email?connected=false&reason={str(exc)[:200]}"
        )

    await upsert_gmail_account(result.email_address, result.refresh_token)

    return RedirectResponse(f"{settings.frontend_url}/email?connected=true")


@router.post("/v1/email/check-now", response_model=CheckNowResponse)
async def check_now() -> CheckNowResponse:
    account = await get_gmail_account()
    if account is None:
        raise HTTPException(
            status_code=400,
            detail="No Gmail account is connected. Call POST /v1/email/connect/start first.",
        )

    try:
        messages = await fetch_recent_messages(account.refresh_token)
    except GmailApiError as exc:
        if exc.invalid_grant:
            raise HTTPException(status_code=401, detail=str(exc)) from exc
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    results: list[CheckedMessage] = []
    for message in messages:
        # run_check_pipeline's EMAIL branch requires a non-empty,
        # non-whitespace body (matching POST /v1/check's own
        # validation, which does payload.body.strip()). A real Gmail
        # message can legitimately have no plain/HTML text body (e.g.
        # an attachment-only email) -- fall back to placeholder text
        # rather than letting one such message's HTTPException(400)
        # abort the entire check-now batch.
        payload = CheckPayload(
            sender=message.sender,
            subject=message.subject,
            body=message.body.strip() or "(no text content)",
        )
        pipeline_result = await run_email_pipeline(
            payload,
            urls=list(message.urls),
            attachments=list(message.attachments),
        )
        check_response = build_check_response_from_result(
            case_id=f"case_{uuid4().hex[:8]}",
            source_type="EMAIL",
            pipeline_result=pipeline_result,
        )
        results.append(
            CheckedMessage(
                message_id=message.message_id,
                from_=message.sender,
                subject=message.subject,
                received_at=message.received_at,
                analysis_coverage=AnalysisCoverage(
                    urls_found=message.urls_found,
                    urls_analyzed=len(message.urls),
                    attachments_found=message.attachments_found,
                    attachments_analyzed=len(message.attachments),
                    skipped_attachments=[
                        SkippedAttachmentOut(filename=item.filename, reason=item.reason)
                        for item in message.skipped_attachments
                    ],
                ),
                check=check_response,
            )
        )

    await update_last_checked_at(datetime.now(timezone.utc))

    return CheckNowResponse(checked_count=len(results), results=results)
