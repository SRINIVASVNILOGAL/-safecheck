"""Gmail OAuth flow and message-fetching adapter.

Scope requested: gmail.readonly ONLY. This module never sends, modifies,
labels, or deletes any email -- it only lists and reads message content
for analysis. See docs/api-contract.md's "Gmail integration (Phase 9)"
section for the full endpoint contract this supports.

Design notes:
- All Google API calls use httpx directly (async, consistent with the
  rest of the codebase's provider adapters -- google_safe_browsing.py,
  virustotal.py) rather than the synchronous googleapiclient library,
  even though that library is already a dependency (installed for a
  possible future admin/verification use, currently unused elsewhere).
- Errors are raised as GmailApiError (a plain exception, not converted
  to Evidence) since this module operates one layer below the risk
  engine -- app.api.email is responsible for translating failures here
  into the HTTP error responses documented in the API contract (400,
  401, 502).
"""

from __future__ import annotations

import asyncio
import base64
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import urlencode

import httpx

from app.config import settings

_AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
_GMAIL_API_BASE = "https://gmail.googleapis.com/gmail/v1/users/me"

# Read-only scope only, per the API contract. openid/email/profile are
# included so we can identify which Gmail address was connected (shown
# in GET /v1/email/status) without needing a second consent screen.
_SCOPES = (
    "https://www.googleapis.com/auth/gmail.readonly "
    "openid email"
)

# How many of the most recent messages check-now fetches per call.
MESSAGE_BATCH_SIZE = 10

_DEFAULT_TIMEOUT_SECONDS = 10.0


class GmailApiError(Exception):
    """Raised for any Gmail/OAuth API failure. Carries enough information
    for app.api.email to pick the right HTTP status code.
    """

    def __init__(self, message: str, *, invalid_grant: bool = False) -> None:
        super().__init__(message)
        self.invalid_grant = invalid_grant


def build_authorization_url(state: str) -> str:
    """Build the Google OAuth consent URL the frontend redirects to.

    access_type=offline + prompt=consent ensures Google issues a refresh
    token even if the user has previously granted consent (Google only
    issues a refresh token on the *first* consent grant by default,
    which would silently break reconnect-after-revoke without
    prompt=consent forcing it every time).
    """
    params = {
        "client_id": settings.google_client_id,
        "redirect_uri": settings.gmail_redirect_uri,
        "response_type": "code",
        "scope": _SCOPES,
        "access_type": "offline",
        "prompt": "consent",
        "state": state,
    }
    query = urlencode(params)
    return f"{_AUTH_ENDPOINT}?{query}"


@dataclass(frozen=True)
class TokenExchangeResult:
    refresh_token: str
    email_address: str


async def exchange_code_for_tokens(
    code: str, http_client: httpx.AsyncClient | None = None
) -> TokenExchangeResult:
    """Exchange an OAuth authorization code for a refresh token, and
    resolve the connected account's email address.

    Raises GmailApiError if the exchange fails (e.g. the code was
    already used, expired, or the user denied consent upstream -- the
    latter is handled by app.api.email checking for an `error` query
    param before this is ever called).

    http_client: optional injected httpx.AsyncClient, for testing
        without real network calls (see google_safe_browsing.py /
        virustotal.py for the same pattern).
    """
    owns_client = http_client is None
    client = http_client or httpx.AsyncClient(timeout=_DEFAULT_TIMEOUT_SECONDS)
    try:
        response = await client.post(
            _TOKEN_ENDPOINT,
            data={
                "code": code,
                "client_id": settings.google_client_id,
                "client_secret": settings.google_client_secret,
                "redirect_uri": settings.gmail_redirect_uri,
                "grant_type": "authorization_code",
            },
        )
        if response.status_code != 200:
            raise GmailApiError(
                f"Token exchange failed: HTTP {response.status_code} {response.text}"
            )
        body = response.json()
        refresh_token = body.get("refresh_token")
        access_token = body.get("access_token")
        if not refresh_token:
            # Happens if prompt=consent was somehow bypassed on a repeat
            # grant. Surface a clear, actionable error rather than
            # storing an empty token that would fail silently later.
            raise GmailApiError(
                "Google did not return a refresh token. Try disconnecting "
                "SafeCheck's access in your Google Account settings and "
                "connecting again."
            )

        userinfo_response = await client.get(
            "https://www.googleapis.com/oauth2/v2/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        if userinfo_response.status_code != 200:
            raise GmailApiError(
                f"Failed to resolve connected account email: "
                f"HTTP {userinfo_response.status_code}"
            )
        email_address = userinfo_response.json().get("email", "")
    finally:
        if owns_client:
            await client.aclose()

    return TokenExchangeResult(refresh_token=refresh_token, email_address=email_address)


async def _get_access_token(
    refresh_token: str, http_client: httpx.AsyncClient | None = None
) -> str:
    """Exchange a stored refresh token for a short-lived access token.

    Raises GmailApiError(invalid_grant=True) if the refresh token itself
    has been revoked (e.g. the user removed SafeCheck's access from
    their Google Account) -- app.api.email maps this to HTTP 401 so the
    frontend knows to prompt reconnecting, rather than a generic 502.
    """
    owns_client = http_client is None
    client = http_client or httpx.AsyncClient(timeout=_DEFAULT_TIMEOUT_SECONDS)
    try:
        response = await client.post(
            _TOKEN_ENDPOINT,
            data={
                "refresh_token": refresh_token,
                "client_id": settings.google_client_id,
                "client_secret": settings.google_client_secret,
                "grant_type": "refresh_token",
            },
        )
    finally:
        if owns_client:
            await client.aclose()
    if response.status_code != 200:
        body_text = response.text
        if "invalid_grant" in body_text:
            raise GmailApiError(
                "Gmail access has been revoked or expired.", invalid_grant=True
            )
        raise GmailApiError(f"Failed to refresh access token: HTTP {response.status_code}")

    access_token = response.json().get("access_token")
    if not access_token:
        raise GmailApiError("Token refresh response did not include an access token.")
    return access_token


@dataclass(frozen=True)
class FetchedMessage:
    message_id: str
    sender: str
    subject: str
    body: str
    received_at: str  # ISO 8601, best-effort parsed from the Date header


def _decode_base64url(data: str) -> str:
    padded = data + "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(padded).decode("utf-8", errors="replace")


def _extract_body(payload: dict) -> str:
    """Walk a Gmail message payload's MIME tree for the best available
    text content. Prefers text/plain; falls back to a crude HTML strip
    of text/html if that's all the message has.
    """
    mime_type = payload.get("mimeType", "")
    body_data = payload.get("body", {}).get("data")

    if mime_type == "text/plain" and body_data:
        return _decode_base64url(body_data)

    parts = payload.get("parts") or []
    html_fallback: str | None = None
    for part in parts:
        part_mime = part.get("mimeType", "")
        part_data = part.get("body", {}).get("data")
        if part_mime == "text/plain" and part_data:
            return _decode_base64url(part_data)
        if part_mime == "text/html" and part_data and html_fallback is None:
            html_fallback = _decode_base64url(part_data)
        elif part.get("parts"):
            # Nested multipart (e.g. multipart/alternative inside
            # multipart/mixed with attachments) -- recurse.
            nested = _extract_body(part)
            if nested:
                return nested

    if html_fallback is not None:
        # Crude tag strip -- good enough for rule-based text analysis,
        # not meant to be a full HTML-to-text converter.
        text = re.sub(r"<[^>]+>", " ", html_fallback)
        return re.sub(r"\s+", " ", text).strip()

    if mime_type != "text/plain" and body_data:
        return _decode_base64url(body_data)

    return ""


def _header(headers: list[dict], name: str) -> str:
    for h in headers:
        if h.get("name", "").lower() == name.lower():
            return h.get("value", "")
    return ""


def _parse_received_at(date_header: str) -> str:
    if not date_header:
        return datetime.now(timezone.utc).isoformat()
    try:
        parsed = parsedate_to_datetime(date_header)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.isoformat()
    except (TypeError, ValueError):
        return datetime.now(timezone.utc).isoformat()


async def fetch_recent_messages(
    refresh_token: str,
    *,
    limit: int = MESSAGE_BATCH_SIZE,
    http_client: httpx.AsyncClient | None = None,
) -> list[FetchedMessage]:
    """Fetch the `limit` most recent messages from the inbox.

    Two Gmail API calls per message (list, then get) is the standard
    pattern for this API -- the list endpoint only returns message IDs,
    not content. `limit` is intentionally small (default 10) to keep
    check-now's total latency reasonable, since each message also
    triggers the full analysis pipeline (including two external URL
    reputation calls if the message contains a URL).
    """
    owns_client = http_client is None
    client = http_client or httpx.AsyncClient(timeout=_DEFAULT_TIMEOUT_SECONDS)

    try:
        access_token = await _get_access_token(refresh_token, client)
        headers = {"Authorization": f"Bearer {access_token}"}

        list_response = await client.get(
            f"{_GMAIL_API_BASE}/messages",
            headers=headers,
            params={"maxResults": limit, "labelIds": "INBOX"},
        )
        if list_response.status_code == 401:
            raise GmailApiError("Gmail access token was rejected.", invalid_grant=True)
        if list_response.status_code != 200:
            raise GmailApiError(
                f"Gmail message list failed: HTTP {list_response.status_code}"
            )

        message_refs = list_response.json().get("messages", [])

        async def fetch_one(ref: dict) -> FetchedMessage | None:
            """Fetch one full message. A failure is isolated to this
            message so one inaccessible/malformed email does not block
            the rest of the on-demand batch.
            """
            msg_response = await client.get(
                f"{_GMAIL_API_BASE}/messages/{ref['id']}",
                headers=headers,
                params={"format": "full"},
            )
            if msg_response.status_code != 200:
                return None

            msg_json = msg_response.json()
            payload = msg_json.get("payload", {})
            gmail_headers = payload.get("headers", [])
            return FetchedMessage(
                message_id=msg_json.get("id", ref["id"]),
                sender=_header(gmail_headers, "From"),
                subject=_header(gmail_headers, "Subject"),
                body=_extract_body(payload),
                received_at=_parse_received_at(_header(gmail_headers, "Date")),
            )

        # Fetch full messages concurrently: the old sequential version
        # could take up to 10 × the per-request timeout for a 10-message
        # batch. Concurrency retains the same ten-message limit but keeps
        # a slow Gmail item from making Check now feel broken.
        fetched = await asyncio.gather(*(fetch_one(ref) for ref in message_refs))
        messages = [message for message in fetched if message is not None]
    finally:
        if owns_client:
            await client.aclose()

    return messages
