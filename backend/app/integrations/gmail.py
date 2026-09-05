"""Gmail OAuth, bounded MIME extraction, and message fetching.

Gmail remains read-only. The Email Agent extracts plain/HTML text, canonical
HTTP(S) URLs, and a bounded set of supported attachment bytes. It never
returns attachment contents or sends/modifies Gmail messages.
"""
from __future__ import annotations

import asyncio
import base64
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import urlencode, urlsplit, urlunsplit

import httpx

from app.config import settings
from app.graph.state import EmailAttachment

_AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
_GMAIL_API_BASE = "https://gmail.googleapis.com/gmail/v1/users/me"
_SCOPES = "https://www.googleapis.com/auth/gmail.readonly openid email"
MESSAGE_BATCH_SIZE = 10
MAX_EMAIL_URLS = 5
MAX_EMAIL_ATTACHMENTS = 3
MAX_ATTACHMENT_BYTES = 5 * 1024 * 1024
MAX_TOTAL_ATTACHMENT_BYTES = 10 * 1024 * 1024
_SUPPORTED_ATTACHMENT_TYPES = {"application/pdf", "image/png", "image/jpeg"}
_DEFAULT_TIMEOUT_SECONDS = 10.0
_URL_PATTERN = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)


class GmailApiError(Exception):
    def __init__(self, message: str, *, invalid_grant: bool = False) -> None:
        super().__init__(message)
        self.invalid_grant = invalid_grant


def build_authorization_url(state: str) -> str:
    return f"{_AUTH_ENDPOINT}?{urlencode({'client_id': settings.google_client_id, 'redirect_uri': settings.gmail_redirect_uri, 'response_type': 'code', 'scope': _SCOPES, 'access_type': 'offline', 'prompt': 'consent', 'state': state})}"


@dataclass(frozen=True)
class TokenExchangeResult:
    refresh_token: str
    email_address: str


async def exchange_code_for_tokens(code: str, http_client: httpx.AsyncClient | None = None) -> TokenExchangeResult:
    owns = http_client is None
    client = http_client or httpx.AsyncClient(timeout=_DEFAULT_TIMEOUT_SECONDS)
    try:
        response = await client.post(_TOKEN_ENDPOINT, data={"code": code, "client_id": settings.google_client_id, "client_secret": settings.google_client_secret, "redirect_uri": settings.gmail_redirect_uri, "grant_type": "authorization_code"})
        if response.status_code != 200:
            raise GmailApiError(f"Token exchange failed: HTTP {response.status_code} {response.text}")
        body = response.json()
        refresh_token, access_token = body.get("refresh_token"), body.get("access_token")
        if not refresh_token:
            raise GmailApiError("Google did not return a refresh token. Try disconnecting SafeCheck's access in your Google Account settings and connecting again.")
        userinfo = await client.get("https://www.googleapis.com/oauth2/v2/userinfo", headers={"Authorization": f"Bearer {access_token}"})
        if userinfo.status_code != 200:
            raise GmailApiError(f"Failed to resolve connected account email: HTTP {userinfo.status_code}")
        return TokenExchangeResult(refresh_token=refresh_token, email_address=userinfo.json().get("email", ""))
    finally:
        if owns:
            await client.aclose()


async def _get_access_token(refresh_token: str, http_client: httpx.AsyncClient | None = None) -> str:
    owns = http_client is None
    client = http_client or httpx.AsyncClient(timeout=_DEFAULT_TIMEOUT_SECONDS)
    try:
        response = await client.post(_TOKEN_ENDPOINT, data={"refresh_token": refresh_token, "client_id": settings.google_client_id, "client_secret": settings.google_client_secret, "grant_type": "refresh_token"})
    finally:
        if owns:
            await client.aclose()
    if response.status_code != 200:
        if "invalid_grant" in response.text:
            raise GmailApiError("Gmail access has been revoked or expired.", invalid_grant=True)
        raise GmailApiError(f"Failed to refresh access token: HTTP {response.status_code}")
    token = response.json().get("access_token")
    if not token:
        raise GmailApiError("Token refresh response did not include an access token.")
    return token


@dataclass(frozen=True)
class SkippedAttachment:
    filename: str
    reason: str


@dataclass(frozen=True)
class FetchedMessage:
    message_id: str
    sender: str
    subject: str
    body: str
    received_at: str
    urls: tuple[str, ...] = ()
    urls_found: int = 0
    attachments: tuple[EmailAttachment, ...] = ()
    attachments_found: int = 0
    skipped_attachments: tuple[SkippedAttachment, ...] = ()


def _decode_base64url(data: str) -> str:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4)).decode("utf-8", errors="replace")


def _decode_bytes(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def _header(headers: list[dict], name: str) -> str:
    return next((h.get("value", "") for h in headers if h.get("name", "").lower() == name.lower()), "")


def _parse_received_at(value: str) -> str:
    try:
        parsed = parsedate_to_datetime(value)
        return (parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)).isoformat()
    except (TypeError, ValueError):
        return datetime.now(timezone.utc).isoformat()


def _walk_parts(payload: dict) -> list[dict]:
    parts = [payload]
    for part in payload.get("parts") or []:
        parts.extend(_walk_parts(part))
    return parts


def _extract_body(payload: dict) -> str:
    parts = _walk_parts(payload)
    plain = [p for p in parts if p.get("mimeType") == "text/plain" and p.get("body", {}).get("data")]
    html = [p for p in parts if p.get("mimeType") == "text/html" and p.get("body", {}).get("data")]
    selected = plain[:1] or html[:1]
    if not selected:
        return ""
    text = _decode_base64url(selected[0]["body"]["data"])
    if selected[0].get("mimeType") == "text/html":
        text = re.sub(r"<[^>]+>", " ", text)
        text = re.sub(r"\s+", " ", text).strip()
    return text


def _canonical_urls(payload: dict) -> tuple[int, tuple[str, ...]]:
    candidates: list[str] = []
    for part in _walk_parts(payload):
        if part.get("mimeType") in {"text/plain", "text/html"} and (data := part.get("body", {}).get("data")):
            candidates.extend(_URL_PATTERN.findall(_decode_base64url(data)))
    unique: list[str] = []
    for candidate in candidates:
        cleaned = candidate.rstrip(".,;:!?)]}\"'")
        parsed = urlsplit(cleaned)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
            continue
        normalized = urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), parsed.path or "/", parsed.query, ""))
        if normalized not in unique:
            unique.append(normalized)
    return len(unique), tuple(unique[:MAX_EMAIL_URLS])


async def _collect_attachments(message_id: str, payload: dict, client: httpx.AsyncClient, headers: dict[str, str]) -> tuple[int, tuple[EmailAttachment, ...], tuple[SkippedAttachment, ...]]:
    candidates = [p for p in _walk_parts(payload) if p.get("filename")]
    skipped: list[SkippedAttachment] = []
    selected: list[dict] = []
    running_size = 0
    for part in candidates:
        filename, content_type = part.get("filename", "attachment"), part.get("mimeType", "")
        body = part.get("body", {})
        size = int(body.get("size", 0) or 0)
        if content_type not in _SUPPORTED_ATTACHMENT_TYPES:
            skipped.append(SkippedAttachment(filename, "Unsupported attachment type."))
        elif len(selected) >= MAX_EMAIL_ATTACHMENTS:
            skipped.append(SkippedAttachment(filename, "Supported attachment limit reached."))
        elif size <= 0:
            skipped.append(SkippedAttachment(filename, "Attachment size is unavailable."))
        elif size > MAX_ATTACHMENT_BYTES:
            skipped.append(SkippedAttachment(filename, "Attachment exceeds the 5 MB per-file limit."))
        elif running_size + size > MAX_TOTAL_ATTACHMENT_BYTES:
            skipped.append(SkippedAttachment(filename, "Total attachment download limit reached."))
        else:
            selected.append(part)
            running_size += size

    async def download(part: dict) -> EmailAttachment | SkippedAttachment:
        body, filename, content_type = part.get("body", {}), part.get("filename", "attachment"), part.get("mimeType", "")
        if data := body.get("data"):
            raw = _decode_bytes(data)
        else:
            attachment_id = body.get("attachmentId")
            if not attachment_id:
                return SkippedAttachment(filename, "Attachment data is unavailable.")
            response = await client.get(f"{_GMAIL_API_BASE}/messages/{message_id}/attachments/{attachment_id}", headers=headers)
            if response.status_code != 200:
                return SkippedAttachment(filename, "Attachment could not be downloaded.")
            raw = _decode_bytes(response.json().get("data", ""))
        if len(raw) > MAX_ATTACHMENT_BYTES:
            return SkippedAttachment(filename, "Attachment exceeds the 5 MB per-file limit.")
        return EmailAttachment(filename=filename, content_type=content_type, data=raw)

    downloaded = await asyncio.gather(*(download(part) for part in selected))
    attachments = tuple(item for item in downloaded if isinstance(item, EmailAttachment))
    skipped.extend(item for item in downloaded if isinstance(item, SkippedAttachment))
    return len(candidates), attachments, tuple(skipped)


async def fetch_recent_messages(refresh_token: str, *, limit: int = MESSAGE_BATCH_SIZE, http_client: httpx.AsyncClient | None = None) -> list[FetchedMessage]:
    owns = http_client is None
    client = http_client or httpx.AsyncClient(timeout=_DEFAULT_TIMEOUT_SECONDS)
    try:
        token = await _get_access_token(refresh_token, client)
        headers = {"Authorization": f"Bearer {token}"}
        response = await client.get(f"{_GMAIL_API_BASE}/messages", headers=headers, params={"maxResults": limit, "labelIds": "INBOX"})
        if response.status_code == 401:
            raise GmailApiError("Gmail access token was rejected.", invalid_grant=True)
        if response.status_code != 200:
            raise GmailApiError(f"Gmail message list failed: HTTP {response.status_code}")

        async def fetch_one(ref: dict) -> FetchedMessage | None:
            message = await client.get(f"{_GMAIL_API_BASE}/messages/{ref['id']}", headers=headers, params={"format": "full"})
            if message.status_code != 200:
                return None
            raw = message.json(); payload = raw.get("payload", {}); message_id = raw.get("id", ref["id"])
            urls_found, urls = _canonical_urls(payload)
            attachment_data = await _collect_attachments(message_id, payload, client, headers)
            return FetchedMessage(message_id=message_id, sender=_header(payload.get("headers", []), "From"), subject=_header(payload.get("headers", []), "Subject"), body=_extract_body(payload), received_at=_parse_received_at(_header(payload.get("headers", []), "Date")), urls=urls, urls_found=urls_found, attachments=attachment_data[1], attachments_found=attachment_data[0], skipped_attachments=attachment_data[2])

        fetched = await asyncio.gather(*(fetch_one(ref) for ref in response.json().get("messages", [])))
        return [message for message in fetched if message is not None]
    finally:
        if owns:
            await client.aclose()
