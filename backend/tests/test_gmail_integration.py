"""Tests for app.integrations.gmail.

Uses httpx.MockTransport for every scenario (token exchange success/
failure, missing refresh token, revoked grant, message list/get, MIME
body extraction) -- no real network calls, matching the pattern already
used in test_google_safe_browsing.py and test_virustotal.py.
"""

from __future__ import annotations

import base64

import httpx
import pytest

from app.integrations.gmail import (
    GmailApiError,
    _extract_body,
    build_authorization_url,
    exchange_code_for_tokens,
    fetch_recent_messages,
)


def _b64(text: str) -> str:
    return base64.urlsafe_b64encode(text.encode("utf-8")).decode("ascii")


def _client_with_handler(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


class TestBuildAuthorizationUrl:
    def test_includes_required_params(self) -> None:
        url = build_authorization_url("some-csrf-state")
        assert "https://accounts.google.com/o/oauth2/v2/auth?" in url
        assert "access_type=offline" in url
        assert "prompt=consent" in url
        assert "state=some-csrf-state" in url
        assert "gmail.readonly" in url


class TestExchangeCodeForTokens:
    @pytest.mark.anyio
    async def test_success_returns_refresh_token_and_email(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if "token" in str(request.url) and request.method == "POST":
                return httpx.Response(
                    200,
                    json={"refresh_token": "rt_abc123", "access_token": "at_xyz"},
                )
            return httpx.Response(200, json={"email": "user@gmail.com"})

        result = await exchange_code_for_tokens(
            "auth-code", http_client=_client_with_handler(handler)
        )
        assert result.refresh_token == "rt_abc123"
        assert result.email_address == "user@gmail.com"

    @pytest.mark.anyio
    async def test_non_200_raises_gmail_api_error(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(400, text="invalid_grant")

        with pytest.raises(GmailApiError):
            await exchange_code_for_tokens(
                "bad-code", http_client=_client_with_handler(handler)
            )

    @pytest.mark.anyio
    async def test_missing_refresh_token_raises_actionable_error(self) -> None:
        """Google omits refresh_token on a repeat consent grant without
        prompt=consent -- should never happen given build_authorization_url
        always sets prompt=consent, but must fail loudly if it does.
        """

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"access_token": "at_xyz"})

        with pytest.raises(GmailApiError, match="did not return a refresh token"):
            await exchange_code_for_tokens(
                "auth-code", http_client=_client_with_handler(handler)
            )

    @pytest.mark.anyio
    async def test_userinfo_failure_raises_gmail_api_error(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if "userinfo" in str(request.url):
                return httpx.Response(500)
            return httpx.Response(
                200, json={"refresh_token": "rt_abc", "access_token": "at_xyz"}
            )

        with pytest.raises(GmailApiError):
            await exchange_code_for_tokens(
                "auth-code", http_client=_client_with_handler(handler)
            )


class TestFetchRecentMessages:
    @pytest.mark.anyio
    async def test_revoked_refresh_token_raises_invalid_grant(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(400, text='{"error": "invalid_grant"}')

        with pytest.raises(GmailApiError) as exc_info:
            await fetch_recent_messages(
                "revoked-token", http_client=_client_with_handler(handler)
            )
        assert exc_info.value.invalid_grant is True

    @pytest.mark.anyio
    async def test_successful_fetch_returns_parsed_messages(self) -> None:
        plain_text = "Pay Rs 5000 now to claim your prize."

        def handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "/token" in url:
                return httpx.Response(200, json={"access_token": "at_xyz"})
            if url.endswith("/messages") or "maxResults" in url:
                return httpx.Response(
                    200, json={"messages": [{"id": "msg1"}, {"id": "msg2"}]}
                )
            if "/messages/msg1" in url:
                return httpx.Response(
                    200,
                    json={
                        "id": "msg1",
                        "payload": {
                            "mimeType": "text/plain",
                            "body": {"data": _b64(plain_text)},
                            "headers": [
                                {"name": "From", "value": "scammer@example.com"},
                                {"name": "Subject", "value": "You won!"},
                                {
                                    "name": "Date",
                                    "value": "Fri, 05 Sep 2026 10:00:00 +0000",
                                },
                            ],
                        },
                    },
                )
            if "/messages/msg2" in url:
                # Simulate one unreadable message -- should be skipped,
                # not fail the whole batch.
                return httpx.Response(500)
            return httpx.Response(404)

        messages = await fetch_recent_messages(
            "valid-refresh-token", http_client=_client_with_handler(handler)
        )

        assert len(messages) == 1
        assert messages[0].message_id == "msg1"
        assert messages[0].sender == "scammer@example.com"
        assert messages[0].subject == "You won!"
        assert messages[0].body == plain_text
        assert messages[0].received_at.startswith("2026-09-05")


class TestExtractBody:
    def test_prefers_plain_text_at_top_level(self) -> None:
        payload = {
            "mimeType": "text/plain",
            "body": {"data": _b64("hello world")},
        }
        assert _extract_body(payload) == "hello world"

    def test_prefers_plain_text_part_over_html_part(self) -> None:
        payload = {
            "mimeType": "multipart/alternative",
            "parts": [
                {"mimeType": "text/html", "body": {"data": _b64("<p>hi</p>")}},
                {"mimeType": "text/plain", "body": {"data": _b64("hi")}},
            ],
        }
        assert _extract_body(payload) == "hi"

    def test_falls_back_to_stripped_html_when_no_plain_text(self) -> None:
        payload = {
            "mimeType": "multipart/alternative",
            "parts": [
                {
                    "mimeType": "text/html",
                    "body": {"data": _b64("<p>Hello <b>there</b></p>")},
                },
            ],
        }
        assert _extract_body(payload) == "Hello there"

    def test_no_text_content_returns_empty_string(self) -> None:
        payload = {"mimeType": "multipart/mixed", "parts": []}
        assert _extract_body(payload) == ""
