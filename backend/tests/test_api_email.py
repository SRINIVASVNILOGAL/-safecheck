"""Tests for POST/GET /v1/email/* endpoints.

app.db (SQLite persistence) and app.integrations.gmail (real network
calls) are both monkeypatched at their import site in app.api.email, so
these tests exercise the endpoint logic and error-status mapping without
touching a real database file or making real HTTP requests to Google.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

import app.api.email as email_module
from app.db import GmailAccount
from app.integrations.gmail import FetchedMessage, GmailApiError, TokenExchangeResult
from app.main import app

client = TestClient(app)


class TestEmailStatus:
    def test_no_account_connected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def fake_get_account():
            return None

        monkeypatch.setattr(email_module, "get_gmail_account", fake_get_account)

        response = client.get("/v1/email/status")
        assert response.status_code == 200
        body = response.json()
        assert body["connected"] is False
        assert body["email_address"] is None

    def test_account_connected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def fake_get_account():
            return GmailAccount(
                id=1,
                email_address="user@gmail.com",
                refresh_token="rt_abc",
                last_checked_at=datetime(2026, 9, 5, 10, 0, tzinfo=timezone.utc),
            )

        monkeypatch.setattr(email_module, "get_gmail_account", fake_get_account)

        response = client.get("/v1/email/status")
        assert response.status_code == 200
        body = response.json()
        assert body["connected"] is True
        assert body["email_address"] == "user@gmail.com"
        assert body["last_checked_at"] is not None


class TestConnectStart:
    def test_missing_client_credentials_returns_500(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Settings is a frozen dataclass -- replace the module-level
        # `settings` singleton wholesale rather than mutating a field.
        from dataclasses import replace

        monkeypatch.setattr(
            email_module,
            "settings",
            replace(email_module.settings, google_client_id="", google_client_secret=""),
        )

        response = client.post("/v1/email/connect/start")
        assert response.status_code == 500

    def test_configured_returns_authorization_url(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from dataclasses import replace

        import app.integrations.gmail as gmail_module

        new_settings = replace(
            email_module.settings,
            google_client_id="test-client-id",
            google_client_secret="test-client-secret",
        )
        # connect_start checks credentials via email_module.settings;
        # build_authorization_url (called from app.integrations.gmail)
        # reads its own imported `settings` reference -- both must be
        # patched since Python binds the name at import time in each
        # module's namespace.
        monkeypatch.setattr(email_module, "settings", new_settings)
        monkeypatch.setattr(gmail_module, "settings", new_settings)

        response = client.post("/v1/email/connect/start")
        assert response.status_code == 200
        body = response.json()
        assert "accounts.google.com" in body["authorization_url"]


class TestConnectCallback:
    def test_user_denied_consent_redirects_with_reason(self) -> None:
        response = client.get(
            "/v1/email/connect/callback",
            params={"error": "access_denied"},
            follow_redirects=False,
        )
        assert response.status_code in (302, 307)
        assert "connected=false" in response.headers["location"]
        assert "access_denied" in response.headers["location"]

    def test_unknown_state_redirects_with_invalid_state(self) -> None:
        response = client.get(
            "/v1/email/connect/callback",
            params={"code": "some-code", "state": "never-issued"},
            follow_redirects=False,
        )
        assert response.status_code in (302, 307)
        assert "invalid_state" in response.headers["location"]

    def test_successful_exchange_stores_account_and_redirects_connected(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Seed a valid pending state the way connect_start would.
        state = "valid-state-123"
        email_module._pending_oauth_states.add(state)

        async def fake_exchange(code: str):
            return TokenExchangeResult(
                refresh_token="rt_new", email_address="user@gmail.com"
            )

        stored: dict = {}

        async def fake_upsert(email_address: str, refresh_token: str):
            stored["email_address"] = email_address
            stored["refresh_token"] = refresh_token

        monkeypatch.setattr(email_module, "exchange_code_for_tokens", fake_exchange)
        monkeypatch.setattr(email_module, "upsert_gmail_account", fake_upsert)

        response = client.get(
            "/v1/email/connect/callback",
            params={"code": "auth-code", "state": state},
            follow_redirects=False,
        )
        assert response.status_code in (302, 307)
        assert "connected=true" in response.headers["location"]
        assert stored["email_address"] == "user@gmail.com"
        assert stored["refresh_token"] == "rt_new"
        # State must be consumed -- reusing it should fail as invalid.
        assert state not in email_module._pending_oauth_states

    def test_exchange_failure_redirects_with_error_reason(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        state = "valid-state-456"
        email_module._pending_oauth_states.add(state)

        async def fake_exchange(code: str):
            raise GmailApiError("Token exchange failed: HTTP 400")

        monkeypatch.setattr(email_module, "exchange_code_for_tokens", fake_exchange)

        response = client.get(
            "/v1/email/connect/callback",
            params={"code": "bad-code", "state": state},
            follow_redirects=False,
        )
        assert response.status_code in (302, 307)
        assert "connected=false" in response.headers["location"]


class TestCheckNow:
    def test_no_account_connected_returns_400(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def fake_get_account():
            return None

        monkeypatch.setattr(email_module, "get_gmail_account", fake_get_account)

        response = client.post("/v1/email/check-now")
        assert response.status_code == 400

    def test_revoked_token_returns_401(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def fake_get_account():
            return GmailAccount(id=1, email_address="user@gmail.com", refresh_token="rt")

        async def fake_fetch(refresh_token: str):
            raise GmailApiError("revoked", invalid_grant=True)

        monkeypatch.setattr(email_module, "get_gmail_account", fake_get_account)
        monkeypatch.setattr(email_module, "fetch_recent_messages", fake_fetch)

        response = client.post("/v1/email/check-now")
        assert response.status_code == 401

    def test_gmail_api_error_returns_502(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def fake_get_account():
            return GmailAccount(id=1, email_address="user@gmail.com", refresh_token="rt")

        async def fake_fetch(refresh_token: str):
            raise GmailApiError("Gmail API is down")

        monkeypatch.setattr(email_module, "get_gmail_account", fake_get_account)
        monkeypatch.setattr(email_module, "fetch_recent_messages", fake_fetch)

        response = client.post("/v1/email/check-now")
        assert response.status_code == 502

    def test_successful_check_runs_pipeline_per_message(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def fake_get_account():
            return GmailAccount(id=1, email_address="user@gmail.com", refresh_token="rt")

        async def fake_fetch(refresh_token: str):
            return [
                FetchedMessage(
                    message_id="msg1",
                    sender="scammer@example.com",
                    subject="You won!",
                    body="Pay Rs 5000 now to claim your lottery prize.",
                    received_at="2026-09-05T10:00:00+00:00",
                )
            ]

        updated: dict = {}

        async def fake_update_last_checked(when):
            updated["called"] = True

        monkeypatch.setattr(email_module, "get_gmail_account", fake_get_account)
        monkeypatch.setattr(email_module, "fetch_recent_messages", fake_fetch)
        monkeypatch.setattr(
            email_module, "update_last_checked_at", fake_update_last_checked
        )

        response = client.post("/v1/email/check-now")
        assert response.status_code == 200
        body = response.json()
        assert body["checked_count"] == 1
        result = body["results"][0]
        assert result["message_id"] == "msg1"
        assert result["from"] == "scammer@example.com"
        # This real text should trigger the real deterministic rule
        # engine (lottery + urgent payment patterns), proving the
        # message actually flows through the same pipeline as
        # POST /v1/check with source_type=EMAIL, not a stub.
        assert result["check"]["risk"]["score"] > 0
        assert updated["called"] is True

    def test_message_with_empty_body_does_not_crash_batch(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An attachment-only email with no plain/HTML text body must not
        abort the whole check-now batch via the EMAIL branch's
        require-non-empty-body validation.
        """

        async def fake_get_account():
            return GmailAccount(id=1, email_address="user@gmail.com", refresh_token="rt")

        async def fake_fetch(refresh_token: str):
            return [
                FetchedMessage(
                    message_id="msg1",
                    sender="someone@example.com",
                    subject="An attachment",
                    body="",
                    received_at="2026-09-05T10:00:00+00:00",
                )
            ]

        async def fake_update_last_checked(when):
            return None

        monkeypatch.setattr(email_module, "get_gmail_account", fake_get_account)
        monkeypatch.setattr(email_module, "fetch_recent_messages", fake_fetch)
        monkeypatch.setattr(
            email_module, "update_last_checked_at", fake_update_last_checked
        )

        response = client.post("/v1/email/check-now")
        assert response.status_code == 200
        assert response.json()["checked_count"] == 1
