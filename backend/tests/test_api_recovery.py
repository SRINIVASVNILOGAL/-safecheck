"""Tests for POST/GET /v1/recovery/* endpoints.

app.db and app.integrations.gmail are monkeypatched at their import site
in app.api.recovery, mirroring test_api_email.py's pattern -- no real
database file or network calls.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

import app.api.recovery as recovery_module
from app.db import GmailAccount, RecoveryReport
from app.integrations.gmail import GmailApiError
from app.main import app

client = TestClient(app)


def _base_payload(**overrides):
    payload = {
        "case_id": "case_abc123",
        "risk_score": 55,
        "risk_band": "MEDIUM",
        "signals": ["FEE_OR_FINE_SCAM", "URGENT_PAYMENT"],
        "context_text": "Alert: You have an unpaid toll fee from SBI. Pay now at kredt.be/3u9CoOh",
    }
    payload.update(overrides)
    return payload


class TestCreateRecoveryDraft:
    def test_identifies_organization_and_generates_draft(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def fake_get_account():
            return None

        stored: dict = {}

        async def fake_create_report(**kwargs):
            stored.update(kwargs)
            return RecoveryReport(
                id="recovery_test1",
                case_id=kwargs["case_id"],
                org_key=kwargs["org_key"],
                org_display_name=kwargs["org_display_name"],
                recipient_email=kwargs["recipient_email"],
                risk_score=kwargs["risk_score"],
                risk_band=kwargs["risk_band"],
                subject=kwargs["subject"],
                body=kwargs["body"],
                status="DRAFT",
            )

        monkeypatch.setattr(recovery_module, "get_gmail_account", fake_get_account)
        monkeypatch.setattr(recovery_module, "create_recovery_report", fake_create_report)

        response = client.post("/v1/recovery/draft", json=_base_payload())
        assert response.status_code == 200
        body = response.json()
        assert body["organization"]["key"] == "SBI"
        assert any(item["key"] == "NATIONAL_CYBERCRIME" for item in body["alternate_organizations"])
        assert body["subject"]
        assert body["body"]
        assert body["can_send"] is False  # no Gmail account connected
        assert stored["org_key"] == "SBI"

    def test_no_specific_org_falls_back_to_national_cybercrime(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def fake_get_account():
            return None

        async def fake_create_report(**kwargs):
            return RecoveryReport(id="recovery_test2", status="DRAFT", **kwargs)

        monkeypatch.setattr(recovery_module, "get_gmail_account", fake_get_account)
        monkeypatch.setattr(recovery_module, "create_recovery_report", fake_create_report)

        response = client.post(
            "/v1/recovery/draft",
            json=_base_payload(context_text="You have won a lottery, click here to claim your prize now."),
        )
        assert response.status_code == 200
        assert response.json()["organization"]["key"] == "NATIONAL_CYBERCRIME"

    def test_invalid_org_key_returns_400(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def fake_get_account():
            return None

        monkeypatch.setattr(recovery_module, "get_gmail_account", fake_get_account)

        response = client.post("/v1/recovery/draft", json=_base_payload(org_key="NOT_A_REAL_ORG"))
        assert response.status_code == 400

    def test_can_send_true_when_gmail_connected_and_org_has_email(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def fake_get_account():
            return GmailAccount(id=1, email_address="user@gmail.com", refresh_token="rt")

        async def fake_create_report(**kwargs):
            return RecoveryReport(id="recovery_test3", status="DRAFT", **kwargs)

        monkeypatch.setattr(recovery_module, "get_gmail_account", fake_get_account)
        monkeypatch.setattr(recovery_module, "create_recovery_report", fake_create_report)

        response = client.post("/v1/recovery/draft", json=_base_payload())
        assert response.status_code == 200
        assert response.json()["can_send"] is True


class TestGetRecoveryDraft:
    def test_not_found_returns_404(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def fake_get_report(report_id):
            return None

        monkeypatch.setattr(recovery_module, "get_recovery_report", fake_get_report)

        response = client.get("/v1/recovery/recovery_missing")
        assert response.status_code == 404


class TestConfirmRecoveryReport:
    def test_unconfirmed_returns_400(self) -> None:
        response = client.post(
            "/v1/recovery/recovery_x/confirm",
            json={"confirmed": False, "idempotency_key": "key12345", "subject": "s", "body": "b"},
        )
        assert response.status_code == 400

    def test_body_with_link_rejected(self) -> None:
        response = client.post(
            "/v1/recovery/recovery_x/confirm",
            json={"confirmed": True, "idempotency_key": "key12345", "subject": "s", "body": "visit https://evil.example"},
        )
        assert response.status_code == 400

    def test_missing_report_returns_404(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def fake_get_report(report_id):
            return None

        monkeypatch.setattr(recovery_module, "get_recovery_report", fake_get_report)

        response = client.post(
            "/v1/recovery/recovery_missing/confirm",
            json={"confirmed": True, "idempotency_key": "key12345", "subject": "s", "body": "b"},
        )
        assert response.status_code == 404

    def test_no_recipient_email_returns_400(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def fake_get_report(report_id):
            return RecoveryReport(
                id=report_id, case_id="c1", org_key="NATIONAL_CYBERCRIME",
                org_display_name="National Cyber Crime Reporting Portal",
                recipient_email=None, risk_score=50, risk_band="MEDIUM",
                subject="s", body="b", status="DRAFT",
            )

        monkeypatch.setattr(recovery_module, "get_recovery_report", fake_get_report)

        response = client.post(
            "/v1/recovery/recovery_1/confirm",
            json={"confirmed": True, "idempotency_key": "key12345", "subject": "s", "body": "b"},
        )
        assert response.status_code == 400

    def test_no_gmail_account_returns_400(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def fake_get_report(report_id):
            return RecoveryReport(
                id=report_id, case_id="c1", org_key="SBI", org_display_name="SBI",
                recipient_email="customercare@sbi.co.in", risk_score=50, risk_band="MEDIUM",
                subject="s", body="b", status="DRAFT",
            )

        async def fake_get_account():
            return None

        monkeypatch.setattr(recovery_module, "get_recovery_report", fake_get_report)
        monkeypatch.setattr(recovery_module, "get_gmail_account", fake_get_account)

        response = client.post(
            "/v1/recovery/recovery_1/confirm",
            json={"confirmed": True, "idempotency_key": "key12345", "subject": "s", "body": "b"},
        )
        assert response.status_code == 400

    def test_successful_send_returns_sent_status(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def fake_get_report(report_id):
            return RecoveryReport(
                id=report_id, case_id="c1", org_key="SBI", org_display_name="SBI",
                recipient_email="customercare@sbi.co.in", risk_score=50, risk_band="MEDIUM",
                subject="s", body="b", status="DRAFT",
            )

        async def fake_get_account():
            return GmailAccount(id=1, email_address="user@gmail.com", refresh_token="rt")

        async def fake_claim(report_id, *, idempotency_key, subject, body):
            return RecoveryReport(
                id=report_id, case_id="c1", org_key="SBI", org_display_name="SBI",
                recipient_email="customercare@sbi.co.in", risk_score=50, risk_band="MEDIUM",
                subject=subject, body=body, status="SENDING",
            ), True

        async def fake_send(refresh_token, *, from_address, recipient, subject, body, warning_id):
            return "gmail_msg_123"

        finished: dict = {}

        async def fake_finish(report_id, *, status, gmail_message_id=None, error=None):
            finished.update(status=status, gmail_message_id=gmail_message_id, error=error)

        monkeypatch.setattr(recovery_module, "get_recovery_report", fake_get_report)
        monkeypatch.setattr(recovery_module, "get_gmail_account", fake_get_account)
        monkeypatch.setattr(recovery_module, "claim_recovery_report", fake_claim)
        monkeypatch.setattr(recovery_module, "send_warning_message", fake_send)
        monkeypatch.setattr(recovery_module, "finish_recovery_report", fake_finish)

        response = client.post(
            "/v1/recovery/recovery_1/confirm",
            json={"confirmed": True, "idempotency_key": "key12345", "subject": "s", "body": "b"},
        )
        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "SENT"
        assert body["gmail_message_id"] == "gmail_msg_123"
        assert finished["status"] == "SENT"

    def test_send_failure_returns_failed_status(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def fake_get_report(report_id):
            return RecoveryReport(
                id=report_id, case_id="c1", org_key="SBI", org_display_name="SBI",
                recipient_email="customercare@sbi.co.in", risk_score=50, risk_band="MEDIUM",
                subject="s", body="b", status="DRAFT",
            )

        async def fake_get_account():
            return GmailAccount(id=1, email_address="user@gmail.com", refresh_token="rt")

        async def fake_claim(report_id, *, idempotency_key, subject, body):
            return RecoveryReport(
                id=report_id, case_id="c1", org_key="SBI", org_display_name="SBI",
                recipient_email="customercare@sbi.co.in", risk_score=50, risk_band="MEDIUM",
                subject=subject, body=body, status="SENDING",
            ), True

        async def fake_send(refresh_token, *, from_address, recipient, subject, body, warning_id):
            raise GmailApiError("Gmail send permission is missing.")

        monkeypatch.setattr(recovery_module, "get_recovery_report", fake_get_report)
        monkeypatch.setattr(recovery_module, "get_gmail_account", fake_get_account)
        monkeypatch.setattr(recovery_module, "claim_recovery_report", fake_claim)
        monkeypatch.setattr(recovery_module, "send_warning_message", fake_send)
        monkeypatch.setattr(recovery_module, "finish_recovery_report", lambda *a, **k: _noop())

        response = client.post(
            "/v1/recovery/recovery_1/confirm",
            json={"confirmed": True, "idempotency_key": "key12345", "subject": "s", "body": "b"},
        )
        assert response.status_code == 200
        assert response.json()["status"] == "FAILED"


async def _noop() -> None:
    return None
