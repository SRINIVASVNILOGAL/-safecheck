"""Tests for POST /v1/check using FastAPI's TestClient.

These exercise the full wiring: HTTP request -> app.api.check ->
run_all_rules() -> calculate_risk() -> generate_explanation() ->
CheckResponse -> HTTP response. This is distinct from the unit tests in
test_rules.py and test_risk_engine.py, which call the underlying functions
directly without going through FastAPI at all.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


class TestTextSourceType:
    def test_lottery_scam_text_returns_uncertain(self) -> None:
        response = client.post(
            "/v1/check",
            json={
                "source_type": "TEXT",
                "payload": {
                    "text": (
                        "Congratulations! You have won a lottery prize of "
                        "Rs 50000. Pay processing fee immediately to claim "
                        "your prize."
                    )
                },
            },
        )
        assert response.status_code == 200
        body = response.json()
        assert body["risk"]["score"] == 30
        assert body["risk"]["band"] == "UNCERTAIN"
        assert body["source_type"] == "TEXT"
        assert body["case_id"].startswith("case_")
        signals = {e["signal"] for e in body["evidence"]}
        assert signals == {"URGENT_PAYMENT", "LOTTERY_OR_PRIZE"}

    def test_legitimate_text_returns_low_with_no_evidence(self) -> None:
        response = client.post(
            "/v1/check",
            json={
                "source_type": "TEXT",
                "payload": {
                    "text": "Rs 500 sent successfully to Ravi through UPI. Reference 123456789."
                },
            },
        )
        assert response.status_code == 200
        body = response.json()
        assert body["risk"]["score"] == 0
        assert body["risk"]["band"] == "LOW"
        assert body["evidence"] == []
        assert body["safe_actions"] == []

    def test_missing_text_returns_400(self) -> None:
        response = client.post(
            "/v1/check",
            json={"source_type": "TEXT", "payload": {}},
        )
        assert response.status_code == 400

    def test_blank_text_returns_400(self) -> None:
        response = client.post(
            "/v1/check",
            json={"source_type": "TEXT", "payload": {"text": "   "}},
        )
        assert response.status_code == 400


class TestEmailSourceType:
    def test_phishing_email_returns_medium(self) -> None:
        response = client.post(
            "/v1/check",
            json={
                "source_type": "EMAIL",
                "payload": {
                    "sender": "support@example.com",
                    "subject": "Urgent: verify your account",
                    "body": (
                        "This is calling from your bank official. Your "
                        "account will be blocked today. Please share OTP "
                        "immediately to verify."
                    ),
                },
            },
        )
        assert response.status_code == 200
        body = response.json()
        assert body["risk"]["score"] == 45
        assert body["risk"]["band"] == "MEDIUM"
        assert body["source_type"] == "EMAIL"

    def test_missing_body_returns_400(self) -> None:
        response = client.post(
            "/v1/check",
            json={
                "source_type": "EMAIL",
                "payload": {"sender": "a@example.com", "subject": "hi"},
            },
        )
        assert response.status_code == 400

    def test_subject_is_included_in_analysis(self) -> None:
        """A rule-triggering phrase in the subject line must also be caught."""
        response = client.post(
            "/v1/check",
            json={
                "source_type": "EMAIL",
                "payload": {
                    "sender": "a@example.com",
                    "subject": "Please share your OTP now",
                    "body": "Thank you.",
                },
            },
        )
        assert response.status_code == 200
        body = response.json()
        signals = {e["signal"] for e in body["evidence"]}
        assert "OTP_REQUEST" in signals


class TestUrlSourceType:
    def test_url_without_analyzer_returns_low_with_no_evidence(self) -> None:
        """No URL analyzer exists yet -- documents current, honest behavior.

        This is not a claim that the URL is safe. It reflects that only
        the rule engine exists as of this phase; a URL analyzer is a
        separate, later phase.
        """
        response = client.post(
            "/v1/check",
            json={
                "source_type": "URL",
                "payload": {"url": "https://example.com/login"},
            },
        )
        assert response.status_code == 200
        body = response.json()
        assert body["risk"]["score"] == 0
        assert body["risk"]["band"] == "LOW"
        assert body["evidence"] == []

    def test_missing_url_returns_400(self) -> None:
        response = client.post(
            "/v1/check",
            json={"source_type": "URL", "payload": {}},
        )
        assert response.status_code == 400


class TestHealthEndpointStillWorks:
    def test_health_check_unaffected_by_new_router(self) -> None:
        response = client.get("/v1/health")
        assert response.status_code == 200
        assert response.json()["status"] == "ok"
