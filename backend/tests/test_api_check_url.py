"""Tests for POST /v1/check with source_type=URL (Phase 4 Step 6 wiring).

These exercise the full combined pipeline: parse_url() -> local checks
+ concurrent external providers -> calculate_risk() -> CheckResponse.
External providers are monkeypatched at the app.graph.nodes import site
(as of Phase 7, this is where the LangGraph extract_evidence node calls
them -- previously app.api.check) so no real network calls occur and
provider behavior is fully controlled.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

import app.graph.nodes as nodes_module
from app.main import app
from app.risk.evidence import Evidence

client = TestClient(app)


def _available_google_evidence() -> Evidence:
    return Evidence(
        category="url",
        signal="GOOGLE_SAFE_BROWSING",
        points=30,
        reason="Confirmed threat.",
        source="google_safe_browsing",
    )


def _available_virustotal_evidence() -> Evidence:
    return Evidence(
        category="url",
        signal="VIRUSTOTAL_MALICIOUS",
        points=25,
        reason="Multiple engines flagged this URL.",
        source="virustotal",
    )


class TestLocalChecksOnly:
    """Both providers unavailable (no API keys) -- exercises real adapters."""

    def test_deceptive_url_combines_local_signals_with_zero_provider_points(
        self,
    ) -> None:
        response = client.post(
            "/v1/check",
            json={
                "source_type": "URL",
                "payload": {"url": "http://sbi-kyc-update.xyz/login"},
            },
        )
        assert response.status_code == 200
        body = response.json()
        assert body["risk"]["band"] == "UNCERTAIN"

        provider_evidence = [
            e for e in body["evidence"] if e["source"] in ("google_safe_browsing", "virustotal")
        ]
        for item in provider_evidence:
            assert item["availability"] == "unavailable"
            assert item["points"] == 0

    def test_legitimate_url_is_clean(self) -> None:
        """A legitimate URL scores LOW/0. Provider evidence may still be
        present as 'unavailable' (no API keys configured in this test
        environment) -- that is correct and expected, not a false
        positive. Only local heuristic signals (lookalike, HTTP, TLD,
        etc.) would indicate an actual problem, and none should fire
        here.
        """
        response = client.post(
            "/v1/check",
            json={
                "source_type": "URL",
                "payload": {"url": "https://www.sbi.co.in/personal-banking"},
            },
        )
        assert response.status_code == 200
        body = response.json()
        assert body["risk"]["score"] == 0
        assert body["risk"]["band"] == "LOW"

        # No local heuristic should have fired for this legitimate URL.
        local_signals = {
            e["signal"]
            for e in body["evidence"]
            if e["source"] not in ("google_safe_browsing", "virustotal")
        }
        assert local_signals == set()

        # Any provider evidence present must be unavailable/zero-point,
        # not a false "clean" claim manufactured from nothing.
        for item in body["evidence"]:
            if item["source"] in ("google_safe_browsing", "virustotal"):
                assert item["availability"] == "unavailable"
                assert item["points"] == 0

    def test_missing_url_returns_400(self) -> None:
        response = client.post(
            "/v1/check", json={"source_type": "URL", "payload": {}}
        )
        assert response.status_code == 400


class TestWithMockedProviders:
    """Providers monkeypatched to return controlled results, no network."""

    def test_confirmed_google_threat_alone_reaches_high_via_url_cap(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def fake_google(url: str):
            return _available_google_evidence()

        async def fake_virustotal(url: str):
            return None

        monkeypatch.setattr(
            nodes_module, "check_url_google_safe_browsing", fake_google
        )
        monkeypatch.setattr(nodes_module, "check_url_virustotal", fake_virustotal)

        response = client.post(
            "/v1/check",
            json={
                "source_type": "URL",
                "payload": {"url": "https://clean-domain-example.com"},
            },
        )
        assert response.status_code == 200
        body = response.json()
        # 30 points, under the 35 cap, band UNCERTAIN (25-39) -- Google
        # alone confirming a threat is strong but still below MEDIUM/HIGH
        # without any corroborating local or VirusTotal signal.
        assert body["risk"]["score"] == 30
        assert body["risk"]["band"] == "UNCERTAIN"

    def test_both_providers_confirm_threat_hits_url_cap_of_35(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def fake_google(url: str):
            return _available_google_evidence()

        async def fake_virustotal(url: str):
            return _available_virustotal_evidence()

        monkeypatch.setattr(
            nodes_module, "check_url_google_safe_browsing", fake_google
        )
        monkeypatch.setattr(nodes_module, "check_url_virustotal", fake_virustotal)

        response = client.post(
            "/v1/check",
            json={
                "source_type": "URL",
                "payload": {"url": "https://clean-domain-example.com"},
            },
        )
        assert response.status_code == 200
        body = response.json()
        # 30 + 25 = 55 raw, capped at URL_POINTS_CAP=35.
        assert body["risk"]["score"] == 35
        assert body["risk"]["band"] == "UNCERTAIN"

    def test_unexpected_provider_exception_does_not_crash_request(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Defense-in-depth test: a provider raising an unexpected
        exception (not one of the handled failure paths inside the
        adapter itself) must still result in a 200 response with
        unavailable evidence, not a 500 error.
        """

        async def broken_google(url: str):
            raise RuntimeError("Simulated unexpected bug in the adapter")

        async def fake_virustotal(url: str):
            return None

        monkeypatch.setattr(
            nodes_module, "check_url_google_safe_browsing", broken_google
        )
        monkeypatch.setattr(nodes_module, "check_url_virustotal", fake_virustotal)

        response = client.post(
            "/v1/check",
            json={
                "source_type": "URL",
                "payload": {"url": "https://example.com"},
            },
        )
        assert response.status_code == 200
        body = response.json()
        google_evidence = next(
            e for e in body["evidence"] if e["signal"] == "GOOGLE_SAFE_BROWSING"
        )
        assert google_evidence["availability"] == "unavailable"
        assert google_evidence["points"] == 0
