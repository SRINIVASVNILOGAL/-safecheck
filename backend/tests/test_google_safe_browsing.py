"""Tests for app.integrations.google_safe_browsing.

Uses httpx.MockTransport to simulate every response scenario (threat
match, clean result, non-200 status, malformed JSON) without any real
network calls. Timeout and connection-error scenarios use a custom
transport that raises the relevant httpx exception directly, which is
more reliable than trying to trigger a real timeout.

The API key is set via monkeypatch for tests that need to get past the
"no API key configured" short-circuit, and explicitly cleared for the
one test that verifies that exact path.
"""

from __future__ import annotations

import httpx
import pytest

from app.integrations.google_safe_browsing import (
    GOOGLE_SAFE_BROWSING_POINTS,
    check_url_google_safe_browsing,
)


@pytest.fixture(autouse=True)
def _api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """Most tests need an API key configured to get past the short-circuit.

    The one test that specifically checks the missing-key path clears it
    explicitly within that test.
    """
    monkeypatch.setenv("GOOGLE_SAFE_BROWSING_API_KEY", "test-key-123")


def _client_with_handler(handler) -> httpx.AsyncClient:
    transport = httpx.MockTransport(handler)
    return httpx.AsyncClient(transport=transport)


class TestMissingApiKey:
    @pytest.mark.anyio
    async def test_missing_api_key_returns_unavailable(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("GOOGLE_SAFE_BROWSING_API_KEY", raising=False)
        result = await check_url_google_safe_browsing("https://example.com")
        assert result is not None
        assert result.availability == "unavailable"
        assert result.points == 0


class TestThreatMatchFound:
    @pytest.mark.anyio
    async def test_confirmed_threat_returns_available_evidence(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "matches": [
                        {
                            "threatType": "SOCIAL_ENGINEERING",
                            "platformType": "ANY_PLATFORM",
                            "threat": {"url": "https://phishing-example.com"},
                        }
                    ]
                },
            )

        client = _client_with_handler(handler)
        result = await check_url_google_safe_browsing(
            "https://phishing-example.com", http_client=client
        )
        assert result is not None
        assert result.signal == "GOOGLE_SAFE_BROWSING"
        assert result.category == "url"
        assert result.points == GOOGLE_SAFE_BROWSING_POINTS
        assert result.availability == "available"
        assert "SOCIAL_ENGINEERING" in result.reason


class TestCleanResult:
    @pytest.mark.anyio
    async def test_no_matches_returns_none(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={})

        client = _client_with_handler(handler)
        result = await check_url_google_safe_browsing(
            "https://legit-site.com", http_client=client
        )
        assert result is None

    @pytest.mark.anyio
    async def test_empty_matches_list_returns_none(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"matches": []})

        client = _client_with_handler(handler)
        result = await check_url_google_safe_browsing(
            "https://legit-site.com", http_client=client
        )
        assert result is None


class TestFailureModes:
    @pytest.mark.anyio
    async def test_non_200_status_returns_unavailable(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(403, text="Forbidden")

        client = _client_with_handler(handler)
        result = await check_url_google_safe_browsing(
            "https://example.com", http_client=client
        )
        assert result is not None
        assert result.availability == "unavailable"
        assert result.points == 0
        assert "403" in result.reason

    @pytest.mark.anyio
    async def test_malformed_json_returns_unavailable(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text="not valid json{{{")

        client = _client_with_handler(handler)
        result = await check_url_google_safe_browsing(
            "https://example.com", http_client=client
        )
        assert result is not None
        assert result.availability == "unavailable"
        assert result.points == 0

    @pytest.mark.anyio
    async def test_timeout_returns_unavailable(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.TimeoutException("Simulated timeout")

        client = _client_with_handler(handler)
        result = await check_url_google_safe_browsing(
            "https://example.com", http_client=client
        )
        assert result is not None
        assert result.availability == "unavailable"
        assert result.points == 0
        assert "timed out" in result.reason.lower()

    @pytest.mark.anyio
    async def test_connection_error_returns_unavailable(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("Simulated connection failure")

        client = _client_with_handler(handler)
        result = await check_url_google_safe_browsing(
            "https://example.com", http_client=client
        )
        assert result is not None
        assert result.availability == "unavailable"
        assert result.points == 0


class TestUnavailableEvidenceNeverCarriesPoints:
    """Cross-check against the Evidence model's own enforced invariant.

    This isn't testing something the adapter could realistically get
    wrong given the code structure, but it documents the expectation
    explicitly at the integration-test level too, not just in
    test_evidence.py.
    """

    @pytest.mark.anyio
    async def test_all_unavailable_paths_have_zero_points(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("GOOGLE_SAFE_BROWSING_API_KEY", raising=False)
        result = await check_url_google_safe_browsing("https://example.com")
        assert result.points == 0
