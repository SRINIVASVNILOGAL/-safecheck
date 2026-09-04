"""Tests for app.integrations.virustotal.

Mirrors test_google_safe_browsing.py's structure using httpx.MockTransport.
The 404 case is the most important scenario specific to this adapter: it
must be treated as "unavailable" (VirusTotal has no report for this URL),
never as "clean" -- those are different things, and conflating them would
be a real safety bug (a brand-new phishing URL with no VirusTotal history
would otherwise appear falsely safe).
"""

from __future__ import annotations

import httpx
import pytest

from app.integrations.virustotal import VIRUSTOTAL_POINTS, check_url_virustotal


@pytest.fixture(autouse=True)
def _api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-key-456")


def _client_with_handler(handler) -> httpx.AsyncClient:
    transport = httpx.MockTransport(handler)
    return httpx.AsyncClient(transport=transport)


def _stats_response(malicious: int = 0, suspicious: int = 0) -> dict:
    return {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": 60,
                    "undetected": 10,
                }
            }
        }
    }


class TestMissingApiKey:
    @pytest.mark.anyio
    async def test_missing_api_key_returns_unavailable(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
        result = await check_url_virustotal("https://example.com")
        assert result is not None
        assert result.availability == "unavailable"
        assert result.points == 0


class TestMaliciousResult:
    @pytest.mark.anyio
    async def test_malicious_engines_at_threshold_returns_available_evidence(
        self,
    ) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=_stats_response(malicious=2))

        client = _client_with_handler(handler)
        result = await check_url_virustotal(
            "https://phishing-example.com", http_client=client
        )
        assert result is not None
        assert result.signal == "VIRUSTOTAL_MALICIOUS"
        assert result.points == VIRUSTOTAL_POINTS
        assert result.availability == "available"

    @pytest.mark.anyio
    async def test_suspicious_engines_at_threshold_returns_available_evidence(
        self,
    ) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=_stats_response(suspicious=3))

        client = _client_with_handler(handler)
        result = await check_url_virustotal(
            "https://suspicious-example.com", http_client=client
        )
        assert result is not None
        assert result.signal == "VIRUSTOTAL_MALICIOUS"

    @pytest.mark.anyio
    async def test_one_malicious_engine_below_threshold_is_not_flagged(self) -> None:
        """1 malicious engine is below the threshold of 2 -- not flagged.

        A single engine's opinion is not treated as confirmed malicious;
        this avoids over-reacting to one outlier antivirus vendor.
        """
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=_stats_response(malicious=1))

        client = _client_with_handler(handler)
        result = await check_url_virustotal(
            "https://borderline-example.com", http_client=client
        )
        assert result is None


class TestCleanResult:
    @pytest.mark.anyio
    async def test_zero_detections_returns_none(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=_stats_response())

        client = _client_with_handler(handler)
        result = await check_url_virustotal(
            "https://legit-site.com", http_client=client
        )
        assert result is None


class TestNoReportExists:
    @pytest.mark.anyio
    async def test_404_returns_unavailable_not_clean(self) -> None:
        """The most important VirusTotal-specific test.

        A 404 means VirusTotal has never seen this URL -- genuinely
        unknown. This must NOT be treated as "clean", since that would
        make brand-new phishing URLs (which have no VirusTotal history
        yet) appear falsely safe.
        """
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(404, json={"error": "NotFoundError"})

        client = _client_with_handler(handler)
        result = await check_url_virustotal(
            "https://brand-new-domain.com", http_client=client
        )
        assert result is not None
        assert result.availability == "unavailable"
        assert result.points == 0
        assert "no existing report" in result.reason.lower()


class TestFailureModes:
    @pytest.mark.anyio
    async def test_rate_limit_429_returns_unavailable(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(429, text="Rate limit exceeded")

        client = _client_with_handler(handler)
        result = await check_url_virustotal(
            "https://example.com", http_client=client
        )
        assert result is not None
        assert result.availability == "unavailable"
        assert result.points == 0
        assert "rate limit" in result.reason.lower()

    @pytest.mark.anyio
    async def test_other_non_200_status_returns_unavailable(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(500, text="Internal Server Error")

        client = _client_with_handler(handler)
        result = await check_url_virustotal(
            "https://example.com", http_client=client
        )
        assert result is not None
        assert result.availability == "unavailable"
        assert result.points == 0

    @pytest.mark.anyio
    async def test_malformed_json_returns_unavailable(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text="not valid json{{{")

        client = _client_with_handler(handler)
        result = await check_url_virustotal(
            "https://example.com", http_client=client
        )
        assert result is not None
        assert result.availability == "unavailable"
        assert result.points == 0

    @pytest.mark.anyio
    async def test_missing_expected_fields_returns_unavailable(self) -> None:
        """Response is valid JSON but doesn't have the expected shape."""
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"data": {"attributes": {}}})

        client = _client_with_handler(handler)
        result = await check_url_virustotal(
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
        result = await check_url_virustotal(
            "https://example.com", http_client=client
        )
        assert result is not None
        assert result.availability == "unavailable"
        assert result.points == 0

    @pytest.mark.anyio
    async def test_connection_error_returns_unavailable(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("Simulated connection failure")

        client = _client_with_handler(handler)
        result = await check_url_virustotal(
            "https://example.com", http_client=client
        )
        assert result is not None
        assert result.availability == "unavailable"
        assert result.points == 0


class TestUrlIdEncoding:
    def test_no_padding_characters_in_encoded_id(self) -> None:
        from app.integrations.virustotal import _url_id

        encoded = _url_id("https://example.com/")
        assert "=" not in encoded

    def test_encoding_is_deterministic(self) -> None:
        from app.integrations.virustotal import _url_id

        assert _url_id("https://example.com/") == _url_id("https://example.com/")
