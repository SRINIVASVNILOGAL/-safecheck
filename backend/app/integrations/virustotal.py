"""VirusTotal API v3 adapter.

Public API terms (per our own earlier research): free with a Community
account, but limited to 500 requests/day and 4 requests/minute, and must
not be used in commercial products/services. Treated here as an optional
second opinion alongside Google Safe Browsing, not a required check.

Uses the existing-report endpoint (GET /api/v3/urls/{url_id}) rather than
submitting a fresh scan and polling for completion. A fresh VirusTotal
scan can take 10-60+ seconds, which would make a synchronous /v1/check
request feel broken; the existing-report endpoint returns VirusTotal's
last known analysis for the URL immediately.

CRITICAL INVARIANT: same as google_safe_browsing.py -- any failure
(missing API key, network error, timeout, non-200, malformed response,
including the specific 404 "no report exists" case) must produce evidence
with availability="unavailable" and points=0. A 404 here means "VirusTotal
has never seen this URL," which is genuinely unknown, not "clean" -- do
not conflate the two.
"""

from __future__ import annotations

import base64
import os

import httpx

from app.risk.evidence import Evidence

_BASE_URL = "https://www.virustotal.com/api/v3/urls"
_DEFAULT_TIMEOUT_SECONDS = 5.0

VIRUSTOTAL_POINTS = 25

# Thresholds from the reference architecture we reviewed earlier: flag as
# malicious/suspicious if at least this many engines agree.
_MALICIOUS_ENGINE_THRESHOLD = 2
_SUSPICIOUS_ENGINE_THRESHOLD = 3


def _get_api_key() -> str | None:
    return os.getenv("VIRUSTOTAL_API_KEY") or None


def _get_timeout() -> float:
    raw = os.getenv("VIRUSTOTAL_TIMEOUT_SECONDS")
    if not raw:
        return _DEFAULT_TIMEOUT_SECONDS
    try:
        return float(raw)
    except ValueError:
        return _DEFAULT_TIMEOUT_SECONDS


def _url_id(url: str) -> str:
    """VirusTotal's required identifier: base64 URL-safe encoding, no padding."""
    encoded = base64.urlsafe_b64encode(url.encode("utf-8"))
    return encoded.decode("ascii").rstrip("=")


def _unavailable_evidence(reason: str) -> Evidence:
    return Evidence(
        category="url",
        signal="VIRUSTOTAL",
        points=0,
        reason=reason,
        source="virustotal",
        correlation_group="CORR_EXTERNAL_REPUTATION",
        availability="unavailable",
        confidence=0.0,
        severity="LOW",
    )


async def check_url_virustotal(
    url: str, http_client: httpx.AsyncClient | None = None
) -> Evidence | None:
    """Check `url` against VirusTotal's existing URL report.

    Args:
        url: the URL to check.
        http_client: optional injected httpx.AsyncClient, for testing
            without real network calls.

    Returns:
    - Evidence with category="url", signal="VIRUSTOTAL_MALICIOUS",
      points=25, availability="available" if enough engines flagged the
      URL as malicious/suspicious.
    - None if VirusTotal has a report and it is genuinely clean (below
      both thresholds).
    - Evidence with availability="unavailable", points=0 if the check
      could not be completed, INCLUDING a 404 (VirusTotal has no report
      for this URL at all -- unknown, not clean).
    """
    api_key = _get_api_key()
    if api_key is None:
        return _unavailable_evidence("VirusTotal API key is not configured.")

    endpoint = f"{_BASE_URL}/{_url_id(url)}"
    headers = {"x-apikey": api_key, "Accept": "application/json"}

    owns_client = http_client is None
    client = http_client or httpx.AsyncClient(timeout=_get_timeout())

    try:
        try:
            response = await client.get(endpoint, headers=headers)
        finally:
            if owns_client:
                await client.aclose()
    except httpx.TimeoutException:
        return _unavailable_evidence("VirusTotal request timed out.")
    except httpx.RequestError as exc:
        return _unavailable_evidence(
            f"VirusTotal request failed: {exc.__class__.__name__}."
        )

    if response.status_code == 404:
        return _unavailable_evidence(
            "VirusTotal has no existing report for this URL."
        )

    if response.status_code == 429:
        return _unavailable_evidence(
            "VirusTotal rate limit exceeded (public API: 500/day, 4/min)."
        )

    if response.status_code != 200:
        return _unavailable_evidence(
            f"VirusTotal returned HTTP {response.status_code}."
        )

    try:
        body = response.json()
        stats = body["data"]["attributes"]["last_analysis_stats"]
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
    except (ValueError, KeyError, TypeError):
        return _unavailable_evidence("VirusTotal returned a malformed response.")

    if malicious < _MALICIOUS_ENGINE_THRESHOLD and suspicious < _SUSPICIOUS_ENGINE_THRESHOLD:
        # Genuinely checked, genuinely below threshold -- clean result,
        # not "unavailable". No evidence item produced.
        return None

    return Evidence(
        category="url",
        signal="VIRUSTOTAL_MALICIOUS",
        points=VIRUSTOTAL_POINTS,
        reason=(
            f"VirusTotal: {malicious} security engine(s) flagged this URL "
            f"as malicious, {suspicious} as suspicious."
        ),
        observed_value=url,
        source="virustotal",
        correlation_group="CORR_EXTERNAL_REPUTATION",
        confidence=0.85,
        severity="CRITICAL",
    )
