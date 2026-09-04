"""Google Safe Browsing v4 adapter.

Non-commercial use only per Google's terms (see our own earlier research
summary). Free, with a default quota. This adapter checks a single URL
against Google's threatMatches:find endpoint.

CRITICAL INVARIANT: any failure (missing API key, network error, timeout,
non-200 response, malformed response) must produce evidence with
availability="unavailable" and points=0. An unavailable provider must
NEVER be treated as either "safe" or "malicious" -- it is simply unknown.
See docs/scoring-engine.md Section 4 and app.risk.evidence.Evidence's own
enforced invariant (unavailable => points=0, or a ValidationError is
raised).
"""

from __future__ import annotations

import os

import httpx

from app.risk.evidence import Evidence

_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
_DEFAULT_TIMEOUT_SECONDS = 5.0

GOOGLE_SAFE_BROWSING_POINTS = 30


def _get_api_key() -> str | None:
    return os.getenv("GOOGLE_SAFE_BROWSING_API_KEY") or None


def _get_timeout() -> float:
    raw = os.getenv("GOOGLE_SAFE_BROWSING_TIMEOUT_SECONDS")
    if not raw:
        return _DEFAULT_TIMEOUT_SECONDS
    try:
        return float(raw)
    except ValueError:
        return _DEFAULT_TIMEOUT_SECONDS


def _unavailable_evidence(reason: str) -> Evidence:
    return Evidence(
        category="url",
        signal="GOOGLE_SAFE_BROWSING",
        points=0,
        reason=reason,
        source="google_safe_browsing",
        correlation_group="CORR_EXTERNAL_REPUTATION",
        availability="unavailable",
        confidence=0.0,
        severity="LOW",
    )


async def check_url_google_safe_browsing(
    url: str, http_client: httpx.AsyncClient | None = None
) -> Evidence | None:
    """Check `url` against Google Safe Browsing v4.

    Args:
        url: the URL to check.
        http_client: optional injected httpx.AsyncClient, primarily for
            testing failure paths (timeouts, non-200, malformed JSON)
            without real network calls. Production callers should omit
            this and let the function create its own client.

    Returns:
    - Evidence with category="url", signal="GOOGLE_SAFE_BROWSING",
      points=30, availability="available" if a threat was confirmed.
    - None if the API responded cleanly and found no threat (this is a
      genuine "checked and clean" result, not an absence of evidence --
      see app.risk.rules for the same "no signal" vs "unavailable"
      distinction used by the rule engine).
    - Evidence with availability="unavailable", points=0 if the check
      could not be completed for any reason.
    """
    api_key = _get_api_key()
    if api_key is None:
        return _unavailable_evidence(
            "Google Safe Browsing API key is not configured."
        )

    payload = {
        "client": {"clientId": "safecheck-web", "clientVersion": "1.0.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    owns_client = http_client is None
    client = http_client or httpx.AsyncClient(timeout=_get_timeout())

    try:
        try:
            response = await client.post(
                _ENDPOINT,
                params={"key": api_key},
                json=payload,
            )
        finally:
            if owns_client:
                await client.aclose()
    except httpx.TimeoutException:
        return _unavailable_evidence("Google Safe Browsing request timed out.")
    except httpx.RequestError as exc:
        return _unavailable_evidence(
            f"Google Safe Browsing request failed: {exc.__class__.__name__}."
        )

    if response.status_code != 200:
        return _unavailable_evidence(
            f"Google Safe Browsing returned HTTP {response.status_code}."
        )

    try:
        body = response.json()
    except ValueError:
        return _unavailable_evidence(
            "Google Safe Browsing returned a malformed response."
        )

    matches = body.get("matches")
    if not matches:
        # Clean result: checked, no threat found. Not "unavailable" --
        # this is a genuine, successful check with a negative result, so
        # no evidence item is produced at all (same "no signal" pattern
        # as an unmatched rule in app.risk.rules).
        return None

    threat_types = sorted({m.get("threatType", "UNKNOWN") for m in matches})
    return Evidence(
        category="url",
        signal="GOOGLE_SAFE_BROWSING",
        points=GOOGLE_SAFE_BROWSING_POINTS,
        reason=(
            "Google Safe Browsing identified this URL as a threat: "
            f"{', '.join(threat_types)}."
        ),
        observed_value=url,
        source="google_safe_browsing",
        correlation_group="CORR_EXTERNAL_REPUTATION",
        confidence=0.95,
        severity="CRITICAL",
    )
