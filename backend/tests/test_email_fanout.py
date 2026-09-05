"""Regression tests for Gmail Email Agent fan-out.

No real Google, Safe Browsing, or VirusTotal calls occur here. The test
proves body-rule, URL, and attachment evidence merge before one final
risk result rather than adding independently-finalized scores.
"""
from __future__ import annotations

import base64

import httpx
import pytest

import app.graph.nodes as nodes
from app.graph.pipeline import run_email_pipeline
from app.graph.state import EmailAttachment
from app.integrations.gmail import _canonical_urls, _collect_attachments
from app.models.check import CheckPayload


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii")


def test_canonical_urls_deduplicates_fragments_and_enforces_limit() -> None:
    payload = {
        "mimeType": "text/html",
        "body": {"data": _b64(b'<a href="https://Example.com/a#one">a</a> https://example.com/a#two https://second.test/x.')},
    }
    found, urls = _canonical_urls(payload)
    assert found == 2
    assert urls == ("https://example.com/a", "https://second.test/x")


@pytest.mark.anyio
async def test_attachment_collector_accepts_supported_inline_attachment() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    try:
        found, attachments, skipped = await _collect_attachments(
            "message-id",
            {
                "mimeType": "multipart/mixed",
                "parts": [{"filename": "offer.pdf", "mimeType": "application/pdf", "body": {"size": 3, "data": _b64(b"pdf")}}],
            },
            client,
            {"Authorization": "Bearer fake"},
        )
    finally:
        await client.aclose()
    assert found == 1
    assert len(attachments) == 1
    assert attachments[0].filename == "offer.pdf"
    assert attachments[0].data == b"pdf"
    assert skipped == ()


@pytest.mark.anyio
async def test_email_pipeline_merges_email_url_and_attachment_evidence(monkeypatch: pytest.MonkeyPatch) -> None:
    async def clean_provider(url: str):
        return None

    monkeypatch.setattr(nodes, "check_url_google_safe_browsing", clean_provider)
    monkeypatch.setattr(nodes, "check_url_virustotal", clean_provider)

    result = await run_email_pipeline(
        CheckPayload(sender="bad@example.com", subject="Prize", body="You have won a lottery prize."),
        urls=["http://sbi-kyc-update.xyz/login"],
        attachments=[EmailAttachment("unreadable.pdf", "application/pdf", b"not-a-pdf")],
    )

    signals = {item.signal for item in result.risk_result.all_evidence}
    assert "LOTTERY_OR_PRIZE" in signals
    assert "LOOKALIKE_DOMAIN" in signals
    assert "ATTACHMENT_TEXT_EXTRACTION" in signals
    # URL local evidence is capped at 35; rules have 15 lottery points.
    # The attachment extraction failure stays unavailable/zero-point.
    assert result.risk_result.score == 50
    unavailable = next(item for item in result.risk_result.all_evidence if item.signal == "ATTACHMENT_TEXT_EXTRACTION")
    assert unavailable.availability == "unavailable"
    assert unavailable.points == 0
