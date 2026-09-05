"""Tests for app.integrations.openrouter.generate_recovery_email's
deterministic fallback path (no OPENROUTER_API_KEY configured).

Mirrors the existing generate_warning_copy fallback-testing pattern:
without an API key, the function must never raise and must always
return a usable, link-free draft.
"""

from __future__ import annotations

import asyncio

import pytest

from app.integrations.openrouter import generate_recovery_email


class TestRecoveryEmailFallback:
    def test_no_api_key_returns_deterministic_fallback(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
        copy = asyncio.run(
            generate_recovery_email(
                org_display_name="State Bank of India (SBI)",
                risk_score=75,
                risk_band="HIGH",
                signals=["OTP_REQUEST", "URGENT_PAYMENT"],
            )
        )
        assert "State Bank of India" in copy.subject
        assert "Otp Request" in copy.body or "OTP" in copy.body.upper()
        assert "http://" not in copy.body.lower()
        assert "https://" not in copy.body.lower()

    def test_fallback_never_raises_with_empty_signals_list(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
        copy = asyncio.run(
            generate_recovery_email(
                org_display_name="IRCTC / Indian Railways",
                risk_score=40,
                risk_band="MEDIUM",
                signals=[],
            )
        )
        assert copy.subject
        assert copy.body
