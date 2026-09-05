"""Tests for the locked OpenRouter model allow-list (app.integrations.openrouter._get_model).

Per user's explicit decision, SafeCheck locks to one free OpenRouter
model rather than exposing a user-facing picker. OPENROUTER_MODEL is a
deployment-level env var, not a request parameter -- this test suite
verifies it is validated against an allow-list rather than passed
through blindly (protects against a stale/typo'd .env silently sending
requests to an unexpected or paid model).
"""

from __future__ import annotations

import pytest

from app.integrations import openrouter


class TestModelAllowList:
    def test_default_model_is_in_its_own_allow_list(self) -> None:
        assert openrouter._DEFAULT_MODEL in openrouter._ALLOWED_MODELS

    def test_unset_env_returns_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("OPENROUTER_MODEL", raising=False)
        assert openrouter._get_model() == openrouter._DEFAULT_MODEL

    def test_blank_env_returns_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OPENROUTER_MODEL", "   ")
        assert openrouter._get_model() == openrouter._DEFAULT_MODEL

    def test_allowed_non_default_model_passes_through(self, monkeypatch: pytest.MonkeyPatch) -> None:
        other = next(iter(openrouter._ALLOWED_MODELS - {openrouter._DEFAULT_MODEL}), None)
        if other is None:
            pytest.skip("Only one model in the allow-list; nothing to test.")
        monkeypatch.setenv("OPENROUTER_MODEL", other)
        assert openrouter._get_model() == other

    def test_unrecognized_model_falls_back_to_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OPENROUTER_MODEL", "some-random/unvetted-paid-model")
        assert openrouter._get_model() == openrouter._DEFAULT_MODEL

    def test_stale_paid_model_from_env_is_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Regression: the .env file previously had a paid model
        # (google/gemini-2.5-flash) with no ":free" suffix. That value
        # must never be sent to OpenRouter as-is.
        monkeypatch.setenv("OPENROUTER_MODEL", "google/gemini-2.5-flash")
        assert openrouter._get_model() == openrouter._DEFAULT_MODEL
