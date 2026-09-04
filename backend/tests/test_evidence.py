"""Tests for app.risk.evidence.Evidence.

Covers the invariant that is easy to violate by accident: unavailable
evidence must never carry points (docs/scoring-engine.md Section 4).
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.risk.evidence import Evidence


def test_available_evidence_with_points_is_valid() -> None:
    evidence = Evidence(
        category="rules",
        signal="URGENT_PAYMENT",
        points=20,
        reason="Message pressures the user to pay immediately.",
        source="rule_engine",
    )
    assert evidence.points == 20
    assert evidence.availability == "available"


def test_unavailable_evidence_with_zero_points_is_valid() -> None:
    evidence = Evidence(
        category="url",
        signal="GOOGLE_SAFE_BROWSING",
        points=0,
        reason="Provider unavailable.",
        source="google_safe_browsing",
        availability="unavailable",
    )
    assert evidence.points == 0


def test_unavailable_evidence_with_nonzero_points_is_rejected() -> None:
    with pytest.raises(ValidationError, match="must have points=0"):
        Evidence(
            category="url",
            signal="BAD",
            points=10,
            reason="An unavailable provider must never score points.",
            source="test",
            availability="unavailable",
        )


def test_evidence_id_is_auto_generated_and_unique() -> None:
    first = Evidence(category="rules", signal="A", points=1, reason="a", source="test")
    second = Evidence(category="rules", signal="A", points=1, reason="a", source="test")
    assert first.evidence_id != second.evidence_id
    assert first.evidence_id.startswith("ev_")


def test_negative_points_are_rejected() -> None:
    with pytest.raises(ValidationError):
        Evidence(category="rules", signal="A", points=-5, reason="a", source="test")


def test_confidence_out_of_range_is_rejected() -> None:
    with pytest.raises(ValidationError):
        Evidence(
            category="rules",
            signal="A",
            points=1,
            reason="a",
            source="test",
            confidence=1.5,
        )
