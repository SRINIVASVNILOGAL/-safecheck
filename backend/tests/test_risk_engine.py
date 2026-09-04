"""Tests for app.risk.engine.

Every threshold and cap value here comes directly from
docs/scoring-engine.md and must not be changed without updating that
document first. If a test here starts failing because "the numbers moved,"
that is a signal to go re-read the frozen contract, not to edit the test.
"""

from __future__ import annotations

import pytest

from app.risk.engine import (
    ML_POINTS_CAP,
    RULE_POINTS_CAP,
    URL_POINTS_CAP,
    calculate_risk,
    calculate_risk_band,
    normalize_evidence,
)
from app.risk.evidence import Evidence


def make_evidence(category: str, points: int, signal: str = "X") -> Evidence:
    return Evidence(
        category=category,  # type: ignore[arg-type]
        signal=signal,
        points=points,
        reason="test evidence",
        source="test",
    )


class TestCategoryCaps:
    def test_caps_sum_to_100(self) -> None:
        assert RULE_POINTS_CAP + URL_POINTS_CAP + ML_POINTS_CAP == 100

    def test_cap_values_match_frozen_contract(self) -> None:
        # docs/scoring-engine.md Section 2.
        assert RULE_POINTS_CAP == 45
        assert URL_POINTS_CAP == 35
        assert ML_POINTS_CAP == 20


class TestRiskBandBoundaries:
    """Exact boundary values from docs/scoring-engine.md Section 3.

    LOW: 0-24, UNCERTAIN: 25-39, MEDIUM: 40-74, HIGH: 75-100.
    """

    @pytest.mark.parametrize(
        ("score", "expected_band"),
        [
            (0, "LOW"),
            (24, "LOW"),
            (25, "UNCERTAIN"),
            (39, "UNCERTAIN"),
            (40, "MEDIUM"),
            (74, "MEDIUM"),
            (75, "HIGH"),
            (100, "HIGH"),
        ],
    )
    def test_band_boundaries(self, score: int, expected_band: str) -> None:
        assert calculate_risk_band(score) == expected_band


class TestNormalizeEvidence:
    def test_empty_list_returns_empty(self) -> None:
        assert normalize_evidence([], 45) == []

    def test_zero_target_returns_empty(self) -> None:
        evidence = [make_evidence("rules", 10)]
        assert normalize_evidence(evidence, 0) == []

    def test_raw_sum_under_cap_is_unchanged(self) -> None:
        evidence = [make_evidence("rules", 10), make_evidence("rules", 15)]
        result = normalize_evidence(evidence, 45)
        assert [e.points for e in result] == [10, 15]

    def test_raw_sum_over_cap_scales_down_to_exact_target(self) -> None:
        evidence = [
            make_evidence("rules", 30, "A"),
            make_evidence("rules", 30, "B"),
        ]
        result = normalize_evidence(evidence, 45)
        assert sum(e.points for e in result) == 45

    def test_normalization_never_scales_up(self) -> None:
        """Weak evidence must never be inflated to reach a target."""
        evidence = [make_evidence("rules", 5)]
        result = normalize_evidence(evidence, 45)
        assert result[0].points == 5


class TestCalculateRisk:
    def test_no_evidence_yields_zero_low(self) -> None:
        result = calculate_risk([])
        assert result.score == 0
        assert result.band == "LOW"

    def test_single_category_under_cap(self) -> None:
        evidence = [
            make_evidence("rules", 20, "URGENT_PAYMENT"),
            make_evidence("rules", 25, "LOTTERY_OR_PRIZE"),
        ]
        result = calculate_risk(evidence)
        assert result.rules.points == 45
        assert result.score == 45
        assert result.band == "MEDIUM"

    def test_category_exceeding_cap_is_clipped_and_cards_still_sum_correctly(
        self,
    ) -> None:
        evidence = [
            make_evidence("rules", 30, "A"),
            make_evidence("rules", 30, "B"),
        ]
        result = calculate_risk(evidence)
        assert result.rules.points == 45
        assert result.rules.raw_points == 60
        # The individual evidence cards shown to the user must sum to
        # exactly what is reported as the category's points.
        assert sum(e.points for e in result.rules.evidence) == result.rules.points

    def test_all_three_categories_maxed_clips_at_100_high(self) -> None:
        evidence = [
            make_evidence("rules", 45, "A"),
            make_evidence("url", 35, "B"),
            make_evidence("ml", 20, "C"),
        ]
        result = calculate_risk(evidence)
        assert result.score == 100
        assert result.band == "HIGH"

    def test_unavailable_evidence_contributes_nothing(self) -> None:
        evidence = [
            Evidence(
                category="url",
                signal="GOOGLE_SAFE_BROWSING",
                points=0,
                reason="provider down",
                source="google_safe_browsing",
                availability="unavailable",
            ),
        ]
        result = calculate_risk(evidence)
        assert result.score == 0
        assert result.url.points == 0

    def test_categories_are_independent(self) -> None:
        """Exceeding one category's cap must not affect the others."""
        evidence = [
            make_evidence("rules", 100, "MASSIVE"),  # way over the 45 cap
            make_evidence("url", 10, "SMALL"),
        ]
        result = calculate_risk(evidence)
        assert result.rules.points == 45  # capped
        assert result.url.points == 10  # untouched
        assert result.score == 55

    def test_score_never_exceeds_100_even_with_pathological_input(self) -> None:
        evidence = [make_evidence("rules", 10_000, "EXTREME")]
        result = calculate_risk(evidence)
        assert result.score <= 100
        assert result.rules.points <= RULE_POINTS_CAP
