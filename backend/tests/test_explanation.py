"""Tests for app.services.explanation.

Regression coverage for a bug found during Phase 4 Step 6 live testing:
unavailable evidence reasons (e.g. "API key is not configured") were
being included in `why`, making a missing API key read like a fraud
signal to the end user. Unavailable evidence must only appear in
`uncertainty`, never in `why`.
"""

from __future__ import annotations

from app.risk.engine import calculate_risk
from app.risk.evidence import Evidence
from app.services.explanation import generate_explanation


def _available(signal: str, points: int, category: str = "rules") -> Evidence:
    return Evidence(
        category=category,
        signal=signal,
        points=points,
        reason=f"Reason for {signal}.",
        source="test",
    )


def _unavailable(signal: str, source: str, category: str = "url") -> Evidence:
    return Evidence(
        category=category,
        signal=signal,
        points=0,
        reason=f"{source} check could not be completed.",
        source=source,
        availability="unavailable",
    )


class TestWhyExcludesUnavailableEvidence:
    def test_unavailable_only_evidence_produces_empty_why(self) -> None:
        evidence = [
            _unavailable("GOOGLE_SAFE_BROWSING", "google_safe_browsing"),
            _unavailable("VIRUSTOTAL", "virustotal"),
        ]
        result = calculate_risk(evidence)
        summary, why, next_action, uncertainty = generate_explanation(result)

        assert why == []
        assert len(uncertainty) == 1
        assert "google_safe_browsing" in uncertainty[0]
        assert "virustotal" in uncertainty[0]

    def test_mixed_available_and_unavailable_evidence_separates_correctly(
        self,
    ) -> None:
        evidence = [
            _available("URGENT_PAYMENT", 20),
            _unavailable("GOOGLE_SAFE_BROWSING", "google_safe_browsing"),
        ]
        result = calculate_risk(evidence)
        summary, why, next_action, uncertainty = generate_explanation(result)

        assert why == ["Reason for URGENT_PAYMENT."]
        assert not any("API key" in reason for reason in why)
        assert len(uncertainty) == 1

    def test_no_evidence_at_all_produces_empty_why_and_uncertainty(self) -> None:
        result = calculate_risk([])
        summary, why, next_action, uncertainty = generate_explanation(result)

        assert why == []
        assert uncertainty == []
