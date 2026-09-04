"""Deterministic risk engine.

Implements docs/scoring-engine.md exactly. This is the ONLY component
allowed to produce a final risk score and band. Analyzers (rule engine,
URL analyzer, document analyzer, LLM-derived classifier) produce Evidence;
this module sums it, caps it per category, and derives the band.

Nothing in this module calls an LLM or any external API. It is pure,
deterministic, and fully unit-testable without network access.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel

from app.risk.evidence import Evidence

RiskBand = Literal["LOW", "UNCERTAIN", "MEDIUM", "HIGH"]

# Category caps from docs/scoring-engine.md Section 1-2.
# These must sum to exactly 100.
RULE_POINTS_CAP = 45
URL_POINTS_CAP = 35
ML_POINTS_CAP = 20

assert RULE_POINTS_CAP + URL_POINTS_CAP + ML_POINTS_CAP == 100, (
    "Category caps must sum to exactly 100 per docs/scoring-engine.md "
    "Section 2. If you are deliberately changing this, update the shared "
    "scoring contract document first."
)

# Band thresholds from docs/scoring-engine.md Section 3.
_HIGH_THRESHOLD = 75
_MEDIUM_THRESHOLD = 40
_UNCERTAIN_THRESHOLD = 25


def calculate_risk_band(score: int) -> RiskBand:
    """Derive the risk band from a final score. Never set independently."""
    if score >= _HIGH_THRESHOLD:
        return "HIGH"
    if score >= _MEDIUM_THRESHOLD:
        return "MEDIUM"
    if score >= _UNCERTAIN_THRESHOLD:
        return "UNCERTAIN"
    return "LOW"


def normalize_evidence(evidence_list: list[Evidence], target_total: int) -> list[Evidence]:
    """Scale evidence points down proportionally if their raw sum exceeds the cap.

    Per docs/scoring-engine.md Section 6: if raw evidence sum is already at
    or below the cap, it is left untouched -- we never inflate weak evidence
    to reach a target. Scaling only ever reduces, never increases.

    The returned list's points sum to exactly `target_total` in the common
    case. KNOWN EDGE CASE: each item has a floor of 1 point (an evidence
    item that contributed nothing would be meaningless), so if there are
    more evidence items than `target_total` points available, the sum can
    exceed `target_total` slightly. This is an inherent limitation of
    "minimum 1 point per item" normalization, not a bug specific to this
    implementation -- it is covered by a unit test in Step 3 so the
    behavior is documented rather than silently wrong.
    """
    if not evidence_list or target_total <= 0:
        return []

    raw_sum = sum(item.points for item in evidence_list)
    if raw_sum <= target_total:
        return evidence_list

    scaled: list[Evidence] = []
    for item in evidence_list:
        scaled_points = max(1, int((item.points / raw_sum) * target_total))
        scaled.append(item.model_copy(update={"points": scaled_points}))

    current_sum = sum(item.points for item in scaled)
    diff = target_total - current_sum
    if diff != 0:
        last = scaled[-1]
        scaled[-1] = last.model_copy(
            update={"points": max(1, last.points + diff)}
        )

    return scaled


class CategoryBreakdown(BaseModel):
    """Per-category evidence and points, after capping/normalization."""

    points: int
    cap: int
    raw_points: int
    evidence: list[Evidence]


class RiskResult(BaseModel):
    """The complete, final output of the risk engine."""

    score: int
    band: RiskBand
    rules: CategoryBreakdown
    url: CategoryBreakdown
    ml: CategoryBreakdown

    @property
    def all_evidence(self) -> list[Evidence]:
        """Evidence across all three categories, in a single flat list."""
        return [*self.rules.evidence, *self.url.evidence, *self.ml.evidence]


def _score_category(
    evidence_list: list[Evidence], cap: int
) -> CategoryBreakdown:
    raw_points = sum(item.points for item in evidence_list)
    normalized = normalize_evidence(evidence_list, min(raw_points, cap))
    capped_points = min(sum(item.points for item in normalized), cap)
    return CategoryBreakdown(
        points=capped_points,
        cap=cap,
        raw_points=raw_points,
        evidence=normalized,
    )


def calculate_risk(evidence_list: list[Evidence]) -> RiskResult:
    """Compute the final score and band from a flat list of Evidence.

    This is the single entry point analyzers/orchestration code should call.
    It partitions evidence by category, caps each category, sums them, and
    clips the total at 100.
    """
    rules_evidence = [e for e in evidence_list if e.category == "rules"]
    url_evidence = [e for e in evidence_list if e.category == "url"]
    ml_evidence = [e for e in evidence_list if e.category == "ml"]

    rules_breakdown = _score_category(rules_evidence, RULE_POINTS_CAP)
    url_breakdown = _score_category(url_evidence, URL_POINTS_CAP)
    ml_breakdown = _score_category(ml_evidence, ML_POINTS_CAP)

    score = min(
        100,
        rules_breakdown.points + url_breakdown.points + ml_breakdown.points,
    )
    band = calculate_risk_band(score)

    return RiskResult(
        score=score,
        band=band,
        rules=rules_breakdown,
        url=url_breakdown,
        ml=ml_breakdown,
    )
