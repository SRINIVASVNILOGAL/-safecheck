"""Evidence data model.

Matches docs/scoring-engine.md Section 4 exactly. Every signal produced by
any analyzer (rule engine, URL analyzer, document analyzer, or LLM-derived
classifier) must be expressed in this shape before reaching the risk engine.

This model is intentionally strict: `availability="unavailable"` evidence
must always carry `points=0` (see docs/scoring-engine.md Section 4). This is
enforced here with a validator rather than left as a convention that
individual analyzers might forget to follow.
"""

from __future__ import annotations

from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, Field

Category = Literal["rules", "url", "ml"]
Severity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
Availability = Literal["available", "unavailable"]


class Evidence(BaseModel):
    """A single scored signal contributed by an analyzer.

    Field meanings (see docs/scoring-engine.md Section 4):
    - evidence_id: unique identifier for this evidence item.
    - category: which scoring category this contributes to (rules/url/ml).
    - signal: short machine-readable code, e.g. "URGENT_PAYMENT".
    - points: points contributed. Must be 0 if availability="unavailable".
    - reason: human-readable explanation shown to the user.
    - observed_value: the actual matched text/domain/etc. that triggered this.
    - confidence: 0.0-1.0 confidence in this finding.
    - correlation_group: groups related evidence, e.g. "CORR_URGENCY".
    - source: which component produced this, e.g. "rule_engine",
      "google_safe_browsing", "gemini_intent".
    - severity: qualitative severity label.
    - availability: whether the underlying check actually ran. An
      unavailable provider (API down, quota exceeded, timeout) must never
      be treated as a positive signal of fraud.
    """

    evidence_id: str = Field(default_factory=lambda: f"ev_{uuid4().hex[:8]}")
    category: Category
    signal: str
    points: int = Field(ge=0)
    reason: str
    observed_value: str = ""
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    correlation_group: str = "CORR_DEFAULT"
    source: str
    severity: Severity = "MEDIUM"
    availability: Availability = "available"

    def model_post_init(self, __context) -> None:
        """Enforce: unavailable evidence must never carry points.

        This runs after all fields are set, so it can safely see both
        `availability` and `points` regardless of declaration order.
        """
        if self.availability == "unavailable" and self.points != 0:
            raise ValueError(
                "Evidence with availability='unavailable' must have "
                f"points=0, got points={self.points} for signal="
                f"{self.signal!r}. An unavailable provider must never be "
                "treated as a positive signal of fraud "
                "(docs/scoring-engine.md Section 4)."
            )
