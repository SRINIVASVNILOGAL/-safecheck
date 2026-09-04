"""Deterministic, non-LLM explanation generation.

This is a placeholder for the real LLM-based explanation service
(OpenRouter integration, a later phase per docs/scoring-engine.md Section
7). It exists so /v1/check can return a contract-shaped response now,
without pretending an LLM is already wired in.

When the OpenRouter service is implemented, this function should become
the fallback path used when the LLM call fails or times out -- per our
architecture, the explanation layer must never be a single point of
failure for the risk result itself.
"""

from __future__ import annotations

from app.risk.engine import RiskResult


def generate_explanation(result: RiskResult) -> tuple[str, list[str], str, list[str]]:
    """Build a deterministic summary from evidence. Returns (summary, why, next_action, uncertainty)."""
    all_evidence = result.all_evidence

    if not all_evidence:
        return (
            "No signs of fraud were found in the submitted content.",
            [],
            "No action needed. Stay cautious with unexpected requests for money or personal information.",
            [],
        )

    why = [item.reason for item in all_evidence]

    if result.band == "HIGH":
        summary = "This content shows strong signs of being fraudulent."
        next_action = (
            "Do not click any links, share any codes, or make any payment. "
            "Verify independently through an official channel before acting."
        )
    elif result.band == "MEDIUM":
        summary = "This content shows several signs that may indicate fraud."
        next_action = (
            "Be cautious. Do not share personal information or make payments "
            "until you have verified this through an official channel."
        )
    elif result.band == "UNCERTAIN":
        summary = "This content has some suspicious characteristics, but the evidence is not conclusive."
        next_action = "Proceed carefully and verify independently if anything is unclear."
    else:
        summary = "No strong signs of fraud were found, but stay alert."
        next_action = "No immediate action needed."

    uncertainty: list[str] = []
    unavailable = [e for e in all_evidence if e.availability == "unavailable"]
    if unavailable:
        sources = ", ".join(sorted({e.source for e in unavailable}))
        uncertainty.append(f"Some checks could not be completed ({sources}).")

    return summary, why, next_action, uncertainty


def generate_safe_actions(result: RiskResult) -> list[str]:
    if result.band in ("HIGH", "MEDIUM"):
        return [
            "Do not click any links or share any codes, passwords, or OTPs.",
            "Verify the sender or organization through its official website or helpline.",
            "Ask a trusted contact to review this before you act.",
        ]
    if result.band == "UNCERTAIN":
        return [
            "Verify the sender or organization independently before acting.",
        ]
    return []
