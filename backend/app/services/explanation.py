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

import logging

from app.integrations.openrouter import generate_openrouter_explanation
from app.risk.engine import RiskResult

logger = logging.getLogger(__name__)


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

    # Only available evidence describes an actual reason for concern.
    # Unavailable evidence (a provider check that could not be completed)
    # is surfaced separately via `uncertainty`, not mixed into `why` --
    # otherwise "the API key is missing" would misleadingly read as a
    # fraud signal. Found and fixed during Phase 4 Step 6 live testing.
    available_evidence = [e for e in all_evidence if e.availability == "available"]
    why = [item.reason for item in available_evidence]

    if not available_evidence:
        return (
            "No signs of fraud were found in the checks that could be completed.",
            [],
            "No strong evidence either way. Some checks could not be completed -- verify independently if unsure.",
            [
                f"Some checks could not be completed ({', '.join(sorted({e.source for e in all_evidence}))})."
            ],
        )

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


# Context-aware safety precautions: each entry maps a specific evidence
# signal (produced by the deterministic rule/URL engine, never by the
# LLM) to specific, actionable advice. Per user's explicit ask: "if the
# message asks for an OTP, it should say 'Never share your OTP.'" These
# take priority over the generic band-based advice below because
# specific advice about the actual detected risk is more useful than a
# generic warning -- a message that asks for an OTP should tell the user
# about OTPs, not just "be cautious."
#
# Ordering here is the display order when multiple signals match; it is
# deliberately fixed (not evidence-arrival order) so the UI is stable
# across requests with the same evidence set.
_SIGNAL_PRECAUTIONS: dict[str, str] = {
    "OTP_REQUEST": "Never share your OTP with anyone, even if they claim to be from your bank or a government agency.",
    "PIN_REQUEST": "Never share your PIN or UPI PIN. No legitimate bank or service will ever ask for it over message, call, or email.",
    "PASSWORD_REQUEST": "Never share your password or login credentials. Legitimate organizations never ask for these directly.",
    "REMOTE_ACCESS_TOOL": "Do not install AnyDesk, TeamViewer, or any remote-access app on the request of an unknown caller or message -- this gives them full control of your device.",
    "ACCOUNT_BLOCKED": "Do not act on threats that your account or card will be blocked. Log in only through the official app or website to check your account status yourself.",
    "URGENT_PAYMENT": "Do not pay under time pressure. Legitimate dues rarely require immediate payment through a link sent by message.",
    "FEE_OR_FINE_SCAM": "Verify any toll, fee, or fine directly on the official website of the issuing authority -- do not pay through a link in the message.",
    "LOTTERY_OR_PRIZE": "Unsolicited prize or lottery claims are almost always scams. Do not pay any 'processing fee' to claim a prize you never entered for.",
    "IMPERSONATION": "Independently verify the caller's or sender's identity using a phone number or website you look up yourself, not one provided in the message.",
    "LOOKALIKE_DOMAIN": "Do not enter any login details or payment information on this site -- its domain is designed to look like a trusted brand but is not official.",
    "TYPOSQUATTING": "Check the website address carefully before entering any information -- this domain is a close misspelling of a trusted brand's real domain.",
    "SHORTENED_LINK": "Avoid clicking shortened links from unknown senders -- they hide the real destination. If you must check it, use a link-preview/unshortening tool first.",
    "IP_HOSTNAME": "Be cautious of links that use a raw IP address instead of a normal domain name -- this is unusual for legitimate sites.",
    "GOOGLE_SAFE_BROWSING": "This link has been flagged as unsafe by Google Safe Browsing. Do not visit it or enter any information.",
    "VIRUSTOTAL": "This link has been flagged by multiple security vendors as malicious. Do not visit it or enter any information.",
}

# Generic, band-based advice shown alongside (not instead of) any
# signal-specific precautions above.
_GENERIC_HIGH_MEDIUM_ACTIONS = [
    "Verify the sender or organization through its official website or helpline, not through any contact detail provided in the message.",
    "Ask a trusted contact to review this before you act.",
]
_GENERIC_UNCERTAIN_ACTIONS = [
    "Verify the sender or organization independently before acting.",
]


def generate_safe_actions(result: RiskResult) -> list[str]:
    """Build context-aware safety precautions from the actual detected signals.

    Deterministic and signal-driven per user's explicit requirement: "The
    precautions should be based on the actual content and type of risk
    detected," not a fixed list keyed only on the risk band. Falls back to
    generic band-based advice when no available evidence matches a known
    signal (e.g. only unavailable-provider evidence, or a band derived
    from a signal without dedicated precaution text).
    """
    if result.band not in ("HIGH", "MEDIUM", "UNCERTAIN"):
        return []

    available_signals = [
        item.signal for item in result.all_evidence if item.availability == "available"
    ]

    specific_actions: list[str] = []
    seen: set[str] = set()
    for signal in available_signals:
        advice = _SIGNAL_PRECAUTIONS.get(signal)
        if advice is not None and advice not in seen:
            specific_actions.append(advice)
            seen.add(advice)

    if result.band == "UNCERTAIN":
        return specific_actions or list(_GENERIC_UNCERTAIN_ACTIONS)

    # HIGH/MEDIUM: always include the generic verify-independently advice
    # alongside any specific precautions, since it applies regardless of
    # which particular signals were detected.
    if not specific_actions:
        return [
            "Do not click any links or share any codes, passwords, or OTPs.",
            *_GENERIC_HIGH_MEDIUM_ACTIONS,
        ]
    return [*specific_actions, *_GENERIC_HIGH_MEDIUM_ACTIONS]


async def generate_user_facing_explanation(
    result: RiskResult,
) -> tuple[str, list[str], str, list[str]]:
    """Return optional OpenRouter wording with a deterministic fallback.

    This function runs strictly after ``calculate_risk``. It preserves the
    deterministic ``why`` and ``uncertainty`` lists and never changes the
    evidence, score, risk band, or safe actions. Cases with no available
    findings do not need an external wording request.
    """
    fallback = generate_explanation(result)
    if not any(item.availability == "available" for item in result.all_evidence):
        return fallback

    try:
        generated = await generate_openrouter_explanation(result)
    except Exception as exc:  # noqa: BLE001 - explanation must never block a case
        logger.warning("OpenRouter explanation fallback: %s", exc.__class__.__name__)
        return fallback

    if generated is None:
        return fallback

    _, why, _, uncertainty = fallback
    return generated.summary, why, generated.next_action, uncertainty
