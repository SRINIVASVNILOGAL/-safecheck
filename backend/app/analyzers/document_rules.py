"""Document-specific deterministic rules.

These detect fraud patterns specific to documents (admission offers, job
offers, loan/prize letters) that are distinct from the message-level
rules in app.risk.rules (which target SMS/email urgency language, OTP
requests, etc.). Document text is not run through app.risk.rules --
these are a separate rule set for a separate analyzer, per the
Document Analyzer scope in docs/api-contract.md's POST /v1/document.

Same mechanism as app.risk.rules: pure functions, text in, zero-or-one
Evidence out, category="rules" (shared Rule_points cap of 45 -- see
docs/scoring-engine.md Section 2, which states document evidence
contributes through Rule_points, with no separate document category
in v1).

Signal names intentionally do not overlap with app.risk.rules's signals
(e.g. URGENT_PAYMENT vs this module's ADVANCE_FEE_REQUEST) so evidence
from the two rule sets is always distinguishable if ever combined in a
future phase (e.g. an email with a document attachment).
"""

from __future__ import annotations

import re
from collections.abc import Callable

from app.risk.evidence import Evidence

_ADVANCE_FEE_PATTERN = re.compile(
    r"\b(pay|deposit|transfer|remit|along\s+with|together\s+with)\b.{0,50}\b"
    r"(processing\s+fee|registration\s+fee|admission\s+fee|security\s+deposit|"
    r"confirmation\s+fee|advance\s+fee)\b.{0,60}\b"
    r"(before|to\s+(confirm|secure|finalize|claim|receive))\b",
    re.IGNORECASE,
)

_UNREALISTIC_GUARANTEE_PATTERN = re.compile(
    r"\b(100%\s*guarante\w*|guarante\w*\s+(admission|selection|visa|job|placement)|"
    r"no\s+interview\s+(required|needed)|selected\s+without\s+(interview|exam))\b",
    re.IGNORECASE,
)

_INFORMAL_CONTACT_ONLY_PATTERN = re.compile(
    r"\b(contact|reach|whatsapp|message)\s+(us\s+)?(at|on|via)\b.{0,15}"
    r"(\+?\d[\d\s-]{8,}|"
    r"[\w.+-]+@(gmail|yahoo|hotmail|outlook)\.com)\b",
    re.IGNORECASE,
)

_URGENCY_LIMITED_TIME_PATTERN = re.compile(
    r"\b(limited\s+seats?|only\s+\d+\s+seats?\s+left|offer\s+(valid|expires?)\s+"
    r"(for|within|in)\s+\d+\s*(hours?|days?)|first\s+come\s+first\s+serve\w*|"
    r"act\s+now|respond\s+within\s+\d+\s*(hours?|days?))\b",
    re.IGNORECASE,
)

_SENSITIVE_DOCUMENT_REQUEST_PATTERN = re.compile(
    r"\b(send|share|attach|upload)\b.{0,40}\b"
    r"(passport\s+copy|aadhaar\s+copy|bank\s+statement|scanned\s+copy\s+of\s+your\s+id|"
    r"copy\s+of\s+your\s+passport)\b",
    re.IGNORECASE,
)


def _rule_advance_fee_request(text: str) -> Evidence | None:
    match = _ADVANCE_FEE_PATTERN.search(text)
    if not match:
        return None
    return Evidence(
        category="rules",
        signal="ADVANCE_FEE_REQUEST",
        points=20,
        reason="The document requests an upfront fee to secure an offer or admission.",
        observed_value=match.group(0),
        source="document_analyzer",
        correlation_group="CORR_ADVANCE_FEE",
        severity="HIGH",
    )


def _rule_unrealistic_guarantee(text: str) -> Evidence | None:
    match = _UNREALISTIC_GUARANTEE_PATTERN.search(text)
    if not match:
        return None
    return Evidence(
        category="rules",
        signal="UNREALISTIC_GUARANTEE",
        points=15,
        reason="The document guarantees an outcome (admission, job, visa) without normal verification steps.",
        observed_value=match.group(0),
        source="document_analyzer",
        correlation_group="CORR_UNREALISTIC_OFFER",
        severity="MEDIUM",
    )


def _rule_informal_contact_only(text: str) -> Evidence | None:
    match = _INFORMAL_CONTACT_ONLY_PATTERN.search(text)
    if not match:
        return None
    return Evidence(
        category="rules",
        signal="INFORMAL_CONTACT_ONLY",
        points=15,
        reason="The document provides only a personal phone number or free email account as contact, not an official channel.",
        observed_value=match.group(0),
        source="document_analyzer",
        correlation_group="CORR_INFORMAL_CONTACT",
        severity="MEDIUM",
    )


def _rule_urgency_limited_time(text: str) -> Evidence | None:
    match = _URGENCY_LIMITED_TIME_PATTERN.search(text)
    if not match:
        return None
    return Evidence(
        category="rules",
        signal="URGENCY_LIMITED_TIME",
        points=12,
        reason="The document pressures the recipient to act within a short deadline.",
        observed_value=match.group(0),
        source="document_analyzer",
        correlation_group="CORR_URGENCY",
        severity="MEDIUM",
    )


def _rule_sensitive_document_request(text: str) -> Evidence | None:
    match = _SENSITIVE_DOCUMENT_REQUEST_PATTERN.search(text)
    if not match:
        return None
    return Evidence(
        category="rules",
        signal="SENSITIVE_DOCUMENT_REQUEST",
        points=15,
        reason="The document asks the recipient to send sensitive identity documents.",
        observed_value=match.group(0),
        source="document_analyzer",
        correlation_group="CORR_CREDENTIAL_HARVEST",
        severity="HIGH",
    )


# The full set of document-specific rules the Document Analyzer runs
# against extracted document text.
ALL_DOCUMENT_RULES: list[Callable[[str], Evidence | None]] = [
    _rule_advance_fee_request,
    _rule_unrealistic_guarantee,
    _rule_informal_contact_only,
    _rule_urgency_limited_time,
    _rule_sensitive_document_request,
]


def run_all_document_rules(text: str) -> list[Evidence]:
    """Run every document-specific rule against `text`.

    Mirrors app.risk.rules.run_all_rules(): an unmatched rule produces no
    Evidence item at all, not a zero-point one (see that module's
    docstring for the "no signal" vs "unavailable" distinction).
    """
    evidence: list[Evidence] = []
    for rule in ALL_DOCUMENT_RULES:
        result = rule(text)
        if result is not None:
            evidence.append(result)
    return evidence
