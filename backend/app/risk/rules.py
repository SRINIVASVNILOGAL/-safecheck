"""Deterministic message/email rule engine.

Each rule is a pure function: text in, zero-or-one Evidence out. Rules never
call an LLM or any external API -- they are regex/keyword based so they are
fast, fully deterministic, and testable without network access.

All rules here produce category="rules" evidence, which the risk engine
caps at RULE_POINTS_CAP=45 (see app.risk.engine). Point values are chosen
so that 2-3 genuine red flags in one message land in MEDIUM/HIGH, not so
that a single rule alone maxes out the category.

Signal names and point values are the first working set for Phase 3 and
may be tuned once we have more real test cases; the mechanism (pure
functions returning Evidence, capped by category) is what must not change
without updating docs/scoring-engine.md.
"""

from __future__ import annotations

import re
from collections.abc import Callable

from app.risk.evidence import Evidence

# Each pattern is intentionally case-insensitive and written to match
# common phrasing rather than exact strings, since real scam messages vary
# wording constantly.

_URGENT_PAYMENT_PATTERN = re.compile(
    r"\b(pay|payment|transfer|deposit)\b.{0,40}\b"
    r"(immediately|urgently|now|today|within\s+\d+\s*(hours?|minutes?))\b",
    re.IGNORECASE,
)

_OTP_REQUEST_PATTERN = re.compile(
    r"\b(share|send|provide|tell\s+us)\b.{0,20}\b(otp|one[\s-]?time\s+password)\b",
    re.IGNORECASE,
)

_PIN_REQUEST_PATTERN = re.compile(
    r"\b(share|send|provide|enter)\b.{0,20}\b(pin|mpin|upi\s*pin)\b",
    re.IGNORECASE,
)

_PASSWORD_REQUEST_PATTERN = re.compile(
    r"\b(share|send|provide|enter|confirm)\b.{0,20}\b(password|passwd|login\s+credentials)\b",
    re.IGNORECASE,
)

_ACCOUNT_BLOCKED_PATTERN = re.compile(
    r"\b(account|card|upi)\b.{0,30}\b(blocked|suspended|frozen|deactivat\w*|will\s+be\s+block\w*)\b",
    re.IGNORECASE,
)

_LOTTERY_OR_PRIZE_PATTERN = re.compile(
    r"\b(congratulations|you\s+have\s+won|winner|claim\s+your\s+prize|lucky\s+draw|lottery)\b",
    re.IGNORECASE,
)

_IMPERSONATION_PATTERN = re.compile(
    r"\b(this\s+is|i\s+am\s+calling\s+from|from\s+the)\b.{0,20}\b"
    r"(rbi|income\s+tax|cybercrime|crime\s+branch|police|customs|sbi|bank\s+official)\b",
    re.IGNORECASE,
)

_REMOTE_ACCESS_TOOL_PATTERN = re.compile(
    r"\b(anydesk|teamviewer|quicksupport|screen\s+share|remote\s+access)\b",
    re.IGNORECASE,
)

# Toll/fee/fine/invoice scam framing (e.g. fake "unpaid toll" SMS), a
# widely reported real-world pattern that had no coverage at all before
# this rule -- the message previously fell through to only URGENT_PAYMENT.
_FEE_OR_FINE_PATTERN = re.compile(
    r"\b(unpaid|outstanding|overdue|pending)\b.{0,30}\b"
    r"(toll|fee|fine|invoice|bill|charge)\b"
    r"|\b(toll|fee|fine|invoice|bill|charge)\b.{0,30}\b"
    r"(unpaid|outstanding|overdue|due|pending)\b",
    re.IGNORECASE,
)


def _rule_urgent_payment(text: str) -> Evidence | None:
    match = _URGENT_PAYMENT_PATTERN.search(text)
    if not match:
        return None
    return Evidence(
        category="rules",
        signal="URGENT_PAYMENT",
        points=15,
        reason="The message pressures the recipient to pay immediately.",
        observed_value=match.group(0),
        source="rule_engine",
        correlation_group="CORR_URGENCY",
        severity="MEDIUM",
    )


def _rule_otp_request(text: str) -> Evidence | None:
    match = _OTP_REQUEST_PATTERN.search(text)
    if not match:
        return None
    return Evidence(
        category="rules",
        signal="OTP_REQUEST",
        points=20,
        reason="The message asks the recipient to share an OTP.",
        observed_value=match.group(0),
        source="rule_engine",
        correlation_group="CORR_CREDENTIAL_HARVEST",
        severity="HIGH",
    )


def _rule_pin_request(text: str) -> Evidence | None:
    match = _PIN_REQUEST_PATTERN.search(text)
    if not match:
        return None
    return Evidence(
        category="rules",
        signal="PIN_REQUEST",
        points=20,
        reason="The message asks the recipient to share a PIN.",
        observed_value=match.group(0),
        source="rule_engine",
        correlation_group="CORR_CREDENTIAL_HARVEST",
        severity="HIGH",
    )


def _rule_password_request(text: str) -> Evidence | None:
    match = _PASSWORD_REQUEST_PATTERN.search(text)
    if not match:
        return None
    return Evidence(
        category="rules",
        signal="PASSWORD_REQUEST",
        points=20,
        reason="The message asks the recipient to share a password.",
        observed_value=match.group(0),
        source="rule_engine",
        correlation_group="CORR_CREDENTIAL_HARVEST",
        severity="HIGH",
    )


def _rule_account_blocked(text: str) -> Evidence | None:
    match = _ACCOUNT_BLOCKED_PATTERN.search(text)
    if not match:
        return None
    return Evidence(
        category="rules",
        signal="ACCOUNT_BLOCKED",
        points=12,
        reason="The message threatens that an account/card will be blocked.",
        observed_value=match.group(0),
        source="rule_engine",
        correlation_group="CORR_URGENCY",
        severity="MEDIUM",
    )


def _rule_lottery_or_prize(text: str) -> Evidence | None:
    match = _LOTTERY_OR_PRIZE_PATTERN.search(text)
    if not match:
        return None
    return Evidence(
        category="rules",
        signal="LOTTERY_OR_PRIZE",
        points=15,
        reason="The message claims the recipient has won an unsolicited prize.",
        observed_value=match.group(0),
        source="rule_engine",
        correlation_group="CORR_LOTTERY",
        severity="MEDIUM",
    )


def _rule_impersonation(text: str) -> Evidence | None:
    match = _IMPERSONATION_PATTERN.search(text)
    if not match:
        return None
    return Evidence(
        category="rules",
        signal="IMPERSONATION",
        points=15,
        reason="The message claims to be from a bank, government body, or law enforcement.",
        observed_value=match.group(0),
        source="rule_engine",
        correlation_group="CORR_IMPERSONATION",
        severity="HIGH",
    )


def _rule_fee_or_fine(text: str) -> Evidence | None:
    match = _FEE_OR_FINE_PATTERN.search(text)
    if not match:
        return None
    return Evidence(
        category="rules",
        signal="FEE_OR_FINE_SCAM",
        points=15,
        reason="The message claims an unpaid toll, fee, fine, or invoice and pressures payment.",
        observed_value=match.group(0),
        source="rule_engine",
        correlation_group="CORR_URGENCY",
        severity="MEDIUM",
    )


def _rule_remote_access_tool(text: str) -> Evidence | None:
    match = _REMOTE_ACCESS_TOOL_PATTERN.search(text)
    if not match:
        return None
    return Evidence(
        category="rules",
        signal="REMOTE_ACCESS_TOOL",
        points=20,
        reason="The message requests installing a remote-access application.",
        observed_value=match.group(0),
        source="rule_engine",
        correlation_group="CORR_REMOTE_ACCESS",
        severity="CRITICAL",
    )


# The full set of rules the message analyzer runs against incoming text.
ALL_RULES: list[Callable[[str], Evidence | None]] = [
    _rule_urgent_payment,
    _rule_otp_request,
    _rule_pin_request,
    _rule_password_request,
    _rule_account_blocked,
    _rule_fee_or_fine,
    _rule_lottery_or_prize,
    _rule_impersonation,
    _rule_remote_access_tool,
]


def run_all_rules(text: str) -> list[Evidence]:
    """Run every rule against `text`, returning evidence for each match.

    This is the single entry point the message/email analyzer should call.
    Rules that don't match simply contribute nothing -- there is no
    "evidence of absence"; an unmatched rule produces no Evidence item at
    all (not a zero-point one), since it did not run any external check
    that could be "unavailable".
    """
    evidence: list[Evidence] = []
    for rule in ALL_RULES:
        result = rule(text)
        if result is not None:
            evidence.append(result)
    return evidence
