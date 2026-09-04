"""Tests for app.risk.rules (deterministic message/email rule engine).

Design decision codified here: rules-only evidence is capped at
RULE_POINTS_CAP=45, which is below the HIGH threshold (75). This means no
combination of text-pattern rules alone can ever produce a HIGH-banded
case -- reaching HIGH requires corroboration from URL and/or ML evidence.
This is intentional (see Phase 3 Step 4 decision log): a single engine
should not be able to unilaterally declare HIGH risk. If this decision is
ever revisited, update docs/scoring-engine.md first, then this test file.
"""

from __future__ import annotations

from app.risk.engine import calculate_risk
from app.risk.rules import run_all_rules


class TestIndividualRules:
    def test_urgent_payment_matches(self) -> None:
        text = "Please pay the fee immediately to avoid penalty."
        evidence = run_all_rules(text)
        signals = [e.signal for e in evidence]
        assert "URGENT_PAYMENT" in signals

    def test_otp_request_matches(self) -> None:
        text = "Please share your OTP to verify the transaction."
        evidence = run_all_rules(text)
        signals = [e.signal for e in evidence]
        assert "OTP_REQUEST" in signals

    def test_pin_request_matches(self) -> None:
        text = "Kindly provide your UPI PIN to complete the refund."
        evidence = run_all_rules(text)
        signals = [e.signal for e in evidence]
        assert "PIN_REQUEST" in signals

    def test_password_request_matches(self) -> None:
        text = "Please confirm your password to secure your account."
        evidence = run_all_rules(text)
        signals = [e.signal for e in evidence]
        assert "PASSWORD_REQUEST" in signals

    def test_account_blocked_matches(self) -> None:
        text = "Your account will be blocked within 24 hours."
        evidence = run_all_rules(text)
        signals = [e.signal for e in evidence]
        assert "ACCOUNT_BLOCKED" in signals

    def test_lottery_or_prize_matches(self) -> None:
        text = "Congratulations! You have won a lucky draw prize."
        evidence = run_all_rules(text)
        signals = [e.signal for e in evidence]
        assert "LOTTERY_OR_PRIZE" in signals

    def test_impersonation_matches(self) -> None:
        text = "This is calling from your bank official regarding your card."
        evidence = run_all_rules(text)
        signals = [e.signal for e in evidence]
        assert "IMPERSONATION" in signals

    def test_remote_access_tool_matches(self) -> None:
        text = "Please install AnyDesk so our technician can assist you."
        evidence = run_all_rules(text)
        signals = [e.signal for e in evidence]
        assert "REMOTE_ACCESS_TOOL" in signals
        matched = next(e for e in evidence if e.signal == "REMOTE_ACCESS_TOOL")
        assert matched.severity == "CRITICAL"


class TestRuleNonMatches:
    def test_legitimate_transaction_receipt_triggers_nothing(self) -> None:
        text = "Rs 500 sent successfully to Ravi through UPI. Reference 123456789."
        evidence = run_all_rules(text)
        assert evidence == []

    def test_empty_string_triggers_nothing(self) -> None:
        assert run_all_rules("") == []

    def test_unmatched_rule_produces_no_evidence_item(self) -> None:
        """An unmatched rule must not appear as zero-point evidence.

        Unlike an unavailable external provider, a rule that simply didn't
        match ran successfully and found nothing -- it should not appear
        in the evidence list at all (see docs/scoring-engine.md Section 4
        distinction between "no signal" and "signal unavailable").
        """
        text = "Have a nice day."
        evidence = run_all_rules(text)
        assert evidence == []


class TestRuleCombinations:
    def test_lottery_scam_message_lands_in_uncertain_or_medium(self) -> None:
        text = (
            "Congratulations! You have won a lottery prize of Rs 50000. "
            "Pay processing fee immediately to claim your prize."
        )
        evidence = run_all_rules(text)
        result = calculate_risk(evidence)
        # URGENT_PAYMENT(15) + LOTTERY_OR_PRIZE(15) = 30 -> UNCERTAIN band.
        assert result.score == 30
        assert result.band == "UNCERTAIN"

    def test_otp_plus_impersonation_plus_threat_is_capped_at_rule_ceiling(
        self,
    ) -> None:
        """Severe combined rule signals are capped by RULE_POINTS_CAP.

        OTP_REQUEST(20) + ACCOUNT_BLOCKED(12) + IMPERSONATION(15) = 47 raw,
        capped to 45 (RULE_POINTS_CAP). This lands in MEDIUM (40-74), not
        HIGH (75+) -- reaching HIGH requires corroborating URL or ML
        evidence, by design. See module docstring.
        """
        text = (
            "This is calling from your bank official. Your account will be "
            "blocked today. Please share OTP immediately to verify."
        )
        evidence = run_all_rules(text)
        result = calculate_risk(evidence)
        assert result.rules.raw_points == 47
        assert result.rules.points == 45  # capped
        assert result.score == 45
        assert result.band == "MEDIUM"

    def test_rules_alone_can_never_reach_high_band(self) -> None:
        """No combination of rule signals alone can exceed RULE_POINTS_CAP.

        This is the concrete, executable version of the design decision:
        rules-only evidence tops out at 45 points, which is below the HIGH
        threshold of 75. Reaching HIGH requires URL and/or ML corroboration.
        """
        # Fire every single rule at once -- the worst case.
        text = (
            "Congratulations! You have won a lucky draw prize. "
            "This is calling from your bank official. "
            "Your account will be blocked immediately. "
            "Please share your OTP, PIN, and password now. "
            "Pay the fee immediately. "
            "Install AnyDesk so our technician can assist you."
        )
        evidence = run_all_rules(text)
        result = calculate_risk(evidence)
        assert result.rules.points == 45  # hits the cap exactly
        assert result.score <= 45
        assert result.band in ("UNCERTAIN", "MEDIUM")
        assert result.band != "HIGH"
