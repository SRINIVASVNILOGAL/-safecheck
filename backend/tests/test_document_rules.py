"""Tests for app.analyzers.document_rules.

Codifies the three smoke-test scenarios verified manually during Phase 5
Step 3, including a regression test for a real gap found during manual
testing: "along with a registration fee" did not originally match
ADVANCE_FEE_REQUEST because the pattern only recognized verb-led phrasing
(pay/deposit/transfer/remit), not this common real-world construction.
"""

from __future__ import annotations

from app.analyzers.document_rules import run_all_document_rules
from app.risk.engine import calculate_risk


class TestIndividualDocumentRules:
    def test_advance_fee_request_matches_verb_led_phrasing(self) -> None:
        text = "Please pay the admission fee of Rs 25000 before you can confirm your seat."
        evidence = run_all_document_rules(text)
        signals = {e.signal for e in evidence}
        assert "ADVANCE_FEE_REQUEST" in signals

    def test_advance_fee_request_matches_along_with_phrasing(self) -> None:
        """Regression test: 'along with a registration fee ... to confirm'
        did not originally match because the pattern required a leading
        verb (pay/deposit/transfer/remit). Found during Phase 5 Step 3
        manual smoke testing."""
        text = (
            "Please share your passport copy and aadhaar copy along with "
            "a registration fee of Rs 5000 to confirm your placement."
        )
        evidence = run_all_document_rules(text)
        signals = {e.signal for e in evidence}
        assert "ADVANCE_FEE_REQUEST" in signals

    def test_unrealistic_guarantee_matches(self) -> None:
        text = "This offer guarantees admission without interview required."
        evidence = run_all_document_rules(text)
        signals = {e.signal for e in evidence}
        assert "UNREALISTIC_GUARANTEE" in signals

    def test_informal_contact_only_matches_phone_number(self) -> None:
        text = "Contact us at +919876543210 for further details."
        evidence = run_all_document_rules(text)
        signals = {e.signal for e in evidence}
        assert "INFORMAL_CONTACT_ONLY" in signals

    def test_informal_contact_only_matches_free_email(self) -> None:
        text = "Reach us at hrteam.offers@gmail.com for confirmation."
        evidence = run_all_document_rules(text)
        signals = {e.signal for e in evidence}
        assert "INFORMAL_CONTACT_ONLY" in signals

    def test_urgency_limited_time_matches(self) -> None:
        text = "Only 5 seats left, offer expires within 24 hours."
        evidence = run_all_document_rules(text)
        signals = {e.signal for e in evidence}
        assert "URGENCY_LIMITED_TIME" in signals

    def test_sensitive_document_request_matches(self) -> None:
        text = "Please send your passport copy and aadhaar copy to proceed."
        evidence = run_all_document_rules(text)
        signals = {e.signal for e in evidence}
        assert "SENSITIVE_DOCUMENT_REQUEST" in signals


class TestDocumentRuleNonMatches:
    def test_legitimate_university_letter_triggers_nothing(self) -> None:
        text = (
            "Dear Applicant, we are pleased to inform you that your "
            "application has been received. The admission committee will "
            "review your documents and respond within 4 weeks. For "
            "queries, contact admissions@university.edu.in or call our "
            "office at 011-23456789."
        )
        evidence = run_all_document_rules(text)
        assert evidence == []

    def test_empty_string_triggers_nothing(self) -> None:
        assert run_all_document_rules("") == []

    def test_official_edu_domain_email_does_not_trigger_informal_contact(
        self,
    ) -> None:
        """An official-looking .edu.in email must not be flagged as an
        informal contact channel -- only free consumer email providers
        (gmail/yahoo/hotmail/outlook) are considered informal."""
        text = "For queries, contact admissions@university.edu.in."
        evidence = run_all_document_rules(text)
        signals = {e.signal for e in evidence}
        assert "INFORMAL_CONTACT_ONLY" not in signals


class TestDocumentRuleCombinations:
    def test_fake_admission_letter_lands_in_medium_via_shared_rule_cap(
        self,
    ) -> None:
        """Four document red flags combine and are capped at the shared
        Rule_points cap of 45 (same cap used by app.risk.rules message
        signals -- there is no separate document category, per
        docs/scoring-engine.md Section 2)."""
        text = (
            "Congratulations! You have been selected for admission to our "
            "MBA program. This offer guarantees admission without "
            "interview required. Please pay the admission fee of Rs 25000 "
            "before you can confirm your seat. Only 5 seats left, offer "
            "expires within 24 hours. Contact us at +919876543210 for "
            "further details."
        )
        evidence = run_all_document_rules(text)
        result = calculate_risk(evidence)

        raw_sum = sum(e.points for e in evidence)
        assert raw_sum == 62  # 20 + 15 + 15 + 12
        assert result.rules.points == 45  # capped
        assert result.score == 45
        assert result.band == "MEDIUM"

    def test_signal_names_do_not_collide_with_message_rules(self) -> None:
        """Document signal names must be distinguishable from
        app.risk.rules message signals if ever combined in a future
        phase (e.g. email with a document attachment)."""
        from app.risk.rules import ALL_RULES

        message_signals = set()
        for rule in ALL_RULES:
            result = rule(
                "pay immediately otp pin password blocked congratulations "
                "this is calling from bank official anydesk"
            )
            if result is not None:
                message_signals.add(result.signal)

        document_evidence = run_all_document_rules(
            "pay the admission fee before confirm guarantees admission "
            "without interview only 5 seats left contact us at "
            "+919876543210 send your passport copy"
        )
        document_signals = {e.signal for e in document_evidence}

        assert message_signals.isdisjoint(document_signals)
