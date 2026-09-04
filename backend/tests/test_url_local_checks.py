"""Tests for the remaining local URL heuristics and run_local_url_checks().

Codifies the four smoke-test scenarios from Phase 4 Step 3, including the
important edge case that a multi-label suffix like "co.in" must not
misfire against the high-risk TLD list (only the final label, "in", is
checked, and "in" is not on the high-risk list).
"""

from __future__ import annotations

from app.analyzers.url_parser import parse_url
from app.analyzers.url_rules import (
    detect_high_risk_tld,
    detect_insecure_http,
    detect_ip_hostname,
    run_local_url_checks,
)
from app.risk.engine import calculate_risk


class TestInsecureHttp:
    def test_http_scheme_is_flagged(self) -> None:
        parsed = parse_url("http://example.com/login")
        evidence = detect_insecure_http(parsed)
        assert evidence is not None
        assert evidence.signal == "INSECURE_HTTP"
        assert evidence.points == 10

    def test_https_scheme_is_not_flagged(self) -> None:
        parsed = parse_url("https://example.com/login")
        assert detect_insecure_http(parsed) is None


class TestIpHostnameEvidence:
    def test_ip_hostname_is_flagged(self) -> None:
        parsed = parse_url("http://192.168.1.1/admin")
        evidence = detect_ip_hostname(parsed)
        assert evidence is not None
        assert evidence.signal == "IP_HOSTNAME"
        assert evidence.points == 15

    def test_domain_hostname_is_not_flagged(self) -> None:
        parsed = parse_url("https://example.com/page")
        assert detect_ip_hostname(parsed) is None


class TestHighRiskTld:
    def test_xyz_tld_is_flagged(self) -> None:
        parsed = parse_url("https://example.xyz/page")
        evidence = detect_high_risk_tld(parsed)
        assert evidence is not None
        assert evidence.signal == "HIGH_RISK_TLD"
        assert evidence.points == 10

    def test_com_tld_is_not_flagged(self) -> None:
        parsed = parse_url("https://example.com/page")
        assert detect_high_risk_tld(parsed) is None

    def test_multi_label_suffix_co_in_does_not_misfire(self) -> None:
        """Critical edge case: 'co.in' must not match against the
        high-risk TLD list via its full multi-label suffix. Only the
        final label ('in') is checked, and 'in' is not high-risk."""
        parsed = parse_url("https://www.sbi.co.in/personal-banking")
        assert detect_high_risk_tld(parsed) is None


class TestRunLocalUrlChecks:
    def test_fully_legitimate_url_has_no_evidence(self) -> None:
        parsed = parse_url("https://www.sbi.co.in/personal-banking")
        assert run_local_url_checks(parsed) == []

    def test_multiple_signals_combine(self) -> None:
        parsed = parse_url("http://sbi-kyc-update.xyz/login")
        evidence = run_local_url_checks(parsed)
        signals = {e.signal for e in evidence}
        assert signals == {"LOOKALIKE_DOMAIN", "INSECURE_HTTP", "HIGH_RISK_TLD"}
        assert sum(e.points for e in evidence) == 45

    def test_ip_hostname_over_http_combines(self) -> None:
        parsed = parse_url("http://192.168.1.1/admin/login.php")
        evidence = run_local_url_checks(parsed)
        signals = {e.signal for e in evidence}
        assert signals == {"INSECURE_HTTP", "IP_HOSTNAME"}

    def test_lookalike_and_typosquatting_never_both_appear(self) -> None:
        """run_local_url_checks() enforces mutual exclusivity between
        LOOKALIKE_DOMAIN and TYPOSQUATTING for a single URL."""
        parsed = parse_url("http://sbi-kyc-update.xyz/login")
        evidence = run_local_url_checks(parsed)
        signals = {e.signal for e in evidence}
        assert not ({"LOOKALIKE_DOMAIN", "TYPOSQUATTING"} <= signals)


class TestLocalUrlChecksThroughRiskEngine:
    def test_deceptive_url_alone_is_capped_at_url_ceiling_and_lands_uncertain(
        self,
    ) -> None:
        """A deceptive URL with no rule/ML corroboration is capped at
        URL_POINTS_CAP=35, landing in UNCERTAIN (25-39) -- not MEDIUM or
        HIGH. Same corroboration philosophy as the rules-only ceiling
        from Phase 3: no single category should unilaterally declare a
        strong verdict.
        """
        parsed = parse_url("http://sbi-kyc-update.xyz/login")
        evidence = run_local_url_checks(parsed)
        result = calculate_risk(evidence)
        assert result.url.raw_points == 45
        assert result.url.points == 35  # capped
        assert result.score == 35
        assert result.band == "UNCERTAIN"

    def test_clean_url_yields_zero_score(self) -> None:
        parsed = parse_url("https://www.sbi.co.in/personal-banking")
        evidence = run_local_url_checks(parsed)
        result = calculate_risk(evidence)
        assert result.score == 0
        assert result.band == "LOW"
