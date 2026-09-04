"""Tests for app.analyzers.url_parser.

Test D-equivalent (deceptive userinfo/@ trick) is the most security-
critical case here: a URL like http://sbi.co.in@evil-site.com/phish must
resolve full_host/registered_domain to the REAL destination (evil-site.com),
not the deceptive-looking prefix before the @. If this were ever wrong,
every downstream lookalike-domain check would be checking the wrong host.
"""

from __future__ import annotations

from app.analyzers.url_parser import parse_url


class TestLegitimateDomainDecomposition:
    def test_psl_aware_split_for_co_in(self) -> None:
        parsed = parse_url("https://www.sbi.co.in/personal-banking")
        assert parsed.sld == "sbi"
        assert parsed.suffix == "co.in"
        assert parsed.registered_domain == "sbi.co.in"
        assert parsed.subdomain == "www"

    def test_plain_dot_com_domain(self) -> None:
        parsed = parse_url("https://hdfcbank.com/login")
        assert parsed.sld == "hdfcbank"
        assert parsed.suffix == "com"
        assert parsed.registered_domain == "hdfcbank.com"


class TestLookalikeDomainStructure:
    def test_deceptive_separator_domain_parses_correctly(self) -> None:
        parsed = parse_url("https://sbi-kyc-update.xyz/login")
        assert parsed.sld == "sbi-kyc-update"
        assert parsed.suffix == "xyz"
        assert parsed.registered_domain == "sbi-kyc-update.xyz"


class TestIpHostname:
    def test_ipv4_hostname_is_detected(self) -> None:
        parsed = parse_url("http://192.168.1.1/admin")
        assert parsed.is_ip_hostname is True

    def test_domain_name_is_not_flagged_as_ip(self) -> None:
        parsed = parse_url("https://sbi.co.in/login")
        assert parsed.is_ip_hostname is False


class TestDeceptiveUserinfo:
    """The most security-critical test in this file. See module docstring."""

    def test_userinfo_trick_resolves_to_real_destination(self) -> None:
        parsed = parse_url("http://sbi.co.in@evil-site.com/phish")
        assert parsed.has_userinfo is True
        assert parsed.full_host == "evil-site.com"
        assert parsed.registered_domain == "evil-site.com"
        # Explicitly confirm the deceptive prefix is NOT what we report.
        assert "sbi" not in parsed.registered_domain

    def test_url_without_userinfo_is_not_flagged(self) -> None:
        parsed = parse_url("https://sbi.co.in/login")
        assert parsed.has_userinfo is False


class TestConfigLoader:
    def test_brand_domain_map_contains_known_brands(self) -> None:
        from app.analyzers.url_config import get_brand_domain_map

        brands = get_brand_domain_map()
        assert "sbi.co.in" in brands["sbi"]
        assert "hdfcbank.com" in brands["hdfc"]

    def test_high_risk_tlds_contains_known_risky_tlds_not_common_ones(self) -> None:
        from app.analyzers.url_config import get_high_risk_tlds

        tlds = get_high_risk_tlds()
        assert "xyz" in tlds
        assert "top" in tlds
        assert "com" not in tlds
        assert "in" not in tlds
