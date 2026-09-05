"""Tests for app.services.org_directory -- deterministic org identification."""

from __future__ import annotations

from app.services.org_directory import NATIONAL_CYBERCRIME, identify_organizations


class TestIdentifyOrganizations:
    def test_sbi_keyword_matches_sbi_and_national_fallback(self) -> None:
        results = identify_organizations("This is SBI. Your account will be blocked.")
        keys = [item.key for item in results]
        assert keys[0] == "SBI"
        assert keys[-1] == "NATIONAL_CYBERCRIME"

    def test_irctc_keyword_matches(self) -> None:
        results = identify_organizations("Your IRCTC ticket refund is pending.")
        assert results[0].key == "IRCTC"

    def test_karnataka_keyword_matches(self) -> None:
        results = identify_organizations("Karnataka State Government notice: pay fine now.")
        assert any(item.key == "KARNATAKA_CYBER_POLICE" for item in results)

    def test_case_insensitive(self) -> None:
        results = identify_organizations("hello from ICICI BANK security team")
        assert results[0].key == "ICICI"

    def test_no_specific_org_falls_back_to_national_only(self) -> None:
        results = identify_organizations("You have won a lottery, click here to claim.")
        assert results == [NATIONAL_CYBERCRIME]

    def test_national_cybercrime_always_present_and_last(self) -> None:
        results = identify_organizations("SBI HDFC ICICI all at once")
        assert results[-1].key == "NATIONAL_CYBERCRIME"
        assert results[-1].phone == "1930"

    def test_every_specific_entry_has_a_verifiable_source_url(self) -> None:
        from app.services.org_directory import _DIRECTORY

        for _, contact in _DIRECTORY:
            assert contact.source_url.startswith("https://")
            assert contact.display_name
