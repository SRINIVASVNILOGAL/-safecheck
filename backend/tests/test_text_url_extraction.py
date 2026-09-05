"""Tests for app.analyzers.text_url_extraction.

Regression coverage for the bug where a pasted TEXT/EMAIL message's
embedded link (frequently scheme-less, e.g. "kredt.be/3u9CoOh" rather
than "https://kredt.be/3u9CoOh") was invisible to the URL analyzer,
letting an obvious toll/fee scam score far too low.
"""

from __future__ import annotations

from app.analyzers.text_url_extraction import extract_urls_from_text


class TestBareDomainExtraction:
    def test_bracketed_bare_domain_with_path_is_extracted(self) -> None:
        text = "Pay immediately to avoid extra penalties: [kredt.be/3u9CoOh]"
        found, urls = extract_urls_from_text(text)
        assert found == 1
        assert urls == ("http://kredt.be/3u9CoOh",)

    def test_scheme_url_is_extracted_normally(self) -> None:
        found, urls = extract_urls_from_text("Visit https://example.com/path?x=1 now")
        assert found == 1
        assert urls == ("https://example.com/path?x=1",)

    def test_scheme_and_bare_rematch_of_same_link_are_not_duplicated(self) -> None:
        text = "Click https://example.com/a then also see example.com/a again"
        found, urls = extract_urls_from_text(text)
        assert found == 1
        assert urls == ("https://example.com/a",)


class TestNonMatches:
    def test_legitimate_receipt_has_no_urls(self) -> None:
        found, urls = extract_urls_from_text(
            "Rs 500 sent successfully to Ravi through UPI. Reference 123456789."
        )
        assert found == 0
        assert urls == ()

    def test_ordinary_abbreviations_are_not_urls(self) -> None:
        found, urls = extract_urls_from_text("e.g. this is fine, so is etc. and $3.25")
        assert found == 0
        assert urls == ()

    def test_empty_string_has_no_urls(self) -> None:
        assert extract_urls_from_text("") == (0, ())


class TestLimit:
    def test_more_than_max_urls_is_bounded(self) -> None:
        text = " ".join(f"https://example{i}.com/page" for i in range(10))
        found, urls = extract_urls_from_text(text)
        assert found == 10  # total unique found, matching gmail._canonical_urls's contract
        assert len(urls) == 5  # returned tuple is bounded to MAX_EXTRACTED_URLS
