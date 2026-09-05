"""Tests for app.analyzers.document_extraction.

PDF tests use hand-crafted, genuinely valid PDF byte strings (see
tests/fixtures/_make_test_pdf.py) rather than mocks, so pypdf is
exercised against real PDF syntax. Image/OCR tests exercise the
missing-Tesseract path directly, since that is the actual, confirmed
state of the test environment (verified manually before writing these
tests) -- a real, honest test of the degradation path Step 1's contract
promises, not a simulated one.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "fixtures"))

from _make_test_pdf import make_empty_pdf, make_pdf_with_text  # noqa: E402

from app.analyzers.document_extraction import (  # noqa: E402
    MAX_EXTRACTED_TEXT_CHARS,
    extract_image_text,
    extract_pdf_text,
    extract_text,
    get_document_kind,
)


class TestGetDocumentKind:
    def test_pdf_content_type_is_recognized(self) -> None:
        assert get_document_kind("application/pdf") == "pdf"

    def test_png_content_type_is_recognized(self) -> None:
        assert get_document_kind("image/png") == "image"

    def test_jpeg_content_type_is_recognized(self) -> None:
        assert get_document_kind("image/jpeg") == "image"

    def test_unsupported_content_type_returns_none(self) -> None:
        assert get_document_kind("application/zip") is None

    def test_case_insensitive(self) -> None:
        assert get_document_kind("APPLICATION/PDF") == "pdf"


class TestExtractPdfText:
    def test_extracts_real_text_from_valid_pdf(self) -> None:
        pdf_bytes = make_pdf_with_text("Congratulations you have won a lottery")
        result = extract_pdf_text(pdf_bytes)
        assert result.ok is True
        assert result.text == "Congratulations you have won a lottery"
        assert result.truncated is False

    def test_pdf_with_no_text_layer_returns_ok_false(self) -> None:
        """A structurally valid PDF with an empty content stream --
        simulating a scanned image with no embedded text layer."""
        result = extract_pdf_text(make_empty_pdf())
        assert result.ok is False
        assert result.text == ""
        assert "no extractable text" in result.reason.lower()

    def test_corrupt_bytes_return_ok_false_not_an_exception(self) -> None:
        """Must never raise -- corrupt input is a normal, expected case."""
        result = extract_pdf_text(b"this is not a pdf at all")
        assert result.ok is False
        assert "corrupt" in result.reason.lower()

    def test_empty_bytes_return_ok_false(self) -> None:
        result = extract_pdf_text(b"")
        assert result.ok is False

    def test_long_text_is_truncated_at_max_chars(self) -> None:
        long_text = "A" * (MAX_EXTRACTED_TEXT_CHARS + 500)
        pdf_bytes = make_pdf_with_text(long_text)
        result = extract_pdf_text(pdf_bytes)
        assert result.ok is True
        assert len(result.text) == MAX_EXTRACTED_TEXT_CHARS
        assert result.truncated is True

    def test_short_text_is_not_truncated(self) -> None:
        pdf_bytes = make_pdf_with_text("short")
        result = extract_pdf_text(pdf_bytes)
        assert result.truncated is False


class TestExtractImageText:
    """These tests exercise the real, confirmed state of the test
    environment: Tesseract is not installed. This proves the actual
    degradation path, not a simulated one.
    """

    def test_missing_tesseract_returns_ok_false_with_specific_reason(self) -> None:
        result = extract_image_text(b"irrelevant bytes for this path")
        assert result.ok is False
        assert result.text == ""
        assert "tesseract" in result.reason.lower()

    def test_missing_tesseract_never_raises(self) -> None:
        """Even with garbage bytes, the missing-Tesseract check happens
        first and returns cleanly -- must never raise."""
        try:
            result = extract_image_text(b"\x00\x01\x02not an image")
        except Exception as exc:  # noqa: BLE001
            raise AssertionError(
                f"extract_image_text raised {exc!r} instead of returning ok=False"
            ) from exc
        assert result.ok is False


class TestExtractTextDispatch:
    def test_dispatches_pdf_to_pdf_extractor(self) -> None:
        pdf_bytes = make_pdf_with_text("dispatch test")
        result = extract_text(pdf_bytes, "application/pdf")
        assert result.ok is True
        assert result.text == "dispatch test"

    def test_dispatches_image_to_image_extractor(self) -> None:
        result = extract_text(b"fake image bytes", "image/png")
        # No Tesseract in this environment -- confirms it reached the
        # image path (not silently treated as unsupported).
        assert result.ok is False
        assert "tesseract" in result.reason.lower()

    def test_unsupported_content_type_returns_ok_false_not_an_exception(self) -> None:
        result = extract_text(b"data", "application/zip")
        assert result.ok is False
        assert "unsupported" in result.reason.lower()
