"""Tests for POST /v1/document (Phase 5 Step 4).

Uses the hand-crafted PDF fixture from tests/fixtures/_make_test_pdf.py
for real extraction (not mocked), and exercises the real, confirmed
missing-Tesseract environment for the image/OCR unavailable path -- same
"verify against real behavior" discipline used throughout this project.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "fixtures"))

from _make_test_pdf import make_empty_pdf, make_pdf_with_text  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402

client = TestClient(app)


class TestSuccessfulDocumentAnalysis:
    def test_fraudulent_pdf_combines_document_and_message_rules(self) -> None:
        """A single document can trigger both document-specific rules
        (ADVANCE_FEE_REQUEST) and message-level rules (URGENT_PAYMENT),
        since both rule sets run against the same extracted text."""
        pdf_bytes = make_pdf_with_text(
            "Pay the admission fee immediately to confirm your seat."
        )
        response = client.post(
            "/v1/document",
            files={"file": ("offer.pdf", pdf_bytes, "application/pdf")},
        )
        assert response.status_code == 200
        body = response.json()
        assert body["source_type"] == "DOCUMENT"
        signals = {e["signal"] for e in body["evidence"]}
        assert "ADVANCE_FEE_REQUEST" in signals
        assert "URGENT_PAYMENT" in signals
        assert body["risk"]["score"] == 35
        assert body["risk"]["band"] == "UNCERTAIN"

    def test_clean_pdf_scores_zero(self) -> None:
        pdf_bytes = make_pdf_with_text(
            "Thank you for your application. We will respond soon."
        )
        response = client.post(
            "/v1/document",
            files={"file": ("letter.pdf", pdf_bytes, "application/pdf")},
        )
        assert response.status_code == 200
        body = response.json()
        assert body["risk"]["score"] == 0
        assert body["risk"]["band"] == "LOW"
        assert body["evidence"] == []


class TestExtractionFailureHandling:
    def test_pdf_with_no_text_layer_returns_unavailable_not_clean(self) -> None:
        """A LOW-scoring result here must not be mistaken for 'this
        document is safe' -- extraction failed, nothing was checked."""
        response = client.post(
            "/v1/document",
            files={"file": ("scanned.pdf", make_empty_pdf(), "application/pdf")},
        )
        assert response.status_code == 200
        body = response.json()
        assert body["risk"]["score"] == 0
        assert body["risk"]["band"] == "LOW"

        extraction_evidence = next(
            e for e in body["evidence"] if e["signal"] == "TEXT_EXTRACTION"
        )
        assert extraction_evidence["availability"] == "unavailable"
        assert extraction_evidence["points"] == 0
        assert len(body["explanation"]["uncertainty"]) == 1

    def test_image_upload_reports_unavailable_when_tesseract_missing(self) -> None:
        """Exercises the REAL, confirmed-absent Tesseract environment on
        this dev machine, not a simulated one."""
        response = client.post(
            "/v1/document",
            files={"file": ("screenshot.png", b"fake png bytes", "image/png")},
        )
        assert response.status_code == 200
        body = response.json()
        assert body["risk"]["score"] == 0
        assert body["risk"]["band"] == "LOW"

        extraction_evidence = next(
            e for e in body["evidence"] if e["signal"] == "TEXT_EXTRACTION"
        )
        assert extraction_evidence["availability"] == "unavailable"
        assert "tesseract" in extraction_evidence["reason"].lower()

    def test_corrupt_pdf_returns_unavailable_not_a_500(self) -> None:
        response = client.post(
            "/v1/document",
            files={"file": ("bad.pdf", b"not a real pdf", "application/pdf")},
        )
        assert response.status_code == 200
        body = response.json()
        extraction_evidence = next(
            e for e in body["evidence"] if e["signal"] == "TEXT_EXTRACTION"
        )
        assert extraction_evidence["availability"] == "unavailable"


class TestRequestValidation:
    def test_unsupported_file_type_returns_415(self) -> None:
        response = client.post(
            "/v1/document",
            files={"file": ("data.zip", b"PK fake zip content", "application/zip")},
        )
        assert response.status_code == 415

    def test_empty_file_returns_400(self) -> None:
        response = client.post(
            "/v1/document",
            files={"file": ("empty.pdf", b"", "application/pdf")},
        )
        assert response.status_code == 400

    def test_oversized_file_returns_413(self) -> None:
        oversized = b"A" * (10 * 1024 * 1024 + 1)
        response = client.post(
            "/v1/document",
            files={"file": ("big.pdf", oversized, "application/pdf")},
        )
        assert response.status_code == 413

    def test_no_file_field_returns_422(self) -> None:
        """FastAPI itself returns 422 for a genuinely missing required
        multipart field (distinct from our own 400 for an empty file)."""
        response = client.post("/v1/document")
        assert response.status_code == 422


class TestTextTruncation:
    def test_oversized_extracted_text_is_truncated_and_reported(self) -> None:
        from app.analyzers.document_extraction import MAX_EXTRACTED_TEXT_CHARS

        long_text = "filler " * (MAX_EXTRACTED_TEXT_CHARS // 6)
        pdf_bytes = make_pdf_with_text(long_text)
        response = client.post(
            "/v1/document",
            files={"file": ("long.pdf", pdf_bytes, "application/pdf")},
        )
        assert response.status_code == 200
        body = response.json()
        signals = {e["signal"] for e in body["evidence"]}
        assert "TEXT_TRUNCATED" in signals
