"""Document text extraction: PDF (pypdf) and image OCR (pytesseract).

Mirrors the external-provider pattern from Phase 4 (google_safe_browsing,
virustotal): extraction is not guaranteed to succeed, and failure must
never be silently treated as "clean." Every failure mode returns a
result with ok=False and a specific reason, which the caller (Step 4)
converts into TEXT_EXTRACTION evidence with availability="unavailable"
and points=0, per docs/api-contract.md's "Extraction failure handling"
section.

PDF extraction requires no external binary (pypdf is pure Python).
Image OCR requires the Tesseract binary to be installed separately on
the host machine -- pytesseract is only a thin wrapper around it. We
check for Tesseract's availability explicitly rather than letting a
missing-binary error surface as an unhandled exception.
"""

from __future__ import annotations

from dataclasses import dataclass
from io import BytesIO

import pytesseract
from PIL import Image, UnidentifiedImageError
from pypdf import PdfReader
from pypdf.errors import PdfReadError

MAX_EXTRACTED_TEXT_CHARS = 20_000

_SUPPORTED_CONTENT_TYPES = {
    "application/pdf": "pdf",
    "image/png": "image",
    "image/jpeg": "image",
}


@dataclass(frozen=True)
class ExtractionResult:
    """Outcome of attempting to extract text from an uploaded document.

    ok=True means extraction succeeded and `text` contains the (possibly
    truncated) result. ok=False means extraction could not be completed;
    `text` is empty and `reason` explains why -- this must be surfaced as
    unavailable evidence, never treated as "the document is clean."
    """

    ok: bool
    text: str
    truncated: bool
    reason: str = ""


def get_document_kind(content_type: str) -> str | None:
    """Return 'pdf' or 'image' for a supported content type, else None."""
    return _SUPPORTED_CONTENT_TYPES.get(content_type.lower())


def is_tesseract_available() -> bool:
    """Check whether the Tesseract OCR binary is actually installed.

    This is checked explicitly (rather than letting pytesseract raise)
    so a missing binary produces a clear, specific reason string instead
    of an opaque exception surfacing from deep inside pytesseract.
    """
    try:
        pytesseract.get_tesseract_version()
        return True
    except (pytesseract.TesseractNotFoundError, OSError):
        return False


def _truncate(text: str) -> tuple[str, bool]:
    stripped = text.strip()
    if len(stripped) <= MAX_EXTRACTED_TEXT_CHARS:
        return stripped, False
    return stripped[:MAX_EXTRACTED_TEXT_CHARS], True


def extract_pdf_text(file_bytes: bytes) -> ExtractionResult:
    """Extract text from PDF bytes using pypdf.

    Returns ok=False (not an exception) for: corrupt/unreadable PDFs,
    and PDFs with no extractable text (e.g. a scanned image with no
    embedded text layer -- pypdf cannot OCR, it only reads existing text).
    """
    try:
        reader = PdfReader(BytesIO(file_bytes))
    except PdfReadError:
        return ExtractionResult(
            ok=False, text="", truncated=False,
            reason="The PDF file is corrupt or could not be read.",
        )
    except Exception as exc:  # noqa: BLE001 - defense-in-depth, see module docstring pattern from Phase 4
        return ExtractionResult(
            ok=False, text="", truncated=False,
            reason=f"The PDF could not be opened ({exc.__class__.__name__}).",
        )

    try:
        pages_text = [page.extract_text() or "" for page in reader.pages]
    except Exception as exc:  # noqa: BLE001
        return ExtractionResult(
            ok=False, text="", truncated=False,
            reason=f"Text could not be extracted from the PDF ({exc.__class__.__name__}).",
        )

    combined = "\n".join(pages_text).strip()
    if not combined:
        return ExtractionResult(
            ok=False, text="", truncated=False,
            reason=(
                "The PDF has no extractable text. It may be a scanned "
                "image without a text layer."
            ),
        )

    text, truncated = _truncate(combined)
    return ExtractionResult(ok=True, text=text, truncated=truncated)


def extract_image_text(file_bytes: bytes) -> ExtractionResult:
    """Extract text from image bytes using Tesseract OCR via pytesseract.

    Returns ok=False for: Tesseract not installed, unreadable/corrupt
    image data, or an image with no detectable text.
    """
    if not is_tesseract_available():
        return ExtractionResult(
            ok=False, text="", truncated=False,
            reason=(
                "OCR is not available because the Tesseract engine is "
                "not installed on this server."
            ),
        )

    try:
        image = Image.open(BytesIO(file_bytes))
        image.load()
    except UnidentifiedImageError:
        return ExtractionResult(
            ok=False, text="", truncated=False,
            reason="The image file is corrupt or could not be read.",
        )
    except Exception as exc:  # noqa: BLE001
        return ExtractionResult(
            ok=False, text="", truncated=False,
            reason=f"The image could not be opened ({exc.__class__.__name__}).",
        )

    try:
        raw_text = pytesseract.image_to_string(image)
    except pytesseract.TesseractNotFoundError:
        # Race condition guard: is_tesseract_available() checked above,
        # but the binary could theoretically become unavailable between
        # that check and this call in a long-running process.
        return ExtractionResult(
            ok=False, text="", truncated=False,
            reason="OCR failed because the Tesseract engine is not available.",
        )
    except Exception as exc:  # noqa: BLE001
        return ExtractionResult(
            ok=False, text="", truncated=False,
            reason=f"OCR failed unexpectedly ({exc.__class__.__name__}).",
        )

    stripped = raw_text.strip()
    if not stripped:
        return ExtractionResult(
            ok=False, text="", truncated=False,
            reason="OCR completed but no text was detected in the image.",
        )

    text, truncated = _truncate(stripped)
    return ExtractionResult(ok=True, text=text, truncated=truncated)


def extract_text(file_bytes: bytes, content_type: str) -> ExtractionResult:
    """Dispatch to the correct extractor based on content type.

    Callers should validate content_type against get_document_kind()
    before calling this (to return a clean 415 for unsupported types at
    the API layer) -- this function itself will return ok=False for an
    unrecognized type rather than raising, as a defensive fallback.
    """
    kind = get_document_kind(content_type)
    if kind == "pdf":
        return extract_pdf_text(file_bytes)
    if kind == "image":
        return extract_image_text(file_bytes)
    return ExtractionResult(
        ok=False, text="", truncated=False,
        reason=f"Unsupported content type for extraction: {content_type!r}.",
    )
