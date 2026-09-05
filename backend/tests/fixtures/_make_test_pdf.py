"""Builds a minimal, valid, hand-crafted PDF byte string for tests.

No external PDF-writing library is available (reportlab, fpdf2 are not
project dependencies), so this constructs the minimal PDF object
structure directly: a single page with a content stream containing a
real text-showing (Tj) operator. This ensures test_document_extraction.py
exercises pypdf against genuine PDF syntax, not a mock.
"""

from __future__ import annotations


def make_pdf_with_text(text: str) -> bytes:
    content_stream = f"BT /F1 24 Tf 50 700 Td ({text}) Tj ET".encode("latin-1")

    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> "
        b"/MediaBox [0 0 612 792] /Contents 5 0 R >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Length "
        + str(len(content_stream)).encode("ascii")
        + b" >>\nstream\n"
        + content_stream
        + b"\nendstream",
    ]

    buffer = bytearray(b"%PDF-1.4\n")
    offsets = [0]  # object 0 is unused in the xref table

    for i, obj_body in enumerate(objects, start=1):
        offsets.append(len(buffer))
        buffer += f"{i} 0 obj\n".encode("ascii")
        buffer += obj_body
        buffer += b"\nendobj\n"

    xref_offset = len(buffer)
    buffer += f"xref\n0 {len(objects) + 1}\n".encode("ascii")
    buffer += b"0000000000 65535 f \n"
    for offset in offsets[1:]:
        buffer += f"{offset:010d} 00000 n \n".encode("ascii")

    buffer += b"trailer\n"
    buffer += f"<< /Size {len(objects) + 1} /Root 1 0 R >>\n".encode("ascii")
    buffer += b"startxref\n"
    buffer += f"{xref_offset}\n".encode("ascii")
    buffer += b"%%EOF"

    return bytes(buffer)


def make_empty_pdf() -> bytes:
    """A valid PDF with a page but no text content at all."""
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /Resources << >> "
        b"/MediaBox [0 0 612 792] /Contents 4 0 R >>",
        b"<< /Length 0 >>\nstream\n\nendstream",
    ]

    buffer = bytearray(b"%PDF-1.4\n")
    offsets = [0]

    for i, obj_body in enumerate(objects, start=1):
        offsets.append(len(buffer))
        buffer += f"{i} 0 obj\n".encode("ascii")
        buffer += obj_body
        buffer += b"\nendobj\n"

    xref_offset = len(buffer)
    buffer += f"xref\n0 {len(objects) + 1}\n".encode("ascii")
    buffer += b"0000000000 65535 f \n"
    for offset in offsets[1:]:
        buffer += f"{offset:010d} 00000 n \n".encode("ascii")

    buffer += b"trailer\n"
    buffer += f"<< /Size {len(objects) + 1} /Root 1 0 R >>\n".encode("ascii")
    buffer += b"startxref\n"
    buffer += f"{xref_offset}\n".encode("ascii")
    buffer += b"%%EOF"

    return bytes(buffer)
