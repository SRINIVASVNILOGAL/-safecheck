"""POST /v1/document -- document (PDF/image) analysis endpoint.

Pipeline:

    multipart file upload
        -> validate content-type and size
        -> extract_text() [app.analyzers.document_extraction]
        -> run_all_document_rules() + run_all_rules() on extracted text
        -> build_check_response() [app.api.check, shared tail]

Extraction failure (corrupt file, no text layer, missing Tesseract) is
treated exactly like an external provider failure (Phase 4 pattern):
TEXT_EXTRACTION evidence with availability="unavailable", points=0.
This still returns 200 -- a document that could not be read is not a
"clean" result, and the explanation/uncertainty fields make that clear
to the user, per docs/api-contract.md's "Extraction failure handling"
section.

Both message-level rules (app.risk.rules -- urgency, OTP requests, etc.)
and document-specific rules (app.analyzers.document_rules -- advance
fee, unrealistic guarantees, etc.) run against the extracted text, since
a fraudulent document can contain either or both kinds of red flag (e.g.
an admission-offer PDF that also demands an OTP be shared).
"""

from __future__ import annotations

from uuid import uuid4

from fastapi import APIRouter, HTTPException, UploadFile

from app.analyzers.document_extraction import get_document_kind, extract_text
from app.analyzers.document_rules import run_all_document_rules
from app.api.check import build_check_response
from app.models.check import CheckResponse
from app.risk.evidence import Evidence
from app.risk.rules import run_all_rules

router = APIRouter()

MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB, per docs/api-contract.md


def _unavailable_extraction_evidence(reason: str) -> Evidence:
    return Evidence(
        category="rules",
        signal="TEXT_EXTRACTION",
        points=0,
        reason=reason,
        source="document_analyzer",
        correlation_group="CORR_EXTRACTION",
        availability="unavailable",
        confidence=0.0,
        severity="LOW",
    )


@router.post("/v1/document", response_model=CheckResponse)
async def analyze_document(file: UploadFile) -> CheckResponse:
    if file is None or not file.filename:
        raise HTTPException(status_code=400, detail="No file was provided.")

    content_type = file.content_type or ""
    if get_document_kind(content_type) is None:
        raise HTTPException(
            status_code=415,
            detail=(
                f"Unsupported file type: {content_type!r}. "
                "Only application/pdf, image/png, and image/jpeg are accepted."
            ),
        )

    file_bytes = await file.read()

    if not file_bytes:
        raise HTTPException(status_code=400, detail="The uploaded file is empty.")

    if len(file_bytes) > MAX_FILE_SIZE_BYTES:
        raise HTTPException(
            status_code=413,
            detail=(
                f"File exceeds the maximum allowed size of "
                f"{MAX_FILE_SIZE_BYTES // (1024 * 1024)} MB."
            ),
        )

    extraction_result = extract_text(file_bytes, content_type)

    if not extraction_result.ok:
        evidence = [_unavailable_extraction_evidence(extraction_result.reason)]
    else:
        text = extraction_result.text
        evidence = [
            *run_all_document_rules(text),
            *run_all_rules(text),
        ]
        if extraction_result.truncated:
            evidence.append(
                Evidence(
                    category="rules",
                    signal="TEXT_TRUNCATED",
                    points=0,
                    reason=(
                        "The extracted text exceeded the maximum length "
                        "and was truncated before analysis."
                    ),
                    source="document_analyzer",
                    correlation_group="CORR_EXTRACTION",
                    availability="available",
                    confidence=1.0,
                    severity="LOW",
                )
            )

    return build_check_response(
        case_id=f"case_{uuid4().hex[:8]}",
        source_type="DOCUMENT",
        evidence_list=evidence,
    )
