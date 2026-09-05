"""POST /v1/document -- document (PDF/image) analysis endpoint.

Pipeline:

    multipart file upload
        -> validate content-type and size
        -> extract_text() [app.analyzers.document_extraction]
        -> run_document_pipeline() [app.graph.pipeline, LangGraph as of Phase 7]
        -> build_check_response_from_result() [app.api.check, shared tail]

Extraction failure (corrupt file, no text layer, missing Tesseract) is
treated exactly like an external provider failure (Phase 4 pattern):
TEXT_EXTRACTION evidence with availability="unavailable", points=0.
This still returns 200 -- a document that could not be read is not a
"clean" result, and the explanation/uncertainty fields make that clear
to the user, per docs/api-contract.md's "Extraction failure handling"
section. This is now handled inside the graph's extract_evidence node
(app.graph.nodes) rather than here -- this module only does file-level
validation and extraction, then hands off to the graph.

Both message-level rules (app.risk.rules -- urgency, OTP requests, etc.)
and document-specific rules (app.analyzers.document_rules -- advance
fee, unrealistic guarantees, etc.) run against the extracted text inside
the graph, since a fraudulent document can contain either or both kinds
of red flag (e.g. an admission-offer PDF that also demands an OTP be
shared).
"""

from __future__ import annotations

from uuid import uuid4

from fastapi import APIRouter, HTTPException, UploadFile

from app.analyzers.document_extraction import get_document_kind, extract_text
from app.api.check import build_check_response_from_result
from app.graph.pipeline import run_document_pipeline
from app.models.check import CheckResponse

router = APIRouter()

MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB, per docs/api-contract.md


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

    pipeline_result = await run_document_pipeline(
        extraction_ok=extraction_result.ok,
        text=extraction_result.text if extraction_result.ok else None,
        extraction_reason=None if extraction_result.ok else extraction_result.reason,
        truncated=extraction_result.truncated if extraction_result.ok else False,
    )

    return build_check_response_from_result(
        case_id=f"case_{uuid4().hex[:8]}",
        source_type="DOCUMENT",
        pipeline_result=pipeline_result,
    )
