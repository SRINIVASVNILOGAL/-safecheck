"""POST /v1/check -- the main analysis endpoint.

Real, non-mock pipeline as of Phase 3 Step 5:

    request -> extract text (per source_type)
            -> run_all_rules()        [app.risk.rules]
            -> calculate_risk()       [app.risk.engine]
            -> deterministic explanation [app.services.explanation]
            -> CheckResponse

Scope note: only the rule engine exists so far (category="rules"). There
is no URL analyzer yet, so source_type="URL" currently produces zero
evidence and a LOW-band result -- not because URLs are treated as safe,
but because that analyzer has not been built yet. Do not read a LOW
result for a bare URL submission as a meaningful safety signal until the
URL analyzer (a later phase) exists.
"""

from __future__ import annotations

from uuid import uuid4

from fastapi import APIRouter, HTTPException

from app.models.check import (
    CheckRequest,
    CheckResponse,
    EvidenceOut,
    Explanation,
    RiskInfo,
)
from app.risk.engine import calculate_risk
from app.risk.rules import run_all_rules
from app.services.explanation import generate_explanation, generate_safe_actions

router = APIRouter()


def _extract_text(request: CheckRequest) -> str:
    """Pull the analyzable text out of the payload based on source_type.

    Raises HTTPException(400) if the required field for the given
    source_type is missing, per docs/api-contract.md field rules.
    """
    payload = request.payload

    if request.source_type == "TEXT":
        if not payload.text or not payload.text.strip():
            raise HTTPException(
                status_code=400,
                detail="payload.text is required and must be non-empty for source_type TEXT",
            )
        return payload.text

    if request.source_type == "URL":
        if not payload.url or not payload.url.strip():
            raise HTTPException(
                status_code=400,
                detail="payload.url is required for source_type URL",
            )
        # No URL analyzer exists yet (later phase). We still run the URL
        # string itself through the rule engine in case it contains
        # coincidental red-flag text, but this will not catch domain-level
        # threats (lookalikes, TLD risk, Safe Browsing/VirusTotal, etc.).
        return payload.url

    if request.source_type == "EMAIL":
        if not payload.body or not payload.body.strip():
            raise HTTPException(
                status_code=400,
                detail="payload.body is required and must be non-empty for source_type EMAIL",
            )
        # Combine subject and body so rules can match against either.
        return f"{payload.subject}\n{payload.body}"

    # Unreachable given CheckRequest's Literal typing, but kept explicit
    # rather than silently falling through.
    raise HTTPException(
        status_code=422,
        detail=f"Unsupported source_type: {request.source_type!r}",
    )


@router.post("/v1/check", response_model=CheckResponse)
async def check_content(request: CheckRequest) -> CheckResponse:
    text = _extract_text(request)

    evidence = run_all_rules(text)
    result = calculate_risk(evidence)

    summary, why, next_action, uncertainty = generate_explanation(result)
    safe_actions = generate_safe_actions(result)

    evidence_out = [
        EvidenceOut(
            signal=item.signal,
            category=item.category,
            points=item.points,
            reason=item.reason,
            source=item.source,
            confidence=_confidence_label(item.confidence),
            availability=item.availability,
            correlationGroup=item.correlation_group,
            severity=item.severity,
        )
        for item in result.all_evidence
    ]

    return CheckResponse(
        case_id=f"case_{uuid4().hex[:8]}",
        source_type=request.source_type,
        risk=RiskInfo(score=result.score, band=result.band),
        evidence=evidence_out,
        explanation=Explanation(
            summary=summary,
            why=why,
            next_action=next_action,
            uncertainty=uncertainty,
        ),
        safe_actions=safe_actions,
    )


def _confidence_label(confidence: float) -> str:
    """Convert the internal 0.0-1.0 confidence float to the API's string label.

    docs/api-contract.md's example response uses string labels
    ("high"/"medium"/"low") for evidence confidence, while the internal
    Evidence model uses a 0.0-1.0 float (docs/scoring-engine.md Section 4).
    This is the conversion boundary between the two.
    """
    if confidence >= 0.85:
        return "high"
    if confidence >= 0.5:
        return "medium"
    return "low"
