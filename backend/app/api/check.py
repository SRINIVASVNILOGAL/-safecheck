"""POST /v1/check -- the main analysis endpoint.

Real, non-mock pipeline:

TEXT / EMAIL:
    request -> extract text -> run_all_rules() [app.risk.rules]
            -> calculate_risk() -> CheckResponse

URL (as of Phase 4 Step 6):
    request -> parse_url() [app.analyzers.url_parser]
            -> run_local_url_checks()               [local heuristics]
            -> check_url_google_safe_browsing()  \\
            -> check_url_virustotal()              } concurrently
            -> calculate_risk() -> CheckResponse

All three branches converge on the same calculate_risk() -> explanation
-> CheckResponse tail, per the "one risk engine" architecture rule.
"""

from __future__ import annotations

import asyncio
import logging
from uuid import uuid4

from fastapi import APIRouter, HTTPException

from app.analyzers.url_parser import parse_url
from app.analyzers.url_rules import run_local_url_checks
from app.integrations.google_safe_browsing import check_url_google_safe_browsing
from app.integrations.virustotal import check_url_virustotal
from app.models.check import (
    CheckRequest,
    CheckResponse,
    EvidenceOut,
    Explanation,
    RiskInfo,
)
from app.risk.engine import calculate_risk
from app.risk.evidence import Evidence
from app.risk.rules import run_all_rules
from app.services.explanation import generate_explanation, generate_safe_actions

router = APIRouter()
logger = logging.getLogger(__name__)


async def _safe_provider_call(
    provider_name: str, coroutine
) -> Evidence | None:
    """Run an external provider adapter, converting any unexpected
    exception into unavailable evidence rather than letting it crash the
    request.

    The adapters themselves (google_safe_browsing.py, virustotal.py)
    already handle their own known failure modes (timeouts, non-200,
    malformed JSON) internally and return unavailable evidence for those.
    This wrapper is a defense-in-depth safety net for *unknown* failures
    -- a bug in an adapter, an unexpected exception type, etc. -- so a
    single provider's misbehavior can never turn into a 500 error for the
    whole /v1/check request.
    """
    try:
        return await coroutine
    except Exception as exc:  # noqa: BLE001 - intentionally broad, see docstring
        logger.warning("Unexpected error calling %s: %s", provider_name, exc)
        return Evidence(
            category="url",
            signal=provider_name,
            points=0,
            reason=f"{provider_name} check failed unexpectedly and could not be completed.",
            source=provider_name.lower(),
            correlation_group="CORR_EXTERNAL_REPUTATION",
            availability="unavailable",
            confidence=0.0,
            severity="LOW",
        )


async def _analyze_url(url: str) -> list[Evidence]:
    """Run local URL heuristics and both external providers concurrently."""
    parsed = parse_url(url)
    local_evidence = run_local_url_checks(parsed)

    google_result, virustotal_result = await asyncio.gather(
        _safe_provider_call(
            "GOOGLE_SAFE_BROWSING", check_url_google_safe_browsing(url)
        ),
        _safe_provider_call("VIRUSTOTAL", check_url_virustotal(url)),
    )

    evidence = list(local_evidence)
    if google_result is not None:
        evidence.append(google_result)
    if virustotal_result is not None:
        evidence.append(virustotal_result)

    return evidence


def _extract_text(request: CheckRequest) -> str:
    """Pull the analyzable text out of the payload for TEXT/EMAIL requests.

    Raises HTTPException(400) if the required field for the given
    source_type is missing, per docs/api-contract.md field rules.

    URL requests do not go through this function -- see _analyze_url().
    """
    payload = request.payload

    if request.source_type == "TEXT":
        if not payload.text or not payload.text.strip():
            raise HTTPException(
                status_code=400,
                detail="payload.text is required and must be non-empty for source_type TEXT",
            )
        return payload.text

    if request.source_type == "EMAIL":
        if not payload.body or not payload.body.strip():
            raise HTTPException(
                status_code=400,
                detail="payload.body is required and must be non-empty for source_type EMAIL",
            )
        # Combine subject and body so rules can match against either.
        return f"{payload.subject}\n{payload.body}"

    raise HTTPException(
        status_code=422,
        detail=f"_extract_text does not support source_type: {request.source_type!r}",
    )


@router.post("/v1/check", response_model=CheckResponse)
async def check_content(request: CheckRequest) -> CheckResponse:
    if request.source_type == "URL":
        payload = request.payload
        if not payload.url or not payload.url.strip():
            raise HTTPException(
                status_code=400,
                detail="payload.url is required for source_type URL",
            )
        evidence = await _analyze_url(payload.url)
    else:
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
