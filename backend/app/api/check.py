"""POST /v1/check -- the main analysis endpoint.

As of Phase 7, the actual analysis pipeline (classify input -> gather
evidence -> score -> explain) is expressed as a LangGraph state graph in
app.graph.pipeline, invoked here via run_check_pipeline(). This module
now only handles the HTTP-shape concerns: request validation passthrough
and converting the graph's PipelineResult into the CheckResponse shape
defined by docs/api-contract.md.

TEXT / EMAIL / URL all flow through the same graph (see
app.graph.pipeline for the node sequence and per-source_type branching).
build_check_response is also reused by app.api.document, since both
endpoints converge on the same "one risk engine" architecture rule.
"""

from __future__ import annotations

from uuid import uuid4

from fastapi import APIRouter

from app.graph.pipeline import PipelineResult, run_check_pipeline
from app.models.check import (
    CheckRequest,
    CheckResponse,
    EvidenceOut,
    Explanation,
    RiskInfo,
)
from app.risk.engine import RiskResult

router = APIRouter()


def confidence_label(confidence: float) -> str:
    """Convert the internal 0.0-1.0 confidence float to the API's string label.

    docs/api-contract.md's example response uses string labels
    ("high"/"medium"/"low") for evidence confidence, while the internal
    Evidence model uses a 0.0-1.0 float (docs/scoring-engine.md Section 4).
    This is the conversion boundary between the two. Shared with
    app.api.document, which also converts Evidence to EvidenceOut.
    """
    if confidence >= 0.85:
        return "high"
    if confidence >= 0.5:
        return "medium"
    return "low"


def build_check_response_from_result(
    case_id: str, source_type, pipeline_result: PipelineResult
) -> CheckResponse:
    """Convert a graph PipelineResult into the API's CheckResponse shape.

    Used by both POST /v1/check (this module) and POST /v1/document
    (app.api.document), since both invoke the same graph
    (app.graph.pipeline) and only differ in how they populate the initial
    GraphState.
    """
    result: RiskResult = pipeline_result.risk_result

    evidence_out = [
        EvidenceOut(
            signal=item.signal,
            category=item.category,
            points=item.points,
            reason=item.reason,
            source=item.source,
            confidence=confidence_label(item.confidence),
            availability=item.availability,
            correlationGroup=item.correlation_group,
            severity=item.severity,
        )
        for item in result.all_evidence
    ]

    return CheckResponse(
        case_id=case_id,
        source_type=source_type,
        risk=RiskInfo(score=result.score, band=result.band),
        evidence=evidence_out,
        explanation=Explanation(
            summary=pipeline_result.summary,
            why=pipeline_result.why,
            next_action=pipeline_result.next_action,
            uncertainty=pipeline_result.uncertainty,
        ),
        safe_actions=pipeline_result.safe_actions,
    )


@router.post("/v1/check", response_model=CheckResponse)
async def check_content(request: CheckRequest) -> CheckResponse:
    pipeline_result = await run_check_pipeline(request.source_type, request.payload)

    return build_check_response_from_result(
        case_id=f"case_{uuid4().hex[:8]}",
        source_type=request.source_type,
        pipeline_result=pipeline_result,
    )
