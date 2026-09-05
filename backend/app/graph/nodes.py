"""Graph node implementations.

Each node is an async function taking the current GraphState and
returning a partial dict of updates, per LangGraph's node contract. Logic
here is moved from app.api.check / app.api.document unchanged -- no
behavior change, just relocated so it can be assembled into an explicit
graph in app.graph.pipeline.
"""

from __future__ import annotations

import asyncio
import logging

from fastapi import HTTPException

from app.analyzers.document_rules import run_all_document_rules
from app.analyzers.url_parser import parse_url
from app.analyzers.url_rules import run_local_url_checks
from app.graph.state import GraphState
from app.integrations.google_safe_browsing import check_url_google_safe_browsing
from app.integrations.virustotal import check_url_virustotal
from app.risk.engine import calculate_risk
from app.risk.evidence import Evidence
from app.risk.rules import run_all_rules
from app.services.explanation import generate_explanation, generate_safe_actions

logger = logging.getLogger(__name__)


def _extract_text_for_check(state: GraphState) -> str:
    """Pull analyzable text out of the payload for TEXT/EMAIL requests.

    Moved verbatim from app.api.check._extract_text. Raises
    HTTPException(400) if the required field for the given source_type is
    missing, per docs/api-contract.md field rules.
    """
    payload = state["payload"]
    source_type = state["source_type"]

    if source_type == "TEXT":
        if not payload.text or not payload.text.strip():
            raise HTTPException(
                status_code=400,
                detail="payload.text is required and must be non-empty for source_type TEXT",
            )
        return payload.text

    if source_type == "EMAIL":
        if not payload.body or not payload.body.strip():
            raise HTTPException(
                status_code=400,
                detail="payload.body is required and must be non-empty for source_type EMAIL",
            )
        return f"{payload.subject}\n{payload.body}"

    raise HTTPException(
        status_code=422,
        detail=f"_extract_text_for_check does not support source_type: {source_type!r}",
    )


async def classify_input(state: GraphState) -> dict:
    """Route on source_type: resolve which text (if any) downstream nodes
    should analyze.

    URL and DOCUMENT branches don't need resolved text here -- URL goes
    straight to parsing/provider calls in extract_evidence, and DOCUMENT
    already has its text extracted before the graph runs (see
    app.graph.pipeline.run_document_pipeline). Only TEXT/EMAIL need this
    step.
    """
    source_type = state["source_type"]

    if source_type == "URL":
        payload = state["payload"]
        if not payload.url or not payload.url.strip():
            raise HTTPException(
                status_code=400,
                detail="payload.url is required for source_type URL",
            )
        return {}

    if source_type == "DOCUMENT":
        return {}

    text = _extract_text_for_check(state)
    return {"analysis_text": text}


async def _safe_provider_call(provider_name: str, coroutine) -> Evidence | None:
    """Run an external provider adapter, converting any unexpected
    exception into unavailable evidence rather than letting it crash the
    request. Moved verbatim from app.api.check._safe_provider_call.
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


async def _gather_url_evidence(url: str) -> list[Evidence]:
    """Run local URL heuristics and both external providers concurrently.

    Moved verbatim from app.api.check._analyze_url.
    """
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


async def extract_evidence(state: GraphState) -> dict:
    """Gather Evidence for the current source_type.

    - TEXT/EMAIL: run_all_rules() against the resolved analysis_text.
    - URL: local heuristics + Google Safe Browsing + VirusTotal, concurrently.
    - DOCUMENT: document-specific rules + message rules against the
      pre-extracted text, or a single TEXT_EXTRACTION unavailable evidence
      item if extraction failed. Also appends a TEXT_TRUNCATED marker if
      the extracted text was truncated.

    This node is the single fan-in point for evidence today. Phase 8's
    LLM-derived evidence will be added here as an additional concurrent
    call (URL/TEXT branches) without changing score_risk or
    build_explanation.
    """
    source_type = state["source_type"]

    if source_type == "URL":
        evidence = await _gather_url_evidence(state["payload"].url)
        return {"evidence": evidence}

    if source_type == "DOCUMENT":
        if not state.get("document_extraction_ok", False):
            evidence = [
                Evidence(
                    category="rules",
                    signal="TEXT_EXTRACTION",
                    points=0,
                    reason=state.get(
                        "document_extraction_reason",
                        "Text extraction failed.",
                    ),
                    source="document_analyzer",
                    correlation_group="CORR_EXTRACTION",
                    availability="unavailable",
                    confidence=0.0,
                    severity="LOW",
                )
            ]
            return {"evidence": evidence}

        text = state["document_text"] or ""
        evidence = [
            *run_all_document_rules(text),
            *run_all_rules(text),
        ]
        if state.get("document_truncated", False):
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
        return {"evidence": evidence}

    # TEXT / EMAIL
    text = state.get("analysis_text") or ""
    evidence = run_all_rules(text)
    return {"evidence": evidence}


async def score_risk(state: GraphState) -> dict:
    """Run the deterministic risk engine over gathered evidence.

    This is the ONLY node allowed to produce a score/band -- it calls
    app.risk.engine.calculate_risk unchanged, per the "one risk engine"
    architecture rule. No LLM or provider call happens here or after.
    """
    result = calculate_risk(state.get("evidence", []))
    return {"risk_result": result}


async def build_explanation(state: GraphState) -> dict:
    """Generate the human-facing explanation and safe-actions list from
    the risk result. Moved verbatim from app.api.check.build_check_response.
    """
    result = state["risk_result"]
    summary, why, next_action, uncertainty = generate_explanation(result)
    safe_actions = generate_safe_actions(result)
    return {
        "summary": summary,
        "why": why,
        "next_action": next_action,
        "uncertainty": uncertainty,
        "safe_actions": safe_actions,
    }
