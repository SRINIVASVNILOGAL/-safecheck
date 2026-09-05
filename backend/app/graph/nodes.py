"""LangGraph node implementations for deterministic SafeCheck analysis."""
from __future__ import annotations

import asyncio
import logging

from fastapi import HTTPException

from app.analyzers.document_extraction import extract_text
from app.analyzers.document_rules import run_all_document_rules
from app.analyzers.url_parser import parse_url
from app.analyzers.url_rules import run_local_url_checks
from app.graph.state import EmailAttachment, GraphState
from app.integrations.google_safe_browsing import check_url_google_safe_browsing
from app.integrations.virustotal import check_url_virustotal
from app.risk.engine import calculate_risk
from app.risk.evidence import Evidence
from app.risk.rules import run_all_rules
from app.services.explanation import (
    generate_safe_actions,
    generate_user_facing_explanation,
)

logger = logging.getLogger(__name__)


def _extract_text_for_check(state: GraphState) -> str:
    payload = state["payload"]
    if state["source_type"] == "TEXT":
        if not payload.text or not payload.text.strip():
            raise HTTPException(400, "payload.text is required and must be non-empty for source_type TEXT")
        return payload.text
    if state["source_type"] == "EMAIL":
        if not payload.body or not payload.body.strip():
            raise HTTPException(400, "payload.body is required and must be non-empty for source_type EMAIL")
        return f"{payload.subject}\n{payload.body}"
    raise HTTPException(422, f"_extract_text_for_check does not support source_type: {state['source_type']!r}")


async def classify_input(state: GraphState) -> dict:
    if state["source_type"] == "URL":
        if not state["payload"].url or not state["payload"].url.strip():
            raise HTTPException(400, "payload.url is required for source_type URL")
        return {}
    if state["source_type"] == "DOCUMENT":
        return {}
    return {"analysis_text": _extract_text_for_check(state)}


async def _safe_provider_call(provider_name: str, coroutine) -> Evidence | None:
    try:
        return await coroutine
    except Exception as exc:  # noqa: BLE001
        logger.warning("Unexpected error calling %s: %s", provider_name, exc)
        return Evidence(category="url", signal=provider_name, points=0, reason=f"{provider_name} check failed unexpectedly and could not be completed.", source=provider_name.lower(), correlation_group="CORR_EXTERNAL_REPUTATION", availability="unavailable", confidence=0.0, severity="LOW")


async def _gather_url_evidence(url: str) -> list[Evidence]:
    parsed = parse_url(url)
    local = run_local_url_checks(parsed)
    google, virustotal = await asyncio.gather(
        _safe_provider_call("GOOGLE_SAFE_BROWSING", check_url_google_safe_browsing(url)),
        _safe_provider_call("VIRUSTOTAL", check_url_virustotal(url)),
    )
    return [*local, *([google] if google else []), *([virustotal] if virustotal else [])]


def _unavailable_attachment_evidence(attachment: EmailAttachment, reason: str) -> Evidence:
    return Evidence(category="rules", signal="ATTACHMENT_TEXT_EXTRACTION", points=0, reason=f"Attachment '{attachment.filename}' could not be analyzed: {reason}", source="document_analyzer", correlation_group="CORR_EXTRACTION", availability="unavailable", confidence=0.0, severity="LOW")


async def _gather_attachment_evidence(attachment: EmailAttachment) -> list[Evidence]:
    extraction = await asyncio.to_thread(extract_text, attachment.data, attachment.content_type)
    if not extraction.ok:
        return [_unavailable_attachment_evidence(attachment, extraction.reason)]
    evidence = [*run_all_document_rules(extraction.text), *run_all_rules(extraction.text)]
    if extraction.truncated:
        evidence.append(Evidence(category="rules", signal="ATTACHMENT_TEXT_TRUNCATED", points=0, reason=f"Attachment '{attachment.filename}' text exceeded the maximum length and was truncated before analysis.", source="document_analyzer", correlation_group="CORR_EXTRACTION", availability="available", confidence=1.0, severity="LOW"))
    return evidence


async def extract_evidence(state: GraphState) -> dict:
    source = state["source_type"]
    if source == "URL":
        return {"evidence": await _gather_url_evidence(state["payload"].url)}
    if source == "DOCUMENT":
        if not state.get("document_extraction_ok", False):
            return {"evidence": [Evidence(category="rules", signal="TEXT_EXTRACTION", points=0, reason=state.get("document_extraction_reason", "Text extraction failed."), source="document_analyzer", correlation_group="CORR_EXTRACTION", availability="unavailable", confidence=0.0, severity="LOW")]}
        evidence = [*run_all_document_rules(state["document_text"] or ""), *run_all_rules(state["document_text"] or "")]
        if state.get("document_truncated", False):
            evidence.append(Evidence(category="rules", signal="TEXT_TRUNCATED", points=0, reason="The extracted text exceeded the maximum length and was truncated before analysis.", source="document_analyzer", correlation_group="CORR_EXTRACTION", availability="available", confidence=1.0, severity="LOW"))
        return {"evidence": evidence}

    text_evidence = run_all_rules(state.get("analysis_text") or "")
    if source != "EMAIL":
        return {"evidence": text_evidence}
    # Email Agent fan-out: body rules, every bounded URL, and every
    # bounded supported attachment run concurrently; score_risk receives
    # their raw combined Evidence exactly once.
    url_tasks = [_gather_url_evidence(url) for url in state.get("email_urls", [])]
    attachment_tasks = [_gather_attachment_evidence(item) for item in state.get("email_attachments", [])]
    groups = await asyncio.gather(*url_tasks, *attachment_tasks)
    return {"evidence": [*text_evidence, *(item for group in groups for item in group)]}


async def score_risk(state: GraphState) -> dict:
    return {"risk_result": calculate_risk(state.get("evidence", []))}


async def build_explanation(state: GraphState) -> dict:
    summary, why, next_action, uncertainty = await generate_user_facing_explanation(
        state["risk_result"]
    )
    return {
        "summary": summary,
        "why": why,
        "next_action": next_action,
        "uncertainty": uncertainty,
        "safe_actions": generate_safe_actions(state["risk_result"]),
    }
