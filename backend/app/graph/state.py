"""Shared state type threaded through the analysis graph.

LangGraph nodes receive the full state dict and return a partial dict of
updates to merge in. This TypedDict is the contract between nodes -- every
node reads from it and/or writes to it via these exact keys.

Design note: `evidence` is declared with `operator.add` as its reducer so
that if extract_evidence ever fans out into multiple parallel branches
(e.g. Phase 8 adding an LLM-evidence node alongside the existing
rule/URL/document extraction), LangGraph will concatenate each branch's
evidence list automatically instead of the last writer overwriting the
others. Today extract_evidence is a single node that already gathers
everything concurrently internally (mirroring the original
asyncio.gather in app.api.check._analyze_url), so this only matters once
Phase 8 splits it into multiple graph nodes.
"""

from __future__ import annotations

import operator
from typing import Annotated, Literal, TypedDict

from app.models.check import CheckPayload, SourceType
from app.risk.evidence import Evidence
from app.risk.engine import RiskResult

# The graph supports one more source_type than the /v1/check request body
# does: "DOCUMENT", used only when invoked from POST /v1/document, where
# extraction has already happened before the graph runs (see
# app.graph.pipeline.run_document_pipeline).
GraphSourceType = Literal["TEXT", "URL", "EMAIL", "DOCUMENT"]


class GraphState(TypedDict, total=False):
    """Pipeline state. `total=False` since nodes populate fields
    progressively as the graph runs -- not every field is present at
    every step.
    """

    # ---- Inputs (set before graph.ainvoke) ----
    source_type: GraphSourceType
    payload: CheckPayload | None
    # Only used for the DOCUMENT branch: pre-extracted text and whether
    # extraction itself succeeded. POST /v1/document performs file
    # extraction (pypdf/pytesseract) before invoking the graph, since
    # that is an I/O-bound file-parsing step, not an evidence-gathering
    # step -- the graph's job starts once there is text (or a known
    # extraction failure) to analyze.
    document_text: str | None
    document_extraction_ok: bool
    document_extraction_reason: str | None
    document_truncated: bool

    # ---- Intermediate (set by classify_input) ----
    analysis_text: str | None  # resolved TEXT/EMAIL text to run rules on

    # ---- Output of extract_evidence ----
    evidence: Annotated[list[Evidence], operator.add]

    # ---- Output of score_risk ----
    risk_result: RiskResult

    # ---- Output of build_explanation ----
    summary: str
    why: list[str]
    next_action: str
    uncertainty: list[str]
    safe_actions: list[str]
