"""Graph assembly and public entry points.

Builds the LangGraph state graph:

    classify_input -> extract_evidence -> score_risk -> build_explanation -> END

All source_types (TEXT/URL/EMAIL/DOCUMENT) currently flow through the
same linear sequence of nodes -- routing on source_type happens *inside*
classify_input and extract_evidence, not via LangGraph conditional edges,
because today every branch's output converges on the same next step
(there's nothing to conditionally skip). This is intentionally the
simplest graph that is still a real graph; Phase 8 is expected to
introduce the first actual conditional edge (e.g. skip the LLM node when
rule-based evidence is already conclusive).

Two public entry points mirror the two existing HTTP endpoints:
- run_check_pipeline(): for POST /v1/check (TEXT/URL/EMAIL)
- run_document_pipeline(): for POST /v1/document (pre-extracted text in)

Both return a RiskResult plus explanation fields, packaged as
PipelineResult -- the shape app.api.check.build_check_response already
expects, unchanged.
"""

from __future__ import annotations

from dataclasses import dataclass

from langgraph.graph import END, StateGraph

from app.graph.nodes import build_explanation, classify_input, extract_evidence, score_risk
from app.graph.state import GraphState
from app.models.check import CheckPayload
from app.risk.engine import RiskResult

_graph_builder = StateGraph(GraphState)
_graph_builder.add_node("classify_input", classify_input)
_graph_builder.add_node("extract_evidence", extract_evidence)
_graph_builder.add_node("score_risk", score_risk)
_graph_builder.add_node("build_explanation", build_explanation)

_graph_builder.set_entry_point("classify_input")
_graph_builder.add_edge("classify_input", "extract_evidence")
_graph_builder.add_edge("extract_evidence", "score_risk")
_graph_builder.add_edge("score_risk", "build_explanation")
_graph_builder.add_edge("build_explanation", END)

# Compiled once at import time. Compiling is relatively expensive and the
# graph structure never changes at runtime, so this is a module-level
# singleton reused across requests -- mirrors how a FastAPI router or a
# SQLAlchemy engine is typically constructed once, not per-request.
compiled_graph = _graph_builder.compile()


@dataclass(frozen=True)
class PipelineResult:
    """Everything app.api.check.build_check_response needs, produced by
    the graph. Deliberately mirrors the return shape build_check_response
    used to assemble by hand from calculate_risk() + generate_explanation()
    + generate_safe_actions().
    """

    risk_result: RiskResult
    summary: str
    why: list[str]
    next_action: str
    uncertainty: list[str]
    safe_actions: list[str]


def _to_pipeline_result(final_state: dict) -> PipelineResult:
    return PipelineResult(
        risk_result=final_state["risk_result"],
        summary=final_state["summary"],
        why=final_state["why"],
        next_action=final_state["next_action"],
        uncertainty=final_state["uncertainty"],
        safe_actions=final_state["safe_actions"],
    )


async def run_check_pipeline(
    source_type: str, payload: CheckPayload
) -> PipelineResult:
    """Entry point for POST /v1/check (TEXT/URL/EMAIL).

    HTTPException raised by classify_input/extract_evidence (missing
    required fields) propagates up through graph.ainvoke unchanged --
    LangGraph does not catch or wrap node exceptions, so FastAPI's
    exception handling still applies exactly as it did when this logic
    lived directly in the route handler.
    """
    initial_state: GraphState = {
        "source_type": source_type,  # type: ignore[typeddict-item]
        "payload": payload,
    }
    final_state = await compiled_graph.ainvoke(initial_state)
    return _to_pipeline_result(final_state)


async def run_document_pipeline(
    *,
    extraction_ok: bool,
    text: str | None,
    extraction_reason: str | None,
    truncated: bool,
) -> PipelineResult:
    """Entry point for POST /v1/document.

    Takes already-extracted text (extraction is file I/O, not part of
    this graph) and runs it through the same
    extract_evidence -> score_risk -> build_explanation sequence.
    classify_input is a no-op for the DOCUMENT branch but still runs, so
    the graph shape stays identical across all source_types.
    """
    initial_state: GraphState = {
        "source_type": "DOCUMENT",
        "payload": None,
        "document_extraction_ok": extraction_ok,
        "document_text": text,
        "document_extraction_reason": extraction_reason,
        "document_truncated": truncated,
    }
    final_state = await compiled_graph.ainvoke(initial_state)
    return _to_pipeline_result(final_state)
