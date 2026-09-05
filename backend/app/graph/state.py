"""Shared state type threaded through the analysis graph.

LangGraph nodes receive the full state dict and return a partial dict of
updates to merge in. This TypedDict is the contract between nodes -- every
node reads from it and/or writes to it via these exact keys.
"""

from __future__ import annotations

import operator
from dataclasses import dataclass
from typing import Annotated, Literal, TypedDict

from app.models.check import CheckPayload
from app.risk.evidence import Evidence
from app.risk.engine import RiskResult

GraphSourceType = Literal["TEXT", "URL", "EMAIL", "DOCUMENT"]


@dataclass(frozen=True)
class EmailAttachment:
    """A supported Gmail attachment already downloaded under the Email
    Agent's strict resource limits. Its bytes are graph input only and are
    never returned by the email API response.
    """

    filename: str
    content_type: str
    data: bytes


class GraphState(TypedDict, total=False):
    """Pipeline state. `total=False` since nodes populate fields
    progressively as the graph runs -- not every field is present at every
    step.
    """

    # ---- Inputs (set before graph.ainvoke) ----
    source_type: GraphSourceType
    payload: CheckPayload | None

    # Gmail-only fan-out inputs. The Email Agent extracts/limits these
    # before the graph is invoked, then extract_evidence merges their
    # evidence with email-text evidence before the single score_risk node.
    email_urls: list[str]
    email_attachments: list[EmailAttachment]

    # Only used for the DOCUMENT branch: pre-extracted text and whether
    # extraction itself succeeded.
    document_text: str | None
    document_extraction_ok: bool
    document_extraction_reason: str | None
    document_truncated: bool

    # ---- Intermediate (set by classify_input) ----
    analysis_text: str | None

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
