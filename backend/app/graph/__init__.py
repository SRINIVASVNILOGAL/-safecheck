"""LangGraph orchestration layer for the SafeCheck analysis pipeline.

This package expresses the same pipeline that previously lived as ad-hoc
glue code in app.api.check and app.api.document as an explicit graph:

    classify_input -> extract_evidence -> score_risk -> build_explanation

Behavior is unchanged from the pre-Phase-7 pipeline -- this is a
restructuring, not a feature change. The deterministic risk engine
(app.risk.engine.calculate_risk) remains the single component allowed to
produce a score/band, per the "one risk engine, not agents" architecture
rule. Nothing in this package calls an LLM; that is Phase 8 work, which
will slot in as an additional node in extract_evidence's ML-category
branch without touching score_risk or build_explanation.
"""
