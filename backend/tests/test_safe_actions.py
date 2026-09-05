"""Tests for context-aware safety precautions (app.services.explanation.generate_safe_actions).

Regression coverage for the user's explicit requirement: "if the message
asks for an OTP, it should say 'Never share your OTP.' The precautions
should be based on the actual content and type of risk detected" -- not a
fixed list keyed only on the risk band.
"""

from __future__ import annotations

from app.risk.engine import calculate_risk
from app.risk.evidence import Evidence
from app.services.explanation import generate_safe_actions


def _available(signal: str, points: int, category: str = "rules") -> Evidence:
    return Evidence(category=category, signal=signal, points=points, reason=f"Reason for {signal}.", source="test")


class TestSignalSpecificPrecautions:
    def test_otp_request_produces_never_share_otp_advice(self) -> None:
        # OTP_REQUEST(20) + PIN_REQUEST(20) = 40 -> MEDIUM band.
        result = calculate_risk([_available("OTP_REQUEST", 20), _available("PIN_REQUEST", 20)])
        actions = generate_safe_actions(result)
        assert any("Never share your OTP" in action for action in actions)

    def test_remote_access_tool_produces_specific_advice(self) -> None:
        result = calculate_risk([_available("REMOTE_ACCESS_TOOL", 20), _available("URGENT_PAYMENT", 15)])
        actions = generate_safe_actions(result)
        assert any("AnyDesk" in action or "TeamViewer" in action for action in actions)
        assert any("time pressure" in action.lower() for action in actions)

    def test_shortened_link_produces_specific_advice(self) -> None:
        result = calculate_risk([_available("SHORTENED_LINK", 15, category="url"), _available("FEE_OR_FINE_SCAM", 15), _available("URGENT_PAYMENT", 15)])
        actions = generate_safe_actions(result)
        assert any("shortened link" in action.lower() for action in actions)
        assert any("toll" in action.lower() or "fee" in action.lower() for action in actions)

    def test_multiple_signals_deduplicate_and_preserve_fixed_order(self) -> None:
        result = calculate_risk([_available("OTP_REQUEST", 20), _available("PIN_REQUEST", 20)])
        actions = generate_safe_actions(result)
        otp_index = next(i for i, a in enumerate(actions) if "OTP" in a)
        pin_index = next(i for i, a in enumerate(actions) if "PIN" in a)
        assert otp_index < pin_index  # fixed display order, not evidence-arrival order

    def test_high_medium_always_includes_generic_verify_advice_alongside_specific(self) -> None:
        result = calculate_risk([_available("OTP_REQUEST", 20), _available("PIN_REQUEST", 20)])
        actions = generate_safe_actions(result)
        assert any("official website or helpline" in action for action in actions)

    def test_no_matching_signal_falls_back_to_generic_high_medium_advice(self) -> None:
        # LOTTERY_OR_PRIZE has no dedicated precaution text in this test's
        # scope check -- but it does have one; use a made-up unmapped
        # signal via direct evidence construction to force the fallback.
        result = calculate_risk([_available("SOME_UNMAPPED_SIGNAL", 50)])
        actions = generate_safe_actions(result)
        assert actions  # non-empty fallback list
        assert any("codes, passwords, or OTPs" in action for action in actions)

    def test_uncertain_band_with_no_signal_match_uses_generic_uncertain_advice(self) -> None:
        result = calculate_risk([_available("SOME_UNMAPPED_SIGNAL", 30)])
        assert result.band == "UNCERTAIN"
        actions = generate_safe_actions(result)
        assert actions == ["Verify the sender or organization independently before acting."]

    def test_low_band_has_no_actions(self) -> None:
        result = calculate_risk([])
        assert generate_safe_actions(result) == []

    def test_unavailable_evidence_never_triggers_a_precaution(self) -> None:
        unavailable = Evidence(
            category="url", signal="GOOGLE_SAFE_BROWSING", points=0,
            reason="unavailable", source="test", availability="unavailable",
        )
        result = calculate_risk([unavailable])
        actions = generate_safe_actions(result)
        assert actions == []
