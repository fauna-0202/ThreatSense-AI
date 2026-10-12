"""Unit tests for explainability formatting and SHAP narrative generator."""

from threatsense.explainability.formatter import ExplanationFormatter


def test_narrative_generation_benign():
    narrative = ExplanationFormatter.generate_narrative(
        predicted_class="BENIGN",
        confidence=0.99,
        top_features=[{"feature": "duration", "actual_value": 1.2, "direction": "supports_prediction"}],
        uncertainty_state="CONFIDENT",
        is_anomaly=False,
    )
    assert "normal/benign" in narrative.lower()
    assert "99.0%" in narrative
    assert "Security disclaimer" in narrative


def test_narrative_generation_attack_with_disclaimer():
    narrative = ExplanationFormatter.generate_narrative(
        predicted_class="DoS/DDoS",
        confidence=0.92,
        top_features=[
            {"feature": "orig_pkts", "actual_value": 12000, "direction": "supports_prediction"},
            {"feature": "orig_to_resp_byte_ratio", "actual_value": 100.0, "direction": "supports_prediction"},
        ],
        uncertainty_state="OUT_OF_DISTRIBUTION",
        is_anomaly=True,
    )
    assert "DoS/DDoS" in narrative
    assert "Security disclaimer" in narrative
    assert "OUT_OF_DISTRIBUTION" in narrative
