"""Unit tests for uncertainty evaluation, OOD detection, and detector disagreement."""

from threatsense.alerting.uncertainty import UncertaintyEngine


def test_confident_prediction():
    engine = UncertaintyEngine()
    res = engine.evaluate(
        predicted_class="BENIGN",
        confidence=0.95,
        entropy=0.10,
        normalized_entropy=0.08,
        is_anomaly=0,
        normalized_anomaly=0.05,
    )
    assert res.state == "CONFIDENT"
    assert res.review_required is False
    assert res.disagreement_detected is False


def test_detector_disagreement_benign_but_anomalous():
    engine = UncertaintyEngine()
    res = engine.evaluate(
        predicted_class="BENIGN",
        confidence=0.90,
        entropy=0.15,
        normalized_entropy=0.10,
        is_anomaly=1,  # Isolation Forest flagged anomaly
        normalized_anomaly=0.75,
    )
    assert res.disagreement_detected is True
    assert res.state == "DETECTOR_DISAGREEMENT"
    assert res.review_required is True


def test_out_of_distribution_unfamiliarity():
    engine = UncertaintyEngine()
    res = engine.evaluate(
        predicted_class="PortScan",
        confidence=0.85,
        entropy=0.20,
        normalized_entropy=0.15,
        is_anomaly=1,
        normalized_anomaly=0.92,  # Very high unfamiliarity
    )
    assert res.state == "OUT_OF_DISTRIBUTION"
    assert res.review_required is True


def test_high_entropy_uncertainty():
    engine = UncertaintyEngine()
    res = engine.evaluate(
        predicted_class="DoS/DDoS",
        confidence=0.45,  # Low confidence
        entropy=1.50,
        normalized_entropy=0.85,  # High entropy
        is_anomaly=1,
        normalized_anomaly=0.30,
    )
    assert res.state == "HIGH_UNCERTAINTY"
    assert res.review_required is True
