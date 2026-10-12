"""Unit tests for operational risk scoring and priority banding."""

from threatsense.alerting.risk import RiskScoringEngine


def test_benign_traffic_yields_low_risk():
    engine = RiskScoringEngine()
    eval_res = engine.calculate_risk(
        predicted_class="BENIGN",
        confidence=0.98,
        is_anomaly=0,
        normalized_anomaly=0.05,
        dst_port=80,
        uncertainty_state="CONFIDENT",
    )
    assert eval_res.priority == "LOW"
    assert eval_res.risk_score < 25.0


def test_dos_attack_yields_high_or_critical_risk():
    engine = RiskScoringEngine()
    eval_res = engine.calculate_risk(
        predicted_class="DoS/DDoS",
        confidence=0.95,
        is_anomaly=1,
        normalized_anomaly=0.85,
        dst_port=80,
        uncertainty_state="CONFIDENT",
    )
    assert eval_res.priority in ("HIGH", "CRITICAL")
    assert eval_res.risk_score >= 50.0


def test_sensitive_port_increases_risk():
    engine = RiskScoringEngine()
    res_std = engine.calculate_risk(
        predicted_class="BruteForce",
        confidence=0.90,
        is_anomaly=1,
        normalized_anomaly=0.70,
        dst_port=80,
        uncertainty_state="CONFIDENT",
    )
    res_ssh = engine.calculate_risk(
        predicted_class="BruteForce",
        confidence=0.90,
        is_anomaly=1,
        normalized_anomaly=0.70,
        dst_port=22,  # SSH sensitive port
        uncertainty_state="CONFIDENT",
    )
    assert res_ssh.risk_score > res_std.risk_score


def test_uncertainty_penalty_adjustment():
    engine = RiskScoringEngine()
    res_confident = engine.calculate_risk(
        predicted_class="Botnet",
        confidence=0.70,
        is_anomaly=1,
        normalized_anomaly=0.50,
        dst_port=6667,
        uncertainty_state="CONFIDENT",
    )
    res_uncertain = engine.calculate_risk(
        predicted_class="Botnet",
        confidence=0.70,
        is_anomaly=1,
        normalized_anomaly=0.50,
        dst_port=6667,
        uncertainty_state="HIGH_UNCERTAINTY",
    )
    assert res_uncertain.risk_score > res_confident.risk_score
