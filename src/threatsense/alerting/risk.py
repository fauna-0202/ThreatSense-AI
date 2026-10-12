"""Configurable 0-100 Risk Scoring Engine."""

from typing import Dict, Any, List
from pydantic import BaseModel
from threatsense.alerting.rules import ATTACK_BASE_SEVERITIES, get_port_risk
from threatsense.config import settings


class RiskEvaluation(BaseModel):
    risk_score: float  # 0.0 to 100.0
    priority: str  # LOW, MODERATE, HIGH, CRITICAL
    contributing_signals: Dict[str, Any]


class RiskScoringEngine:
    """Calculates operational risk score (0-100) combining model signals and threat context."""

    def __init__(self):
        self.bands = settings.risk_scoring.bands
        self.w_clf = settings.risk_scoring.classifier_weight
        self.w_ano = settings.risk_scoring.anomaly_weight
        self.w_port = settings.risk_scoring.protocol_weight
        self.uncertainty_factor = settings.risk_scoring.uncertainty_penalty_factor

    def calculate_risk(
        self,
        predicted_class: str,
        confidence: float,
        is_anomaly: int,
        normalized_anomaly: float,
        dst_port: int,
        uncertainty_state: str,
    ) -> RiskEvaluation:
        # 1. Base attack severity (0-100)
        base_severity = ATTACK_BASE_SEVERITIES.get(predicted_class, 20.0)

        # 2. Classifier contribution (0-100)
        # For Benign: low score, but scaled by (1 - confidence) if uncertain
        if predicted_class == "BENIGN":
            clf_risk = max(5.0, (1.0 - confidence) * 30.0)
        else:
            clf_risk = base_severity * confidence

        # 3. Anomaly contribution (0-100)
        ano_risk = normalized_anomaly * 80.0

        # 4. Port and target service risk (0-100)
        port_info = get_port_risk(dst_port)
        port_risk = port_info["risk_weight"] * 100.0

        # 5. Composite weighted score
        composite = (
            self.w_clf * clf_risk
            + self.w_ano * ano_risk
            + self.w_port * port_risk
        )

        # 6. Uncertainty state modifier
        # If model is uncertain or OOD, adjust risk upwards for defense-in-depth review
        uncertainty_adjustment = 0.0
        if uncertainty_state in ("HIGH_UNCERTAINTY", "OUT_OF_DISTRIBUTION", "DETECTOR_DISAGREEMENT"):
            uncertainty_adjustment = 15.0 * self.uncertainty_factor
            composite += uncertainty_adjustment

        # Clamp score between 0.0 and 100.0
        final_score = round(max(0.0, min(100.0, composite)), 1)

        # Map to priority band
        if final_score < 25.0:
            priority = "LOW"
        elif final_score < 50.0:
            priority = "MODERATE"
        elif final_score < 75.0:
            priority = "HIGH"
        else:
            priority = "CRITICAL"

        contributing_signals = {
            "predicted_class": predicted_class,
            "classifier_risk_component": round(clf_risk, 2),
            "anomaly_risk_component": round(ano_risk, 2),
            "port_risk_component": round(port_risk, 2),
            "target_service": port_info["service"],
            "uncertainty_adjustment": round(uncertainty_adjustment, 2),
            "weights_used": {
                "classifier": self.w_clf,
                "anomaly": self.w_ano,
                "port": self.w_port,
            },
        }

        return RiskEvaluation(
            risk_score=final_score,
            priority=priority,
            contributing_signals=contributing_signals,
        )
