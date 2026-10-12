"""Uncertainty, entropy, and out-of-distribution (OOD) evaluation engine."""

from typing import Dict, Any, List
from pydantic import BaseModel
from threatsense.config import settings


class UncertaintyEvaluation(BaseModel):
    state: str  # CONFIDENT, HIGH_UNCERTAINTY, OUT_OF_DISTRIBUTION, DETECTOR_DISAGREEMENT, REVIEW_REQUIRED
    review_required: bool
    confidence: float
    entropy: float
    normalized_entropy: float
    ood_score: float  # Estimate of unfamiliarity
    disagreement_detected: bool
    reasons: List[str]


class UncertaintyEngine:
    """Evaluates prediction confidence, entropy, OOD unfamiliarity, and detector disagreement."""

    def __init__(self, min_confidence: float = 0.60, entropy_threshold: float = 0.65):
        self.min_confidence = min_confidence
        self.entropy_threshold = entropy_threshold

    def evaluate(
        self,
        predicted_class: str,
        confidence: float,
        entropy: float,
        normalized_entropy: float,
        is_anomaly: int,
        normalized_anomaly: float,
        schema_status: str = "VALID",
    ) -> UncertaintyEvaluation:
        reasons = []
        state = "CONFIDENT"
        review_required = False
        disagreement = False

        # 1. Check for Detector Disagreement
        # (Supervised says Benign, but Unsupervised flags significant anomaly, or vice-versa)
        if predicted_class == "BENIGN" and is_anomaly == 1 and normalized_anomaly > 0.60:
            disagreement = True
            reasons.append(
                f"Detector disagreement: Supervised model predicted BENIGN, but Isolation Forest flagged anomalous flow (anomaly factor: {normalized_anomaly:.2f})."
            )
        elif predicted_class != "BENIGN" and is_anomaly == 0 and confidence < 0.80:
            disagreement = True
            reasons.append(
                f"Detector disagreement: Supervised model predicted '{predicted_class}', but Isolation Forest observed standard benign distribution."
            )

        # 2. Check Out-of-Distribution / High Unfamiliarity
        if normalized_anomaly > 0.80:
            reasons.append(
                f"Out-of-distribution observation: High unfamiliarity score ({normalized_anomaly:.2f}) indicates flow features lie outside typical training bounds."
            )
            state = "OUT_OF_DISTRIBUTION"
            review_required = True

        # 3. Check Confidence and Distributional Entropy
        if confidence < self.min_confidence:
            reasons.append(
                f"Low prediction confidence ({confidence:.1%} < {self.min_confidence:.1%})."
            )
            state = "HIGH_UNCERTAINTY"
            review_required = True
        elif normalized_entropy > self.entropy_threshold:
            reasons.append(
                f"High probability entropy ({normalized_entropy:.2f}): Model expresses ambiguity across multiple attack categories."
            )
            state = "HIGH_UNCERTAINTY"
            review_required = True

        # 4. Integrate disagreement into state
        if disagreement:
            state = "DETECTOR_DISAGREEMENT"
            review_required = True

        # 5. Schema status check
        if schema_status != "VALID" and schema_status != "COMPATIBLE":
            state = "REVIEW_REQUIRED"
            review_required = True
            reasons.append(f"Feature schema status warning: {schema_status}")

        if not reasons:
            reasons.append("Model confidence is high and detectors are in mutual agreement.")

        return UncertaintyEvaluation(
            state=state,
            review_required=review_required,
            confidence=confidence,
            entropy=entropy,
            normalized_entropy=normalized_entropy,
            ood_score=normalized_anomaly,
            disagreement_detected=disagreement,
            reasons=reasons,
        )
