"""ThreatSense AI unified detection, explainability, and risk engine."""

from typing import Dict, Any, Optional
import pandas as pd
from sqlalchemy.orm import Session

from threatsense.ingestion.schemas import IngestedEvent
from threatsense.features.extractor import FlowFeatureExtractor
from threatsense.features.compatibility import FeatureCompatibilityValidator
from threatsense.detection.classifier import SupervisedClassifier
from threatsense.detection.anomaly import AnomalyDetector
from threatsense.explainability.explainer import FlowExplainer
from threatsense.explainability.formatter import ExplanationFormatter
from threatsense.alerting.uncertainty import UncertaintyEngine
from threatsense.alerting.risk import RiskScoringEngine
from threatsense.storage.models import NetworkEvent, Prediction, Alert, Explanation
from threatsense.storage.repository import EventRepository, AlertRepository
from threatsense.logging import logger


class DetectionEngine:
    """Master detection engine coordinating flow ingestion, inference, explainability, and alerting."""

    def __init__(self, artifacts_dir: str = "./artifacts/models"):
        self.artifacts_dir = artifacts_dir
        self.classifier = SupervisedClassifier(artifacts_dir=artifacts_dir)
        self.anomaly_detector = AnomalyDetector(artifacts_dir=artifacts_dir)
        self.uncertainty_engine = UncertaintyEngine()
        self.risk_engine = RiskScoringEngine()

        # Initialize explainer with classifier
        if self.classifier.is_ready:
            self.explainer = FlowExplainer(self.classifier.model)
        else:
            self.explainer = None

    def analyze_event(
        self, event: IngestedEvent, db: Optional[Session] = None
    ) -> Dict[str, Any]:
        """Analyzes an ingested event through the full ThreatSense pipeline."""
        # 1. Feature Extraction
        feature_dict = FlowFeatureExtractor.extract_features(event)
        feature_df = FlowFeatureExtractor.to_dataframe(feature_dict)

        # 2. Compatibility Verification
        compat = FeatureCompatibilityValidator.validate(feature_dict)
        if not compat.is_compatible:
            logger.warning(f"Incompatible event features: {compat.message}")
            return {
                "event_id": None,
                "status": "REJECTED",
                "schema_status": compat.status_code,
                "message": compat.message,
                "details": compat.details,
            }

        # 3. Model Inference
        clf_res = self.classifier.predict(feature_df)
        ano_res = self.anomaly_detector.evaluate(
            feature_df, scaled_features=clf_res["scaled_features"]
        )

        # 4. Uncertainty Evaluation
        uncertainty = self.uncertainty_engine.evaluate(
            predicted_class=clf_res["predicted_class"],
            confidence=clf_res["confidence"],
            entropy=clf_res["entropy"],
            normalized_entropy=clf_res["normalized_entropy"],
            is_anomaly=ano_res["is_anomaly"],
            normalized_anomaly=ano_res["normalized_anomaly_factor"],
            schema_status=compat.status_code,
        )

        # 5. Risk Scoring
        risk = self.risk_engine.calculate_risk(
            predicted_class=clf_res["predicted_class"],
            confidence=clf_res["confidence"],
            is_anomaly=ano_res["is_anomaly"],
            normalized_anomaly=ano_res["normalized_anomaly_factor"],
            dst_port=event.dst_port,
            uncertainty_state=uncertainty.state,
        )

        # 6. Explainability
        explanation_data = None
        narrative_summary = ""
        if self.explainer:
            raw_exp = self.explainer.explain(
                scaled_features=clf_res["scaled_features"],
                feature_df=feature_df,
                predicted_class=clf_res["predicted_class"],
                class_list=self.classifier.classes,
                top_k=5,
            )
            narrative_summary = ExplanationFormatter.generate_narrative(
                predicted_class=clf_res["predicted_class"],
                confidence=clf_res["confidence"],
                top_features=raw_exp.get("top_features", []),
                uncertainty_state=uncertainty.state,
                is_anomaly=bool(ano_res["is_anomaly"]),
            )
            explanation_data = {
                "influential_features": raw_exp.get("top_features", []),
                "summary": narrative_summary,
                "status": raw_exp.get("status", "SUCCESS"),
            }

        # 7. Persistence (if db session provided)
        event_record = None
        alert_record = None
        if db is not None:
            # Check deduplication
            existing = EventRepository.get_by_fingerprint(db, event.event_fingerprint)
            if existing:
                event_record = existing
            else:
                event_record = NetworkEvent(
                    timestamp=event.timestamp,
                    src_ip=event.src_ip,
                    src_port=event.src_port,
                    dst_ip=event.dst_ip,
                    dst_port=event.dst_port,
                    protocol=event.protocol,
                    conn_state=event.conn_state,
                    duration=event.duration,
                    orig_bytes=event.orig_bytes,
                    resp_bytes=event.resp_bytes,
                    orig_pkts=event.orig_pkts,
                    resp_pkts=event.resp_pkts,
                    data_source=event.data_source,
                    event_fingerprint=event.event_fingerprint,
                    raw_payload=event.raw_payload,
                )
                db.add(event_record)
                db.commit()
                db.refresh(event_record)

            pred_record = Prediction(
                event_id=event_record.id,
                model_version=clf_res["model_version"],
                predicted_class=clf_res["predicted_class"],
                confidence=clf_res["confidence"],
                class_probabilities=clf_res["probabilities"],
                anomaly_score=ano_res["anomaly_score"],
                is_anomaly=ano_res["is_anomaly"],
                uncertainty_state=uncertainty.state,
                schema_status=compat.status_code,
            )
            db.add(pred_record)
            db.commit()
            db.refresh(pred_record)

            alert_record = Alert(
                event_id=event_record.id,
                prediction_id=pred_record.id,
                risk_score=risk.risk_score,
                priority=risk.priority,
                status="NEW",
                contributing_signals=risk.contributing_signals,
            )
            db.add(alert_record)
            db.commit()
            db.refresh(alert_record)

            if explanation_data:
                exp_record = Explanation(
                    prediction_id=pred_record.id,
                    influential_features=explanation_data["influential_features"],
                    summary_text=explanation_data["summary"],
                    explanation_status=explanation_data["status"],
                )
                db.add(exp_record)
                db.commit()

        return {
            "event_id": event_record.id if event_record else None,
            "alert_id": alert_record.id if alert_record else None,
            "status": "PROCESSED",
            "prediction": {
                "predicted_class": clf_res["predicted_class"],
                "confidence": clf_res["confidence"],
                "probabilities": clf_res["probabilities"],
                "model_version": clf_res["model_version"],
            },
            "anomaly": {
                "is_anomaly": ano_res["is_anomaly"],
                "anomaly_score": ano_res["anomaly_score"],
                "normalized_anomaly_factor": ano_res["normalized_anomaly_factor"],
                "decision": ano_res["decision"],
            },
            "uncertainty": {
                "state": uncertainty.state,
                "review_required": uncertainty.review_required,
                "ood_score": uncertainty.ood_score,
                "entropy": uncertainty.entropy,
                "reasons": uncertainty.reasons,
            },
            "risk": {
                "risk_score": risk.risk_score,
                "priority": risk.priority,
                "signals": risk.contributing_signals,
            },
            "explanation": explanation_data,
        }
