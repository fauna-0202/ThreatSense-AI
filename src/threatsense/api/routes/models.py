"""Model versions and metadata endpoints."""

import json
from pathlib import Path
from typing import List
from fastapi import APIRouter
from threatsense.api.schemas import ModelInfo
from threatsense.config import settings

router = APIRouter(prefix="/models", tags=["Models"])


@router.get("", response_model=List[ModelInfo])
def list_models():
    models_dir = Path(settings.models.artifacts_dir)
    meta_file = models_dir / "metadata.json"

    meta = {}
    if meta_file.exists():
        try:
            with open(meta_file, "r", encoding="utf-8") as f:
                meta = json.load(f)
        except Exception:
            pass

    classes = meta.get("classes", ["BENIGN", "Botnet", "BruteForce", "DoS/DDoS", "PortScan"])
    trained_at = meta.get("trained_at")

    return [
        ModelInfo(
            name="Random Forest Classifier (Primary)",
            version=meta.get("model_version", "rf_threatsense_v1"),
            type="SUPERVISED_CLASSIFIER",
            feature_schema_version=meta.get("feature_schema_version", "threatsense-features-v1"),
            classes=classes,
            trained_at=trained_at,
            status="ACTIVE",
        ),
        ModelInfo(
            name="Isolation Forest Anomaly Detector",
            version=meta.get("anomaly_model_version", "iforest_threatsense_v1"),
            type="ANOMALY_DETECTOR",
            feature_schema_version=meta.get("feature_schema_version", "threatsense-features-v1"),
            classes=["NORMAL", "ANOMALOUS"],
            trained_at=trained_at,
            status="ACTIVE",
        ),
        ModelInfo(
            name="Gradient Boosting Classifier (Baseline Comparison)",
            version=meta.get("baseline_model_version", "gb_threatsense_v1"),
            type="SUPERVISED_BASELINE",
            feature_schema_version=meta.get("feature_schema_version", "threatsense-features-v1"),
            classes=classes,
            trained_at=trained_at,
            status="STANDBY",
        ),
    ]
