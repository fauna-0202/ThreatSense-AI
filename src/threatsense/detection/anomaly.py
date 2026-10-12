"""Unsupervised Anomaly Detector using Isolation Forest."""

import json
from pathlib import Path
from typing import Dict, Any, Optional
import joblib
import numpy as np
import pandas as pd
from threatsense.features.schema import FEATURE_NAMES
from threatsense.logging import logger


class AnomalyDetector:
    """Evaluates flow abnormality using trained Isolation Forest."""

    def __init__(self, artifacts_dir: str = "./artifacts/models"):
        self.artifacts_dir = Path(artifacts_dir)
        self.model = None
        self.scaler = None
        self.model_version: str = "iforest_threatsense_v1"
        self._load()

    def _load(self):
        iso_path = self.artifacts_dir / "isolation_forest.joblib"
        scaler_path = self.artifacts_dir / "scaler.joblib"
        meta_path = self.artifacts_dir / "metadata.json"

        if iso_path.exists() and scaler_path.exists():
            self.model = joblib.load(iso_path)
            self.scaler = joblib.load(scaler_path)
            if meta_path.exists():
                try:
                    with open(meta_path, "r", encoding="utf-8") as f:
                        meta = json.load(f)
                        self.model_version = meta.get("anomaly_model_version", self.model_version)
                except Exception:
                    pass
            logger.info(f"Loaded anomaly detector {self.model_version}")
        else:
            logger.warning(f"Anomaly detector artifacts not found in {self.artifacts_dir}")

    @property
    def is_ready(self) -> bool:
        return self.model is not None and self.scaler is not None

    def evaluate(self, feature_df: pd.DataFrame, scaled_features: Optional[np.ndarray] = None) -> Dict[str, Any]:
        """Evaluates anomaly score and normality decision."""
        if not self.is_ready:
            raise RuntimeError("Anomaly detector is not loaded or initialized.")

        if scaled_features is not None:
            X_scaled = scaled_features
        else:
            X = feature_df[FEATURE_NAMES]
            X_scaled = self.scaler.transform(X)

        # score_samples returns opposite of anomaly score (lower means more anomalous)
        raw_score = float(self.model.score_samples(X_scaled)[0])
        decision = int(self.model.predict(X_scaled)[0])  # -1 for anomaly, 1 for normal
        is_anomaly = 1 if decision == -1 else 0

        # Map raw score to normalized unfamiliarity / anomaly factor (0.0 to 1.0)
        # Typically score_samples is roughly between -0.8 and 0.2
        # -0.8 -> high anomaly (1.0), 0.0 -> normal (0.0)
        clamped_score = max(-0.8, min(0.1, raw_score))
        normalized_anomaly = float((0.1 - clamped_score) / 0.9)
        normalized_anomaly = round(max(0.0, min(1.0, normalized_anomaly)), 4)

        return {
            "is_anomaly": is_anomaly,
            "anomaly_score": round(raw_score, 4),
            "normalized_anomaly_factor": normalized_anomaly,
            "model_version": self.model_version,
            "decision": "ANOMALOUS" if is_anomaly else "NORMAL",
        }
