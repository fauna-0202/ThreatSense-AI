"""Supervised Random Forest Classifier wrapper."""

import json
from pathlib import Path
from typing import Dict, Any, List, Optional
import joblib
import numpy as np
import pandas as pd
from threatsense.features.schema import FEATURE_NAMES
from threatsense.logging import logger


class SupervisedClassifier:
    """Loads and executes trained Random Forest model with probability calibration checks."""

    def __init__(self, artifacts_dir: str = "./artifacts/models"):
        self.artifacts_dir = Path(artifacts_dir)
        self.model = None
        self.scaler = None
        self.classes: List[str] = []
        self.model_version: str = "rf_threatsense_v1"
        self._load()

    def _load(self):
        rf_path = self.artifacts_dir / "rf_classifier.joblib"
        scaler_path = self.artifacts_dir / "scaler.joblib"
        meta_path = self.artifacts_dir / "metadata.json"

        if rf_path.exists() and scaler_path.exists():
            self.model = joblib.load(rf_path)
            self.scaler = joblib.load(scaler_path)
            self.classes = self.model.classes_.tolist()
            if meta_path.exists():
                try:
                    with open(meta_path, "r", encoding="utf-8") as f:
                        meta = json.load(f)
                        self.model_version = meta.get("model_version", self.model_version)
                except Exception:
                    pass
            logger.info(f"Loaded classifier {self.model_version} with classes: {self.classes}")
        else:
            logger.warning(f"Classifier artifacts not found in {self.artifacts_dir}")

    @property
    def is_ready(self) -> bool:
        return self.model is not None and self.scaler is not None

    def predict(self, feature_df: pd.DataFrame) -> Dict[str, Any]:
        """Runs supervised inference, returning predicted class, confidence, and probability map."""
        if not self.is_ready:
            raise RuntimeError("Classifier is not loaded or initialized.")

        # Ensure feature order matches FEATURE_NAMES
        X = feature_df[FEATURE_NAMES]
        X_scaled = self.scaler.transform(X)

        probs = self.model.predict_proba(X_scaled)[0]
        pred_idx = int(np.argmax(probs))
        predicted_class = self.classes[pred_idx]
        top_prob = float(probs[pred_idx])

        # Compute Shannon entropy as an indicator of distributional uncertainty
        eps = 1e-12
        entropy = -float(np.sum(probs * np.log(probs + eps)))
        # Max entropy for N classes is log(N)
        max_entropy = float(np.log(len(self.classes))) if len(self.classes) > 1 else 1.0
        normalized_entropy = float(entropy / max_entropy) if max_entropy > 0 else 0.0

        prob_dict = {cls: float(round(p, 4)) for cls, p in zip(self.classes, probs)}

        return {
            "predicted_class": predicted_class,
            "confidence": round(top_prob, 4),
            "probabilities": prob_dict,
            "entropy": round(entropy, 4),
            "normalized_entropy": round(normalized_entropy, 4),
            "model_version": self.model_version,
            "scaled_features": X_scaled,
        }
