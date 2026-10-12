"""Explainable AI engine using SHAP TreeExplainer with robust fallbacks."""

from typing import Dict, Any, List, Optional
import numpy as np
import pandas as pd
from threatsense.features.schema import FEATURE_NAMES
from threatsense.logging import logger

try:
    import shap
    SHAP_AVAILABLE = True
except ImportError:
    SHAP_AVAILABLE = False


class FlowExplainer:
    """Generates per-prediction feature attribution explanations using SHAP."""

    def __init__(self, classifier_model, background_data: Optional[np.ndarray] = None):
        self.model = classifier_model
        self.explainer = None
        self.status = "UNINITIALIZED"

        if SHAP_AVAILABLE and self.model is not None:
            try:
                # TreeExplainer for Random Forest
                self.explainer = shap.TreeExplainer(self.model)
                self.status = "READY"
                logger.info("SHAP TreeExplainer initialized successfully.")
            except Exception as e:
                logger.warning(f"Could not initialize TreeExplainer directly: {e}. Will use fallback.")
                self.status = "FALLBACK"
        else:
            self.status = "FALLBACK"

    def explain(
        self,
        scaled_features: np.ndarray,
        feature_df: pd.DataFrame,
        predicted_class: str,
        class_list: List[str],
        top_k: int = 5,
    ) -> Dict[str, Any]:
        """Calculates influential features for the predicted class."""
        pred_idx = class_list.index(predicted_class) if predicted_class in class_list else 0

        # Try SHAP TreeExplainer if ready
        if self.status == "READY" and self.explainer is not None:
            try:
                raw_shap = self.explainer.shap_values(scaled_features)
                
                # Multi-class output handling
                if isinstance(raw_shap, list):
                    # List of [1, n_features] per class
                    class_shap = raw_shap[pred_idx][0]
                elif isinstance(raw_shap, np.ndarray):
                    if raw_shap.ndim == 3:
                        class_shap = raw_shap[0, :, pred_idx]
                    elif raw_shap.ndim == 2:
                        class_shap = raw_shap[0]
                    else:
                        class_shap = raw_shap
                else:
                    raise ValueError(f"Unexpected SHAP values type: {type(raw_shap)}")

                return self._format_contributions(
                    class_shap, feature_df, predicted_class, top_k, status="SUCCESS"
                )
            except Exception as e:
                logger.warning(f"SHAP explanation computation failed: {e}. Falling back.")

        # Fallback explanation using tree feature importances & normalized deviations
        return self._fallback_explanation(scaled_features, feature_df, predicted_class, top_k)

    def _format_contributions(
        self,
        shap_vector: np.ndarray,
        feature_df: pd.DataFrame,
        predicted_class: str,
        top_k: int,
        status: str,
    ) -> Dict[str, Any]:
        contributions = []
        for i, feat_name in enumerate(FEATURE_NAMES):
            val = float(feature_df[feat_name].iloc[0])
            contrib = float(shap_vector[i])
            contributions.append({
                "feature": feat_name,
                "importance": round(abs(contrib), 4),
                "shap_value": round(contrib, 4),
                "actual_value": round(val, 4) if isinstance(val, float) else val,
                "direction": "supports_prediction" if contrib > 0 else "opposes_prediction",
            })

        # Sort by absolute importance
        contributions.sort(key=lambda x: x["importance"], reverse=True)
        top_features = contributions[:top_k]

        return {
            "status": status,
            "predicted_class": predicted_class,
            "top_features": top_features,
            "all_features": contributions,
            "base_value": 0.0,
        }

    def _fallback_explanation(
        self,
        scaled_features: np.ndarray,
        feature_df: pd.DataFrame,
        predicted_class: str,
        top_k: int,
    ) -> Dict[str, Any]:
        """Deterministic surrogate explanation using model feature importances and z-score deviation."""
        importances = getattr(self.model, "feature_importances_", np.ones(len(FEATURE_NAMES)) / len(FEATURE_NAMES))
        scaled_vec = scaled_features[0]

        # Product of feature importance and absolute z-score deviation
        pseudo_shap = importances * scaled_vec

        return self._format_contributions(
            pseudo_shap, feature_df, predicted_class, top_k, status="FALLBACK"
        )
