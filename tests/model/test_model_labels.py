"""Machine learning model tests for label mapping and classes."""

import json
from pathlib import Path
import joblib
from threatsense.features.schema import FEATURE_NAMES

MODELS_DIR = Path("./artifacts/models")


def test_model_artifacts_exist():
    assert (MODELS_DIR / "rf_classifier.joblib").exists()
    assert (MODELS_DIR / "isolation_forest.joblib").exists()
    assert (MODELS_DIR / "scaler.joblib").exists()
    assert (MODELS_DIR / "metadata.json").exists()


def test_model_classes_match_spec():
    with open(MODELS_DIR / "metadata.json", "r", encoding="utf-8") as f:
        meta = json.load(f)

    classes = meta["classes"]
    expected = ["BENIGN", "Botnet", "BruteForce", "DoS/DDoS", "PortScan"]
    assert sorted(classes) == sorted(expected)

    rf_clf = joblib.load(MODELS_DIR / "rf_classifier.joblib")
    assert sorted(rf_clf.classes_.tolist()) == sorted(expected)


def test_feature_count_and_names_match():
    rf_clf = joblib.load(MODELS_DIR / "rf_classifier.joblib")
    assert rf_clf.n_features_in_ == len(FEATURE_NAMES)
