"""Model training pipeline for supervised classifier, anomaly detector, and baseline."""

import json
from datetime import datetime, timezone
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier, IsolationForest, GradientBoostingClassifier
from threatsense.features.schema import FEATURE_NAMES, FEATURE_SCHEMA_VERSION
from threatsense.logging import logger
from training.prepare_dataset import load_and_preprocess_data


def train_models(
    train_csv_path: str = "./data/processed/train_features.csv",
    artifacts_dir: str = "./artifacts/models",
    random_seed: int = 42,
):
    train_path = Path(train_csv_path)
    if not train_path.exists():
        logger.info("Train CSV not found. Running prepare_dataset first...")
        load_and_preprocess_data()

    logger.info(f"Loading training data from {train_path}")
    train_df = pd.read_csv(train_path)

    X_train = train_df[FEATURE_NAMES]
    y_train = train_df["label"]

    classes = sorted(y_train.unique().tolist())
    logger.info(f"Target classes: {classes}")

    # 1. Fit Preprocessor (StandardScaler) strictly on train data
    logger.info("Fitting StandardScaler on training data...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)

    # 2. Fit Supervised Classifier (Random Forest)
    logger.info("Training Random Forest Classifier baseline...")
    rf_clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=12,
        min_samples_split=4,
        min_samples_leaf=2,
        random_state=random_seed,
        n_jobs=-1,
    )
    rf_clf.fit(X_train_scaled, y_train)

    # 3. Fit Anomaly Detector (Isolation Forest) on benign data to learn normal behavior
    logger.info("Training Isolation Forest on benign samples...")
    benign_mask = (y_train == "BENIGN")
    X_benign_scaled = X_train_scaled[benign_mask]

    iso_forest = IsolationForest(
        n_estimators=100,
        contamination=0.05,
        max_samples="auto",
        random_state=random_seed,
        n_jobs=-1,
    )
    iso_forest.fit(X_benign_scaled)

    # 4. Fit Baseline Comparison Model (Gradient Boosting Classifier)
    logger.info("Training comparison baseline: GradientBoostingClassifier...")
    gb_clf = GradientBoostingClassifier(
        n_estimators=50,
        max_depth=5,
        random_state=random_seed,
    )
    gb_clf.fit(X_train_scaled, y_train)

    # 5. Save Artifacts
    out_dir = Path(artifacts_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    joblib.dump(scaler, out_dir / "scaler.joblib")
    joblib.dump(rf_clf, out_dir / "rf_classifier.joblib")
    joblib.dump(iso_forest, out_dir / "isolation_forest.joblib")
    joblib.dump(gb_clf, out_dir / "baseline_model.joblib")

    metadata = {
        "model_version": "rf_threatsense_v1",
        "anomaly_model_version": "iforest_threatsense_v1",
        "baseline_model_version": "gb_threatsense_v1",
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "feature_names": FEATURE_NAMES,
        "classes": classes,
        "training_samples": len(train_df),
        "benign_samples": int(benign_mask.sum()),
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "random_seed": random_seed,
    }

    with open(out_dir / "metadata.json", "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    logger.info(f"All model artifacts and metadata saved to {out_dir}")
    return metadata


if __name__ == "__main__":
    train_models()
