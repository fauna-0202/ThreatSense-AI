"""Evaluation and benchmarking module for trained models."""

import json
from datetime import datetime, timezone
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
)
from threatsense.features.schema import FEATURE_NAMES
from threatsense.logging import logger


def evaluate_models(
    test_csv_path: str = "./data/processed/test_features.csv",
    artifacts_dir: str = "./artifacts/models",
    reports_dir: str = "./artifacts/reports",
) -> dict:
    models_path = Path(artifacts_dir)
    test_path = Path(test_csv_path)
    rep_dir = Path(reports_dir)
    rep_dir.mkdir(parents=True, exist_ok=True)

    logger.info(f"Loading test set from {test_path}")
    test_df = pd.read_csv(test_path)
    X_test = test_df[FEATURE_NAMES]
    y_test = test_df["label"]

    scaler = joblib.load(models_path / "scaler.joblib")
    rf_clf = joblib.load(models_path / "rf_classifier.joblib")
    iso_forest = joblib.load(models_path / "isolation_forest.joblib")
    gb_clf = joblib.load(models_path / "baseline_model.joblib")

    X_test_scaled = scaler.transform(X_test)

    # 1. Evaluate Supervised Random Forest
    rf_preds = rf_clf.predict(X_test_scaled)
    classes = rf_clf.classes_.tolist()

    rf_acc = float(accuracy_score(y_test, rf_preds))
    rf_f1_macro = float(f1_score(y_test, rf_preds, average="macro"))
    rf_prec_macro = float(precision_score(y_test, rf_preds, average="macro"))
    rf_rec_macro = float(recall_score(y_test, rf_preds, average="macro"))

    cm = confusion_matrix(y_test, rf_preds, labels=classes).tolist()
    cls_report = classification_report(y_test, rf_preds, output_dict=True)

    # Calculate False Positive Rate (FPR) for Benign class:
    # FPR = FP / (FP + TN) where negative = Benign, positive = Any attack
    benign_idx = classes.index("BENIGN") if "BENIGN" in classes else 0
    benign_total = int(np.sum([cm[benign_idx][j] for j in range(len(classes))]))
    benign_fp = int(sum(cm[benign_idx][j] for j in range(len(classes)) if j != benign_idx))
    benign_fpr = float(benign_fp / benign_total) if benign_total > 0 else 0.0

    # 2. Evaluate Baseline Gradient Boosting
    gb_preds = gb_clf.predict(X_test_scaled)
    gb_acc = float(accuracy_score(y_test, gb_preds))
    gb_f1_macro = float(f1_score(y_test, gb_preds, average="macro"))

    # 3. Evaluate Isolation Forest
    # -1 indicates anomaly, 1 indicates normal
    iso_raw = iso_forest.predict(X_test_scaled)
    iso_scores = iso_forest.score_samples(X_test_scaled).tolist()
    iso_anomalies = int(np.sum(iso_raw == -1))
    iso_anomaly_rate = float(iso_anomalies / len(test_df))

    # Measure agreement between Anomaly Detector and RF attack detection
    rf_attack_mask = (rf_preds != "BENIGN")
    iso_anomaly_mask = (iso_raw == -1)
    detector_agreement = float(np.mean(rf_attack_mask == iso_anomaly_mask))

    # Feature Importance from Random Forest
    feat_importances = dict(
        zip(FEATURE_NAMES, [float(x) for x in rf_clf.feature_importances_])
    )
    sorted_importances = sorted(feat_importances.items(), key=lambda x: x[1], reverse=True)

    report_data = {
        "evaluation_timestamp": datetime.now(timezone.utc).isoformat(),
        "test_sample_count": len(test_df),
        "classes": classes,
        "primary_model": {
            "name": "Random Forest Classifier",
            "accuracy": round(rf_acc, 4),
            "macro_f1": round(rf_f1_macro, 4),
            "macro_precision": round(rf_prec_macro, 4),
            "macro_recall": round(rf_rec_macro, 4),
            "benign_fpr": round(benign_fpr, 4),
            "confusion_matrix": cm,
            "per_class_report": cls_report,
            "feature_importances": dict(sorted_importances),
        },
        "baseline_comparison": {
            "name": "Gradient Boosting Classifier",
            "accuracy": round(gb_acc, 4),
            "macro_f1": round(gb_f1_macro, 4),
        },
        "anomaly_detector": {
            "name": "Isolation Forest",
            "detected_anomalies": iso_anomalies,
            "anomaly_rate": round(iso_anomaly_rate, 4),
            "agreement_with_classifier": round(detector_agreement, 4),
        },
    }

    # Save JSON report
    report_file = rep_dir / "evaluation_report.json"
    with open(report_file, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2)

    # Save Markdown report in docs
    docs_report = Path("./docs/evaluation_report.md")
    docs_report.parent.mkdir(parents=True, exist_ok=True)
    with open(docs_report, "w", encoding="utf-8") as f:
        f.write(f"# ThreatSense AI — Model Evaluation Report\n\n")
        f.write(f"**Generated:** {report_data['evaluation_timestamp']}  \n")
        f.write(f"**Test Sample Count:** {len(test_df)}  \n\n")
        f.write("## 1. Primary Model Performance (Random Forest)\n\n")
        f.write(f"- **Accuracy:** {rf_acc:.2%}\n")
        f.write(f"- **Macro F1 Score:** {rf_f1_macro:.4f}\n")
        f.write(f"- **Macro Precision:** {rf_prec_macro:.4f}\n")
        f.write(f"- **Macro Recall:** {rf_rec_macro:.4f}\n")
        f.write(f"- **Benign False Positive Rate (FPR):** {benign_fpr:.4f}\n\n")
        f.write("### Per-Class Metrics\n\n")
        f.write("| Class | Precision | Recall | F1-Score | Support |\n")
        f.write("|---|---|---|---|---|\n")
        for cls in classes:
            c_data = cls_report.get(cls, {})
            f.write(
                f"| **{cls}** | {c_data.get('precision', 0):.4f} | {c_data.get('recall', 0):.4f} | {c_data.get('f1-score', 0):.4f} | {c_data.get('support', 0)} |\n"
            )
        f.write("\n## 2. Baseline Model Comparison\n\n")
        f.write(f"- **Random Forest:** Accuracy: {rf_acc:.2%}, Macro F1: {rf_f1_macro:.4f}\n")
        f.write(f"- **Gradient Boosting:** Accuracy: {gb_acc:.2%}, Macro F1: {gb_f1_macro:.4f}\n\n")
        f.write("## 3. Unsupervised Anomaly Detection (Isolation Forest)\n\n")
        f.write(f"- **Total Anomalies Flagged:** {iso_anomalies} ({iso_anomaly_rate:.2%})\n")
        f.write(f"- **Agreement with Supervised Classifier:** {detector_agreement:.2%}\n\n")
        f.write("## 4. Top Feature Importances\n\n")
        f.write("| Feature | Importance Weight |\n")
        f.write("|---|---|\n")
        for feat, imp in sorted_importances[:8]:
            f.write(f"| `{feat}` | {imp:.4f} |\n")

    logger.info(f"Evaluation reports generated at {report_file} and {docs_report}")
    return report_data


if __name__ == "__main__":
    evaluate_models()
