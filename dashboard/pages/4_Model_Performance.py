"""Page 4: Model Performance and Evaluation."""

import json
from pathlib import Path
import streamlit as st
import pandas as pd
from dashboard.components.styles import apply_custom_styles
from dashboard.components.charts import (
    create_confusion_matrix_heatmap,
    create_feature_importance_chart,
)

st.set_page_config(page_title="Model Performance — ThreatSense AI", page_icon="📊", layout="wide")
apply_custom_styles()

st.title("Model Performance & Benchmarking")
st.markdown("Offline evaluation metrics, cross-model comparison, and feature importance diagnostics.")

# Important distinction banner
st.info(
    "📌 **Operational Notice:** The metrics below represent reproducible offline hold-out evaluation on the test dataset split (3,000 samples). Live detection precision in dynamic production environments may vary based on traffic drift."
)

report_path = Path("./artifacts/reports/evaluation_report.json")
meta_path = Path("./artifacts/models/metadata.json")

if not report_path.exists():
    st.warning("Model evaluation report not found. Run `python -m training.evaluate` to generate metrics.")
    st.stop()

with open(report_path, "r", encoding="utf-8") as f:
    report = json.load(f)

with open(meta_path, "r", encoding="utf-8") as f:
    meta = json.load(f)

primary = report.get("primary_model", {})
baseline = report.get("baseline_comparison", {})
anomaly = report.get("anomaly_detector", {})
classes = report.get("classes", [])

# Top Metric Cards
c1, c2, c3, c4 = st.columns(4)
with c1:
    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-title">Random Forest Accuracy</div>
            <div class="metric-value">{primary.get('accuracy', 0):.2%}</div>
            <div class="metric-subtitle">Macro F1: <b>{primary.get('macro_f1', 0):.4f}</b></div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with c2:
    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-title">Benign False Positive Rate</div>
            <div class="metric-value">{primary.get('benign_fpr', 0):.4f}</div>
            <div class="metric-subtitle">Target: &lt; 0.0100</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with c3:
    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-title">Isolation Forest Agreement</div>
            <div class="metric-value">{anomaly.get('agreement_with_classifier', 0):.2%}</div>
            <div class="metric-subtitle">Anomaly Rate: <b>{anomaly.get('anomaly_rate', 0):.2%}</b></div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with c4:
    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-title">Evaluation Test Samples</div>
            <div class="metric-value">{report.get('test_sample_count', 0):,}</div>
            <div class="metric-subtitle">Train: <b>{meta.get('training_samples', 0):,}</b> samples</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

st.markdown("<br>", unsafe_allow_html=True)

# Confusion Matrix and Per-Class Metrics
col_cm, col_pc = st.columns([3, 2])

with col_cm:
    st.subheader("Confusion Matrix (Hold-out Test Set)")
    cm = primary.get("confusion_matrix", [])
    if cm:
        cm_chart = create_confusion_matrix_heatmap(cm, classes)
        st.plotly_chart(cm_chart, use_container_width=True)

with col_pc:
    st.subheader("Per-Class Classification Metrics")
    per_class = primary.get("per_class_report", {})
    pc_data = []
    for cls in classes:
        c_stats = per_class.get(cls, {})
        pc_data.append({
            "Class": cls,
            "Precision": f"{c_stats.get('precision', 0):.4f}",
            "Recall": f"{c_stats.get('recall', 0):.4f}",
            "F1-Score": f"{c_stats.get('f1-score', 0):.4f}",
            "Samples": int(c_stats.get("support", 0)),
        })
    st.dataframe(pd.DataFrame(pc_data), use_container_width=True, hide_index=True)

st.markdown("---")

# Model Comparison & Feature Importances
c_comp, c_feat = st.columns(2)

with c_comp:
    st.subheader("Supervised Baseline Comparison")
    st.markdown("Benchmarking primary Random Forest against Gradient Boosting classifier:")
    comp_df = pd.DataFrame([
        {
            "Model Architecture": "Random Forest (Primary)",
            "Accuracy": f"{primary.get('accuracy', 0):.2%}",
            "Macro F1": f"{primary.get('macro_f1', 0):.4f}",
            "Role": "Operational Classifier + SHAP TreeExplainer",
        },
        {
            "Model Architecture": "Gradient Boosting (Baseline)",
            "Accuracy": f"{baseline.get('accuracy', 0):.2%}",
            "Macro F1": f"{baseline.get('macro_f1', 0):.4f}",
            "Role": "Comparative Baseline Validation",
        },
    ])
    st.dataframe(comp_df, use_container_width=True, hide_index=True)

    st.subheader("Training & Evaluation Metadata")
    st.json({
        "Model Version": meta.get("model_version"),
        "Anomaly Model Version": meta.get("anomaly_model_version"),
        "Feature Schema Version": meta.get("feature_schema_version"),
        "Trained At": meta.get("trained_at"),
        "Random Seed": meta.get("random_seed"),
        "Evaluation Timestamp": report.get("evaluation_timestamp"),
    })

with c_feat:
    st.subheader("Global Feature Importance (Gini Impurity)")
    importances = primary.get("feature_importances", {})
    if importances:
        feat_chart = create_feature_importance_chart(importances)
        st.plotly_chart(feat_chart, use_container_width=True)
