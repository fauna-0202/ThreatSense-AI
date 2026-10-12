"""Page 5: System Health and Operational Settings."""

import streamlit as st
import pandas as pd
from datetime import datetime
from dashboard.components.styles import apply_custom_styles
from dashboard.components.api_client import backend_client
from threatsense.config import settings
from threatsense.features.schema import CANONICAL_FEATURES, FEATURE_SCHEMA_VERSION

st.set_page_config(page_title="System Health & Settings — ThreatSense AI", page_icon="⚙️", layout="wide")
apply_custom_styles()

st.title("System Health & Operational Settings")
st.markdown("Subsystem diagnostics, active feature schemas, risk policies, and sensor configurations.")

# Subsystem Status Cards
sensor_info = backend_client.get_sensor_status()
metrics = backend_client.get_metrics()

c1, c2, c3 = st.columns(3)
with c1:
    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-title">API & Backend Status</div>
            <div class="metric-value" style="color: #10B981;">Online (v{settings.app.version})</div>
            <div class="metric-subtitle">Host: {settings.api.host}:{settings.api.port}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with c2:
    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-title">Database Subsystem</div>
            <div class="metric-value" style="color: #10B981;">Connected (SQLite)</div>
            <div class="metric-subtitle">Events Persisted: {metrics.get('total_events', 0):,}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with c3:
    is_live = sensor_info.get("is_alive", False)
    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-title">Sensor Subsystem</div>
            <div class="metric-value" style="color: {'#10B981' if is_live else '#F59E0B'};">{sensor_info.get('state', 'Stopped')}</div>
            <div class="metric-subtitle">Mode: {sensor_info.get('mode', 'replay').upper()} | {sensor_info.get('interface')}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

st.markdown("---")

# Feature Schema Dictionary
st.subheader(f"Supported Canonical Feature Schema (`{FEATURE_SCHEMA_VERSION}`)")
st.markdown("The 12 mathematical flow features mapped consistently between Zeek connection logs and training pipelines:")

schema_rows = []
for f in CANONICAL_FEATURES:
    schema_rows.append({
        "Feature Name": f"`{f.name}`",
        "Data Type": f.dtype,
        "Unit": f.unit,
        "Valid Range": f"[{f.min_val:g}, {f.max_val:g}]",
        "Description": f.description,
        "Source Compatibility Mapping": f.source_mapping,
    })

schema_df = pd.DataFrame(schema_rows)
st.dataframe(schema_df, use_container_width=True, hide_index=True)

st.markdown("---")

# Operational Risk Policy and Weights
col_cfg, col_err = st.columns(2)

with col_cfg:
    st.subheader("Operational Risk Scoring Policy")
    st.markdown("Configured scoring weights and threshold definitions:")

    weights_df = pd.DataFrame([
        {"Component": "Supervised Classifier Attack Probability", "Weight": f"{settings.risk_scoring.classifier_weight:.0%}"},
        {"Component": "Isolation Forest Abnormality Factor", "Weight": f"{settings.risk_scoring.anomaly_weight:.0%}"},
        {"Component": "Target Port / Service Sensitivity Factor", "Weight": f"{settings.risk_scoring.protocol_weight:.0%}"},
        {"Component": "Uncertainty Penalty Factor", "Weight": f"{settings.risk_scoring.uncertainty_penalty_factor:.0%}"},
        {"Component": "Minimum Confidence Review Threshold", "Weight": f"{settings.risk_scoring.min_confidence_threshold:.0%}"},
    ])
    st.dataframe(weights_df, use_container_width=True, hide_index=True)

    st.markdown("**Priority Bands:**")
    st.markdown("- **Low:** 0 – 24")
    st.markdown("- **Moderate:** 25 – 49")
    st.markdown("- **High:** 50 – 74")
    st.markdown("- **Critical:** 75 – 100")

with col_err:
    st.subheader("Sensor Error & Telemetry Logs")
    last_err = sensor_info.get("last_error")
    err_count = sensor_info.get("errors_count", 0)

    st.markdown(f"**Recorded Sensor Errors:** `{err_count}`")
    if last_err:
        st.error(f"Last Sensor Error: {last_err}")
    else:
        st.success("No active sensor errors recorded.")

    st.markdown("**Active Models:**")
    st.markdown(f"- Supervised Classifier: `{settings.models.active_classifier_id}`")
    st.markdown(f"- Anomaly Detector: `{settings.models.active_anomaly_id}`")
    st.markdown(f"- Explainability: `SHAP TreeExplainer (Top 5 features)`")

    st.caption("🔒 Security Notice: Sensitive internal variables, secret keys, and credentials are protected and never displayed in this interface.")
