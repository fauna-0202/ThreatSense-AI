"""ThreatSense AI — Security Operations Center Dashboard."""

import streamlit as st
import pandas as pd
from datetime import datetime
from dashboard.components.styles import apply_custom_styles, get_priority_badge, get_status_badge
from dashboard.components.charts import create_priority_chart, create_risk_distribution_chart
from dashboard.components.api_client import backend_client

st.set_page_config(
    page_title="ThreatSense AI — Security Operations",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

apply_custom_styles()

# Sidebar
st.sidebar.markdown("## 🛡️ **ThreatSense AI**")
st.sidebar.markdown("*Detect. Explain. Defend.*")
st.sidebar.markdown("---")

sensor_info = backend_client.get_sensor_status()
sensor_state = sensor_info.get("state", "Stopped")

# State color indicator
state_color = "🟢" if sensor_info.get("is_alive") else "🟡"
if sensor_state == "Error":
    state_color = "🔴"

st.sidebar.markdown(f"**Sensor Status:** {state_color} `{sensor_state}`")
st.sidebar.markdown(f"**Mode:** `{sensor_info.get('mode', 'replay').upper()}`")
st.sidebar.markdown(f"**Interface:** `{sensor_info.get('interface', 'eth0')}`")
st.sidebar.markdown("---")

# Quick Action Replay Button
if st.sidebar.button("▶ Run Replay Demo Batch", use_container_width=True):
    from sensor.health import sensor_tracker, SensorState
    from threatsense.ingestion.replay import ReplayEngine
    from threatsense.detection.engine import DetectionEngine
    from threatsense.storage.database import SessionLocal
    from threatsense.config import settings

    with st.spinner("Processing replay batch..."):
        db = SessionLocal()
        try:
            eng = DetectionEngine()
            rep = ReplayEngine(settings.sensor.replay_sample_file)
            count = 0
            for ev in rep.stream_events(delay_seconds=0.0):
                eng.analyze_event(ev, db=db)
                sensor_tracker.record_event()
                count += 1
            st.sidebar.success(f"Ingested {count} events!")
        finally:
            db.close()
    st.rerun()

# Security Overview Header
st.title("Security Overview")
st.markdown("Real-time network anomaly surveillance, threat categorization, and alert distribution.")

# Fetch Telemetry
metrics = backend_client.get_metrics()
total_events = metrics.get("total_events", 0)
total_alerts = metrics.get("total_alerts", 0)
epm = metrics.get("events_per_minute", 0.0)
last_event_ts = metrics.get("last_event_timestamp") or "None"

# Top Metrics Row
c1, c2, c3, c4 = st.columns(4)
with c1:
    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-title">Sensor State</div>
            <div class="metric-value">{sensor_state}</div>
            <div class="metric-subtitle">Mode: {sensor_info.get('mode', 'replay').upper()}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with c2:
    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-title">Events Processed</div>
            <div class="metric-value">{total_events:,}</div>
            <div class="metric-subtitle">Throughput: {epm} ev/min</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with c3:
    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-title">Total Alerts</div>
            <div class="metric-value">{total_alerts:,}</div>
            <div class="metric-subtitle">Critical: {metrics.get('priority_counts', {}).get('CRITICAL', 0)}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with c4:
    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-title">Model Health</div>
            <div class="metric-value" style="color: #10B981;">Operational</div>
            <div class="metric-subtitle">Dual: RF + Isolation Forest</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

st.markdown("<br>", unsafe_allow_html=True)

# Charts Row
col_left, col_right = st.columns(2)

with col_left:
    st.subheader("Alerts by Priority")
    pri_chart = create_priority_chart(metrics.get("priority_counts", {}))
    st.plotly_chart(pri_chart, use_container_width=True)

with col_right:
    st.subheader("Operational Risk Distribution")
    risk_chart = create_risk_distribution_chart(metrics.get("risk_distribution", {}))
    st.plotly_chart(risk_chart, use_container_width=True)

st.markdown("---")

# Recent Alerts Table
st.subheader("Recent Security Alerts")

alerts = backend_client.get_alerts(limit=10)

if not alerts:
    st.info("No security alerts recorded yet. Click 'Run Replay Demo Batch' in the sidebar or send traffic to generate live events.")
else:
    table_data = []
    for a in alerts:
        pred = a.get("prediction") or {}
        ev = a.get("event") or {}
        table_data.append({
            "Alert ID": a["id"][:8] + "...",
            "Timestamp": str(a.get("created_at", ""))[:19].replace("T", " "),
            "Source": f"{ev.get('src_ip', '')}:{ev.get('src_port', '')}",
            "Destination": f"{ev.get('dst_ip', '')}:{ev.get('dst_port', '')}",
            "Protocol": ev.get("protocol", "TCP"),
            "Predicted Threat": pred.get("predicted_class", "UNKNOWN"),
            "Risk Score": f"{a.get('risk_score', 0):.1f}",
            "Priority": a.get("priority", "LOW"),
            "Status": a.get("status", "NEW"),
            "Uncertainty": pred.get("uncertainty_state", "CONFIDENT"),
        })

    df = pd.DataFrame(table_data)
    st.dataframe(df, use_container_width=True, hide_index=True)
