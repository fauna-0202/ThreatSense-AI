"""Page 3: Alert Investigation."""

import streamlit as st
import pandas as pd
from dashboard.components.styles import apply_custom_styles
from dashboard.components.charts import create_shap_bar_chart
from dashboard.components.api_client import backend_client

st.set_page_config(page_title="Alert Investigation — ThreatSense AI", page_icon="🔍", layout="wide")
apply_custom_styles()

st.title("Alert Investigation & Explainability")
st.markdown("Detailed forensic inspection, SHAP attributions, uncertainty diagnostics, and SecOps triage.")

alerts = backend_client.get_alerts(limit=100)

if not alerts:
    st.info("No security alerts available to investigate. Trigger a replay batch from the main overview page.")
    st.stop()

# Alert Selector
alert_options = {}
for a in alerts:
    pred = a.get("prediction") or {}
    ev = a.get("event") or {}
    ts = str(a.get("created_at", ""))[:19].replace("T", " ")
    label = f"[{a.get('priority')}] {pred.get('predicted_class', 'ALERT')} — {ev.get('src_ip')}:{ev.get('src_port')} ➔ {ev.get('dst_ip')}:{ev.get('dst_port')} ({ts}) — ID: {a['id'][:8]}"
    alert_options[label] = a["id"]

selected_label = st.selectbox("Select Alert for In-Depth Forensic Analysis", list(alert_options.keys()))
selected_id = alert_options[selected_label]

alert_data = backend_client.get_alert_detail(selected_id)
if not alert_data:
    st.error("Failed to retrieve alert details.")
    st.stop()

ev = alert_data.get("event") or {}
pred = alert_data.get("prediction") or {}
exp = pred.get("explanation") or {}
signals = alert_data.get("contributing_signals") or {}

# Top Summary Row
col1, col2, col3, col4 = st.columns(4)
with col1:
    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-title">Risk Score & Priority</div>
            <div class="metric-value">{alert_data.get('risk_score', 0):.1f} / 100</div>
            <div class="metric-subtitle">Priority: <b>{alert_data.get('priority')}</b></div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with col2:
    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-title">Predicted Class</div>
            <div class="metric-value">{pred.get('predicted_class', 'UNKNOWN')}</div>
            <div class="metric-subtitle">Confidence: <b>{pred.get('confidence', 0):.1%}</b></div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with col3:
    ano_score = pred.get("anomaly_score", 0.0)
    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-title">Anomaly Detector</div>
            <div class="metric-value">{'ANOMALOUS' if ano_score < -0.1 else 'NORMAL'}</div>
            <div class="metric-subtitle">Raw Score: <b>{ano_score:.3f}</b></div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with col4:
    uncert = pred.get("uncertainty_state", "CONFIDENT")
    uncert_color = "#10B981" if uncert == "CONFIDENT" else "#F59E0B"
    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-title">Uncertainty State</div>
            <div class="metric-value" style="color: {uncert_color};">{uncert}</div>
            <div class="metric-subtitle">Status: <b>{alert_data.get('status')}</b></div>
        </div>
        """,
        unsafe_allow_html=True,
    )

st.markdown("---")

# Main Forensic Columns
left_col, right_col = st.columns([3, 2])

with left_col:
    st.subheader("Explainable AI (SHAP Feature Attributions)")
    st.markdown(
        "Feature contributions indicating which flow characteristics drove the classifier toward or away from this threat classification:"
    )

    influential = exp.get("influential_features", [])
    shap_chart = create_shap_bar_chart(influential)
    st.plotly_chart(shap_chart, use_container_width=True)

    summary_narrative = exp.get("summary_text")
    if summary_narrative:
        st.info(f"**Analyst Narrative:** {summary_narrative}")

    # Flow Characteristics Details
    st.subheader("Network Flow Parameters")
    flow_meta = {
        "Source IP / Port": f"{ev.get('src_ip')}:{ev.get('src_port')}",
        "Destination IP / Port": f"{ev.get('dst_ip')}:{ev.get('dst_port')}",
        "Protocol": ev.get("protocol"),
        "Duration": f"{ev.get('duration', 0):.3f} seconds",
        "Originator Payload": f"{ev.get('orig_bytes', 0):,} bytes",
        "Responder Payload": f"{ev.get('resp_bytes', 0):,} bytes",
        "Event ID": ev.get("id"),
    }
    st.json(flow_meta)

with right_col:
    st.subheader("Triage & Analyst Actions")
    current_status = alert_data.get("status", "NEW")
    st.markdown(f"Current Status: **`{current_status}`**")

    with st.form("update_status_form"):
        new_status = st.selectbox(
            "Change Alert Status",
            ["NEW", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"],
            index=["NEW", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"].index(current_status),
        )
        note_text = st.text_area("Analyst Investigation Note", placeholder="Enter findings, root cause, or resolution rationale...")
        submitted = st.form_submit_button("Save Status & Note", use_container_width=True)

        if submitted:
            success = backend_client.update_alert(alert_data["id"], new_status, note=note_text if note_text.strip() else None)
            if success:
                st.success("Alert status and note successfully updated!")
                st.rerun()
            else:
                st.error("Failed to update alert.")

    # Historical Analyst Notes
    st.subheader("Investigation Timeline & Notes")
    notes = alert_data.get("notes", [])
    if not notes:
        st.caption("No analyst notes recorded yet for this alert.")
    else:
        for n in reversed(notes):
            st.markdown(
                f"""
                <div style="background-color: #1E293B; border-left: 3px solid #38BDF8; padding: 8px 12px; margin-bottom: 8px; border-radius: 4px;">
                    <div style="font-size: 0.75rem; color: #94A3B8;"><b>{n.get('author')}</b> — {n.get('created_at', '')[:19].replace('T', ' ')}</div>
                    <div style="font-size: 0.9rem; color: #F8FAFC; margin-top: 4px;">{n.get('note')}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )

    # Class Probabilities Breakdown
    st.subheader("Prediction Probabilities")
    probs = pred.get("class_probabilities", {})
    if probs:
        p_df = pd.DataFrame(list(probs.items()), columns=["Threat Category", "Probability"])
        p_df["Probability"] = p_df["Probability"].map(lambda x: f"{x:.2%}")
        st.dataframe(p_df, use_container_width=True, hide_index=True)
