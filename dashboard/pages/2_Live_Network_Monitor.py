"""Page 2: Live Network Monitor."""

import streamlit as st
import pandas as pd
from dashboard.components.styles import apply_custom_styles
from dashboard.components.api_client import backend_client

st.set_page_config(page_title="Live Network Monitor — ThreatSense AI", page_icon="📡", layout="wide")
apply_custom_styles()

st.title("Live Network Monitor")
st.markdown("Real-time telemetry and network flow inspection across authorized interfaces.")

sensor_info = backend_client.get_sensor_status()
is_live = sensor_info.get("is_alive", False)
sensor_state = sensor_info.get("state", "Stopped")

# State notice
if not is_live:
    st.warning(f"⚠️ Sensor state is currently **{sensor_state}**. Real-time updates paused. Displaying recorded event history.")
else:
    st.success(f"🟢 Sensor actively streaming in **{sensor_info.get('mode', '').upper()}** mode on interface `{sensor_info.get('interface', '')}`.")

# Filters Row
c1, c2, c3, c4 = st.columns([2, 1, 1, 1])

with c1:
    search_query = st.text_input("🔍 Search IP, Port or Class", placeholder="e.g. 192.168.1.101, 80, DoS")

with c2:
    proto_filter = st.selectbox("Protocol", ["ALL", "TCP", "UDP", "ICMP"])

with c3:
    limit_count = st.selectbox("Record Limit", [25, 50, 100, 200], index=1)

with c4:
    st.markdown("<div style='height: 28px;'></div>", unsafe_allow_html=True)
    if st.button("🔄 Refresh Telemetry", use_container_width=True):
        st.rerun()

# Fetch Alerts & Events
alerts = backend_client.get_alerts(limit=limit_count)

if not alerts:
    st.info("No network events found. Use the sidebar on the main page to trigger an offline replay batch.")
else:
    rows = []
    for a in alerts:
        ev = a.get("event") or {}
        pred = a.get("prediction") or {}

        src_str = f"{ev.get('src_ip', '')}:{ev.get('src_port', '')}"
        dst_str = f"{ev.get('dst_ip', '')}:{ev.get('dst_port', '')}"
        proto = ev.get("protocol", "TCP")
        threat = pred.get("predicted_class", "UNKNOWN")
        risk = a.get("risk_score", 0.0)
        pri = a.get("priority", "LOW")
        conf = pred.get("confidence", 0.0)
        uncert = pred.get("uncertainty_state", "CONFIDENT")

        # Apply search and filters
        if proto_filter != "ALL" and proto != proto_filter:
            continue

        if search_query:
            q = search_query.lower()
            combined_text = f"{src_str} {dst_str} {proto} {threat}".lower()
            if q not in combined_text:
                continue

        rows.append({
            "Timestamp": str(a.get("created_at", ""))[:19].replace("T", " "),
            "Protocol": proto,
            "Source IP:Port": src_str,
            "Destination IP:Port": dst_str,
            "Duration (s)": round(ev.get("duration", 0.0), 3),
            "Orig Bytes": ev.get("orig_bytes", 0),
            "Resp Bytes": ev.get("resp_bytes", 0),
            "Predicted Threat": threat,
            "Risk Score": f"{risk:.1f}",
            "Priority": pri,
            "Confidence": f"{conf:.1%}",
            "Uncertainty State": uncert,
        })

    if not rows:
        st.warning("No network flows matched the selected filters.")
    else:
        df = pd.DataFrame(rows)
        st.dataframe(df, use_container_width=True, hide_index=True)
        st.caption(f"Displaying {len(rows)} connections.")
