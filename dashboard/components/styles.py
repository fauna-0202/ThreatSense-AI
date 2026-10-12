"""Custom cybersecurity CSS and badge styles for Streamlit."""

import streamlit as st

CUSTOM_CSS = """
<style>
    /* Dark Cybersecurity Operations Theme */
    .stApp {
        background-color: #0B132B;
        color: #E2E8F0;
        font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, sans-serif;
    }
    
    header, [data-testid="stHeader"] {
        background-color: #0B132B;
    }
    
    [data-testid="stSidebar"] {
        background-color: #1C2541;
        border-right: 1px solid #3A506B;
    }
    
    /* Metric Cards */
    .metric-card {
        background-color: #1C2541;
        border: 1px solid #3A506B;
        border-radius: 8px;
        padding: 16px;
        margin-bottom: 12px;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.2);
    }
    .metric-title {
        font-size: 0.82rem;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        color: #94A3B8;
        margin-bottom: 4px;
    }
    .metric-value {
        font-size: 1.8rem;
        font-weight: 700;
        color: #F8FAFC;
    }
    .metric-subtitle {
        font-size: 0.75rem;
        color: #64748B;
        margin-top: 4px;
    }

    /* Badges */
    .badge {
        display: inline-block;
        padding: 2px 8px;
        font-size: 0.75rem;
        font-weight: 600;
        border-radius: 4px;
        text-transform: uppercase;
        letter-spacing: 0.03em;
    }
    .badge-critical { background-color: rgba(239, 68, 68, 0.2); color: #EF4444; border: 1px solid #EF4444; }
    .badge-high { background-color: rgba(249, 115, 22, 0.2); color: #F97316; border: 1px solid #F97316; }
    .badge-moderate { background-color: rgba(245, 158, 11, 0.2); color: #F59E0B; border: 1px solid #F59E0B; }
    .badge-low { background-color: rgba(16, 185, 129, 0.2); color: #10B981; border: 1px solid #10B981; }
    
    .badge-new { background-color: rgba(56, 189, 248, 0.2); color: #38BDF8; border: 1px solid #38BDF8; }
    .badge-investigating { background-color: rgba(234, 179, 8, 0.2); color: #EAB308; border: 1px solid #EAB308; }
    .badge-resolved { background-color: rgba(34, 197, 94, 0.2); color: #22C55E; border: 1px solid #22C55E; }
    .badge-false_positive { background-color: rgba(148, 163, 184, 0.2); color: #94A3B8; border: 1px solid #94A3B8; }

    /* Tables */
    div[data-testid="stDataFrame"] {
        border: 1px solid #3A506B;
        border-radius: 6px;
    }
</style>
"""


def apply_custom_styles():
    st.markdown(CUSTOM_CSS, unsafe_allow_html=True)


def get_priority_badge(priority: str) -> str:
    p = str(priority).upper()
    return f'<span class="badge badge-{p.lower()}">{p}</span>'


def get_status_badge(status: str) -> str:
    s = str(status).upper()
    return f'<span class="badge badge-{s.lower()}">{s}</span>'
