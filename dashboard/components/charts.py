"""Plotly charts styled for dark cybersecurity operations interface."""

from typing import Dict, Any, List
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd

THEME_LAYOUT = dict(
    paper_bgcolor="#1C2541",
    plot_bgcolor="#1C2541",
    font=dict(color="#E2E8F0", family="Segoe UI, sans-serif"),
    margin=dict(l=20, r=20, t=30, b=20),
)


def create_priority_chart(priority_counts: Dict[str, int]) -> go.Figure:
    colors = {
        "CRITICAL": "#EF4444",
        "HIGH": "#F97316",
        "MODERATE": "#F59E0B",
        "LOW": "#10B981",
    }
    labels = list(priority_counts.keys())
    values = list(priority_counts.values())

    if not values or sum(values) == 0:
        labels = ["No Alerts"]
        values = [1]
        marker_colors = ["#475569"]
    else:
        marker_colors = [colors.get(l.upper(), "#38BDF8") for l in labels]

    fig = go.Figure(
        data=[
            go.Pie(
                labels=labels,
                values=values,
                hole=0.6,
                marker=dict(colors=marker_colors),
                textinfo="label+value",
                hoverinfo="label+value+percent",
            )
        ]
    )
    fig.update_layout(
        **THEME_LAYOUT,
        showlegend=False,
        height=240,
    )
    return fig


def create_risk_distribution_chart(risk_dist: Dict[str, int]) -> go.Figure:
    bands = ["Low\n(0-24)", "Moderate\n(25-49)", "High\n(50-74)", "Critical\n(75-100)"]
    counts = [
        risk_dist.get("low", 0),
        risk_dist.get("moderate", 0),
        risk_dist.get("high", 0),
        risk_dist.get("critical", 0),
    ]
    colors = ["#10B981", "#F59E0B", "#F97316", "#EF4444"]

    fig = go.Figure(
        data=[
            go.Bar(
                x=bands,
                y=counts,
                marker_color=colors,
                text=counts,
                textposition="auto",
            )
        ]
    )
    fig.update_layout(
        **THEME_LAYOUT,
        yaxis=dict(gridcolor="#3A506B", zeroline=False),
        xaxis=dict(gridcolor="#3A506B"),
        height=240,
    )
    return fig


def create_shap_bar_chart(influential_features: List[Dict[str, Any]]) -> go.Figure:
    if not influential_features:
        fig = go.Figure()
        fig.add_annotation(
            text="No feature explanation available",
            showarrow=False,
            font=dict(color="#94A3B8"),
        )
        fig.update_layout(**THEME_LAYOUT, height=260)
        return fig

    # Reverse order for top-to-bottom display
    feats = [f["feature"] for f in reversed(influential_features)]
    shaps = [f.get("shap_value", f.get("importance", 0.0)) for f in reversed(influential_features)]
    colors = ["#EF4444" if s > 0 else "#10B981" for s in shaps]

    fig = go.Figure(
        data=[
            go.Bar(
                y=feats,
                x=shaps,
                orientation="h",
                marker_color=colors,
                text=[f"{s:+.3f}" for s in shaps],
                textposition="auto",
            )
        ]
    )
    fig.update_layout(
        **THEME_LAYOUT,
        xaxis=dict(gridcolor="#3A506B", title="SHAP Impact (Toward Predicted Class)"),
        yaxis=dict(gridcolor="#3A506B"),
        height=280,
    )
    return fig


def create_confusion_matrix_heatmap(cm: List[List[int]], classes: List[str]) -> go.Figure:
    fig = px.imshow(
        cm,
        x=classes,
        y=classes,
        labels=dict(x="Predicted Class", y="Actual Ground Truth", color="Count"),
        color_continuous_scale="Blues",
        text_auto=True,
    )
    fig.update_layout(
        **THEME_LAYOUT,
        height=380,
        coloraxis_showscale=False,
    )
    return fig


def create_feature_importance_chart(importances: Dict[str, float]) -> go.Figure:
    sorted_items = sorted(importances.items(), key=lambda x: x[1], reverse=True)[:10]
    names = [x[0] for x in reversed(sorted_items)]
    vals = [x[1] for x in reversed(sorted_items)]

    fig = go.Figure(
        data=[
            go.Bar(
                y=names,
                x=vals,
                orientation="h",
                marker_color="#38BDF8",
                text=[f"{v:.3f}" for v in vals],
                textposition="auto",
            )
        ]
    )
    fig.update_layout(
        **THEME_LAYOUT,
        xaxis=dict(gridcolor="#3A506B", title="Gini Importance"),
        yaxis=dict(gridcolor="#3A506B"),
        height=340,
    )
    return fig
