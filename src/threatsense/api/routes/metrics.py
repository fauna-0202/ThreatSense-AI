"""Operational metrics and SecOps telemetry endpoints."""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from threatsense.api.schemas import MetricsResponse
from threatsense.api.dependencies import get_db_session
from threatsense.storage.repository import MetricsRepository

router = APIRouter(prefix="/metrics", tags=["Metrics"])


@router.get("", response_model=MetricsResponse)
def get_metrics(db: Session = Depends(get_db_session)):
    metrics = MetricsRepository.get_dashboard_metrics(db)
    return MetricsResponse(
        total_events=metrics["total_events"],
        total_alerts=metrics["total_alerts"],
        events_per_minute=metrics["events_per_minute"],
        last_event_timestamp=metrics["last_event_timestamp"],
        priority_counts=metrics["priority_counts"],
        status_counts=metrics["status_counts"],
        risk_distribution=metrics["risk_distribution"],
        class_distribution=metrics["class_distribution"],
    )
