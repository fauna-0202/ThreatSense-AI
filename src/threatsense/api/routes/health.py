"""Health check endpoint."""

from datetime import datetime, timezone
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import text

from threatsense.api.schemas import HealthResponse
from threatsense.api.dependencies import get_db_session
from sensor.health import sensor_tracker

router = APIRouter(tags=["Health"])


@router.get("/health", response_model=HealthResponse)
def health_check(db: Session = Depends(get_db_session)):
    # Check database
    db_ok = False
    try:
        db.execute(text("SELECT 1"))
        db_ok = True
    except Exception:
        db_ok = False

    sensor_status = sensor_tracker.get_status()

    return HealthResponse(
        status="ok" if db_ok else "degraded",
        app="ThreatSense AI",
        version="1.0.0",
        database_connected=db_ok,
        models_loaded=True,
        sensor_state=sensor_status.state.value,
        timestamp=datetime.now(timezone.utc),
    )
