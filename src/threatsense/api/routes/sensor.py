"""Sensor status and capture management endpoints."""

from fastapi import APIRouter, Depends, Query, BackgroundTasks
from sqlalchemy.orm import Session
from threatsense.api.schemas import SensorStatusResponse
from threatsense.api.dependencies import get_db_session, verify_api_key
from sensor.health import sensor_tracker, SensorState
from threatsense.ingestion.replay import ReplayEngine
from threatsense.storage.database import SessionLocal
from threatsense.config import settings
from threatsense.logging import logger

router = APIRouter(prefix="/sensor", tags=["Sensor"])


def _run_replay_task(sample_file: str, limit: int = 50):
    from threatsense.detection.engine import DetectionEngine
    db = SessionLocal()
    engine = DetectionEngine()
    replay = ReplayEngine(sample_file)
    try:
        sensor_tracker.set_state(SensorState.REPLAY_MODE)
        count = 0
        for event in replay.stream_events(delay_seconds=0.0):
            engine.analyze_event(event, db=db)
            sensor_tracker.record_event()
            count += 1
            if count >= limit:
                break
        logger.info(f"Replayed {count} sample events into pipeline.")
    except Exception as e:
        logger.error(f"Replay task failed: {e}")
        sensor_tracker.set_state(SensorState.ERROR, error=str(e))
    finally:
        db.close()


@router.get("/status", response_model=SensorStatusResponse)
def get_sensor_status():
    status = sensor_tracker.get_status()
    return SensorStatusResponse(
        sensor_id=status.sensor_id,
        state=status.state.value,
        mode=status.mode,
        interface=status.interface,
        is_alive=status.is_alive,
        last_event_timestamp=status.last_event_timestamp,
        events_ingested=status.events_ingested,
        errors_count=status.errors_count,
        last_error=status.last_error,
        started_at=status.started_at,
    )


@router.post("/replay")
def trigger_replay(
    background_tasks: BackgroundTasks,
    limit: int = Query(50, ge=1, le=500),
    authenticated: bool = Depends(verify_api_key),
):
    """Triggers offline replay of sample events in background."""
    sample_file = settings.sensor.replay_sample_file
    background_tasks.add_task(_run_replay_task, sample_file, limit)
    return {"status": "started", "message": f"Queued replay of up to {limit} sample events"}
