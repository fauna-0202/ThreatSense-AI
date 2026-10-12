"""Sensor health monitoring and state tracking."""

from datetime import datetime, timezone
from enum import Enum
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field


class SensorState(str, Enum):
    CONNECTED = "Connected"
    STARTING = "Starting"
    STOPPED = "Stopped"
    PERMISSION_REQUIRED = "Permission Required"
    ERROR = "Error"
    REPLAY_MODE = "Replay Mode"


class SensorHealthStatus(BaseModel):
    sensor_id: str
    state: SensorState
    mode: str  # live | replay | stopped
    interface: str
    is_alive: bool
    last_event_timestamp: Optional[datetime] = None
    events_ingested: int = 0
    errors_count: int = 0
    last_error: Optional[str] = None
    started_at: Optional[datetime] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class SensorHealthTracker:
    def __init__(self, sensor_id: str = "sensor-node-01", mode: str = "replay", interface: str = "eth0"):
        self.sensor_id = sensor_id
        self.mode = mode
        self.interface = interface
        self.state = SensorState.REPLAY_MODE if mode == "replay" else SensorState.STOPPED
        self.is_alive = False
        self.last_event_timestamp: Optional[datetime] = None
        self.events_ingested = 0
        self.errors_count = 0
        self.last_error: Optional[str] = None
        self.started_at: Optional[datetime] = None
        self.metadata: Dict[str, Any] = {}

    def set_state(self, state: SensorState, error: Optional[str] = None):
        self.state = state
        if state in (SensorState.CONNECTED, SensorState.REPLAY_MODE):
            self.is_alive = True
            if not self.started_at:
                self.started_at = datetime.now(timezone.utc)
        else:
            self.is_alive = False

        if error:
            self.last_error = error
            self.errors_count += 1

    def record_event(self):
        self.events_ingested += 1
        self.last_event_timestamp = datetime.now(timezone.utc)

    def get_status(self) -> SensorHealthStatus:
        return SensorHealthStatus(
            sensor_id=self.sensor_id,
            state=self.state,
            mode=self.mode,
            interface=self.interface,
            is_alive=self.is_alive,
            last_event_timestamp=self.last_event_timestamp,
            events_ingested=self.events_ingested,
            errors_count=self.errors_count,
            last_error=self.last_error,
            started_at=self.started_at,
            metadata=self.metadata,
        )


sensor_tracker = SensorHealthTracker()
