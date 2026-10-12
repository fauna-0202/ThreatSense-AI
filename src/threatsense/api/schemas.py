"""Pydantic request and response schemas for REST API."""

from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    status: str = "ok"
    app: str = "ThreatSense AI"
    version: str = "1.0.0"
    database_connected: bool
    models_loaded: bool
    sensor_state: str
    timestamp: datetime


class EventSummary(BaseModel):
    id: str
    timestamp: datetime
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    duration: float
    orig_bytes: int
    resp_bytes: int
    orig_pkts: int
    resp_pkts: int
    data_source: str
    event_fingerprint: str

    model_config = {"from_attributes": True}


class EventDetail(EventSummary):
    raw_payload: Optional[Dict[str, Any]] = None


class PaginatedEventsResponse(BaseModel):
    total: int
    skip: int
    limit: int
    events: List[EventSummary]


class ExplanationSummary(BaseModel):
    id: str
    status: str = Field(alias="explanation_status")
    summary: Optional[str] = Field(alias="summary_text")
    influential_features: List[Dict[str, Any]]

    model_config = {"from_attributes": True, "populate_by_name": True}


class PredictionDetail(BaseModel):
    id: str
    model_version: str
    predicted_class: str
    confidence: float
    anomaly_score: float
    is_anomaly: int
    uncertainty_state: str
    schema_status: str
    class_probabilities: Optional[Dict[str, float]] = None
    explanation: Optional[ExplanationSummary] = None

    model_config = {"from_attributes": True}


class AnalystNoteSchema(BaseModel):
    id: str
    author: str
    note: str
    created_at: datetime

    model_config = {"from_attributes": True}


class AlertSummary(BaseModel):
    id: str
    event_id: str
    prediction_id: str
    risk_score: float
    priority: str
    status: str
    created_at: datetime
    updated_at: datetime
    predicted_class: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None

    model_config = {"from_attributes": True}


class AlertDetail(BaseModel):
    id: str
    event_id: str
    prediction_id: str
    risk_score: float
    priority: str
    status: str
    contributing_signals: Optional[Dict[str, Any]] = None
    created_at: datetime
    updated_at: datetime
    event: Optional[EventSummary] = None
    prediction: Optional[PredictionDetail] = None
    notes: List[AnalystNoteSchema] = Field(default_factory=list)

    model_config = {"from_attributes": True}


class PaginatedAlertsResponse(BaseModel):
    total: int
    skip: int
    limit: int
    alerts: List[AlertDetail]


class UpdateAlertRequest(BaseModel):
    status: str = Field(..., pattern="^(NEW|INVESTIGATING|RESOLVED|FALSE_POSITIVE)$")
    note: Optional[str] = None
    actor: str = "secops_analyst"


class AnalyzeEventRequest(BaseModel):
    src_ip: str
    src_port: int = Field(..., ge=0, le=65535)
    dst_ip: str
    dst_port: int = Field(..., ge=0, le=65535)
    protocol: str = "TCP"
    duration: float = Field(default=0.0, ge=0.0)
    orig_bytes: int = Field(default=0, ge=0)
    resp_bytes: int = Field(default=0, ge=0)
    orig_pkts: int = Field(default=0, ge=0)
    resp_pkts: int = Field(default=0, ge=0)
    conn_state: Optional[str] = "SF"
    service: Optional[str] = "unknown"
    data_source: str = "api"


class SensorStatusResponse(BaseModel):
    sensor_id: str
    state: str
    mode: str
    interface: str
    is_alive: bool
    last_event_timestamp: Optional[datetime] = None
    events_ingested: int
    errors_count: int
    last_error: Optional[str] = None
    started_at: Optional[datetime] = None


class ModelInfo(BaseModel):
    name: str
    version: str
    type: str
    feature_schema_version: str
    classes: List[str]
    trained_at: Optional[str] = None
    status: str


class MetricsResponse(BaseModel):
    total_events: int
    total_alerts: int
    events_per_minute: float
    last_event_timestamp: Optional[str] = None
    priority_counts: Dict[str, int]
    status_counts: Dict[str, int]
    risk_distribution: Dict[str, int]
    class_distribution: Dict[str, int]
