"""SQLAlchemy models for ThreatSense AI."""

from datetime import datetime, timezone
import uuid
from sqlalchemy import (
    Column,
    String,
    Float,
    Integer,
    DateTime,
    ForeignKey,
    Text,
    JSON,
    Index,
)
from sqlalchemy.orm import relationship
from threatsense.storage.database import Base


def generate_uuid() -> str:
    return str(uuid.uuid4())


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


class NetworkEvent(Base):
    __tablename__ = "network_events"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    timestamp = Column(DateTime, default=now_utc, index=True, nullable=False)
    src_ip = Column(String(45), nullable=False, index=True)
    src_port = Column(Integer, nullable=False)
    dst_ip = Column(String(45), nullable=False, index=True)
    dst_port = Column(Integer, nullable=False, index=True)
    protocol = Column(String(16), nullable=False, index=True)
    conn_state = Column(String(32), nullable=True)
    duration = Column(Float, default=0.0)
    orig_bytes = Column(Integer, default=0)
    resp_bytes = Column(Integer, default=0)
    orig_pkts = Column(Integer, default=0)
    resp_pkts = Column(Integer, default=0)
    data_source = Column(String(32), default="zeek_conn_log")  # zeek, replay, pcap, api
    event_fingerprint = Column(String(64), unique=True, index=True, nullable=False)
    raw_payload = Column(JSON, nullable=True)

    predictions = relationship("Prediction", back_populates="event", cascade="all, delete-orphan")
    alerts = relationship("Alert", back_populates="event", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_event_src_dst", "src_ip", "dst_ip"),
        Index("idx_event_time_proto", "timestamp", "protocol"),
    )


class Prediction(Base):
    __tablename__ = "predictions"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    event_id = Column(String(36), ForeignKey("network_events.id", ondelete="CASCADE"), nullable=False, index=True)
    model_version = Column(String(64), nullable=False, index=True)
    predicted_class = Column(String(64), nullable=False, index=True)
    confidence = Column(Float, default=0.0, nullable=False)
    class_probabilities = Column(JSON, nullable=True)
    anomaly_score = Column(Float, default=0.0, nullable=False)
    is_anomaly = Column(Integer, default=0)  # 1 if anomaly, 0 if normal
    uncertainty_state = Column(String(64), default="CONFIDENT", index=True)  # CONFIDENT, UNCERTAIN, OOD, DISAGREEMENT
    schema_status = Column(String(64), default="VALID")
    created_at = Column(DateTime, default=now_utc, index=True)

    event = relationship("NetworkEvent", back_populates="predictions")
    alert = relationship("Alert", back_populates="prediction", uselist=False, cascade="all, delete-orphan")
    explanation = relationship("Explanation", back_populates="prediction", uselist=False, cascade="all, delete-orphan")


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    event_id = Column(String(36), ForeignKey("network_events.id", ondelete="CASCADE"), nullable=False, index=True)
    prediction_id = Column(String(36), ForeignKey("predictions.id", ondelete="CASCADE"), nullable=False, index=True)
    risk_score = Column(Float, nullable=False, index=True)  # 0 to 100
    priority = Column(String(16), nullable=False, index=True)  # LOW, MODERATE, HIGH, CRITICAL
    status = Column(String(32), default="NEW", index=True)  # NEW, INVESTIGATING, RESOLVED, FALSE_POSITIVE
    contributing_signals = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=now_utc, index=True)
    updated_at = Column(DateTime, default=now_utc, onupdate=now_utc)

    event = relationship("NetworkEvent", back_populates="alerts")
    prediction = relationship("Prediction", back_populates="alert")
    notes = relationship("AnalystNote", back_populates="alert", cascade="all, delete-orphan")


class Explanation(Base):
    __tablename__ = "explanations"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    prediction_id = Column(String(36), ForeignKey("predictions.id", ondelete="CASCADE"), nullable=False, index=True)
    influential_features = Column(JSON, nullable=False)  # list of {feature, contribution, value, human_desc}
    explanation_metadata = Column(JSON, nullable=True)
    summary_text = Column(Text, nullable=True)
    explanation_status = Column(String(32), default="SUCCESS")  # SUCCESS, FALLBACK, FAILED
    created_at = Column(DateTime, default=now_utc)

    prediction = relationship("Prediction", back_populates="explanation")


class AnalystNote(Base):
    __tablename__ = "analyst_notes"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    alert_id = Column(String(36), ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False, index=True)
    author = Column(String(64), default="secops_analyst", nullable=False)
    note = Column(Text, nullable=False)
    created_at = Column(DateTime, default=now_utc, index=True)

    alert = relationship("Alert", back_populates="notes")


class ModelVersion(Base):
    __tablename__ = "model_versions"

    id = Column(String(64), primary_key=True)  # e.g. "rf_threatsense_v1"
    model_type = Column(String(32), nullable=False)  # SUPERVISED_CLASSIFIER, ANOMALY_DETECTOR
    version = Column(String(32), nullable=False)
    feature_schema_version = Column(String(64), nullable=False)
    dataset_metadata = Column(JSON, nullable=True)
    evaluation_report_reference = Column(String(255), nullable=True)
    created_at = Column(DateTime, default=now_utc)
    is_active = Column(Integer, default=1)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    actor = Column(String(64), nullable=False, index=True)
    action = Column(String(128), nullable=False, index=True)
    details = Column(JSON, nullable=True)
    outcome = Column(String(32), default="SUCCESS")
    timestamp = Column(DateTime, default=now_utc, index=True)
