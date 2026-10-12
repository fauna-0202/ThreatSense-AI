"""Repository layer for database operations."""

from datetime import datetime, timezone, timedelta
from typing import List, Optional, Tuple, Dict, Any
from sqlalchemy.orm import Session, joinedload
from sqlalchemy import func, desc

from threatsense.storage.models import (
    NetworkEvent,
    Prediction,
    Alert,
    Explanation,
    AnalystNote,
    ModelVersion,
    AuditLog,
)


class EventRepository:
    @staticmethod
    def get_by_id(db: Session, event_id: str) -> Optional[NetworkEvent]:
        return db.query(NetworkEvent).filter(NetworkEvent.id == event_id).first()

    @staticmethod
    def get_by_fingerprint(db: Session, fingerprint: str) -> Optional[NetworkEvent]:
        return db.query(NetworkEvent).filter(NetworkEvent.event_fingerprint == fingerprint).first()

    @staticmethod
    def create(db: Session, event: NetworkEvent) -> NetworkEvent:
        db.add(event)
        db.commit()
        db.refresh(event)
        return event

    @staticmethod
    def list_events(
        db: Session,
        skip: int = 0,
        limit: int = 50,
        protocol: Optional[str] = None,
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> Tuple[List[NetworkEvent], int]:
        query = db.query(NetworkEvent)
        if protocol:
            query = query.filter(NetworkEvent.protocol == protocol.upper())
        if src_ip:
            query = query.filter(NetworkEvent.src_ip == src_ip)
        if dst_ip:
            query = query.filter(NetworkEvent.dst_ip == dst_ip)
        if start_time:
            query = query.filter(NetworkEvent.timestamp >= start_time)
        if end_time:
            query = query.filter(NetworkEvent.timestamp <= end_time)

        total = query.count()
        events = query.order_by(desc(NetworkEvent.timestamp)).offset(skip).limit(limit).all()
        return events, total


class AlertRepository:
    @staticmethod
    def get_by_id(db: Session, alert_id: str) -> Optional[Alert]:
        return (
            db.query(Alert)
            .options(
                joinedload(Alert.event),
                joinedload(Alert.prediction).joinedload(Prediction.explanation),
                joinedload(Alert.notes),
            )
            .filter(Alert.id == alert_id)
            .first()
        )

    @staticmethod
    def create(db: Session, alert: Alert) -> Alert:
        db.add(alert)
        db.commit()
        db.refresh(alert)
        return alert

    @staticmethod
    def list_alerts(
        db: Session,
        skip: int = 0,
        limit: int = 50,
        priority: Optional[str] = None,
        status: Optional[str] = None,
        min_risk: Optional[float] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> Tuple[List[Alert], int]:
        query = db.query(Alert).options(
            joinedload(Alert.event),
            joinedload(Alert.prediction),
        )
        if priority:
            query = query.filter(Alert.priority == priority.upper())
        if status:
            query = query.filter(Alert.status == status.upper())
        if min_risk is not None:
            query = query.filter(Alert.risk_score >= min_risk)
        if start_time:
            query = query.filter(Alert.created_at >= start_time)
        if end_time:
            query = query.filter(Alert.created_at <= end_time)

        total = query.count()
        alerts = query.order_by(desc(Alert.created_at)).offset(skip).limit(limit).all()
        return alerts, total

    @staticmethod
    def update_status(
        db: Session,
        alert_id: str,
        new_status: str,
        actor: str = "analyst",
        note_text: Optional[str] = None,
    ) -> Optional[Alert]:
        alert = db.query(Alert).filter(Alert.id == alert_id).first()
        if not alert:
            return None

        old_status = alert.status
        alert.status = new_status
        alert.updated_at = datetime.now(timezone.utc)

        if note_text:
            note = AnalystNote(alert_id=alert.id, author=actor, note=note_text)
            db.add(note)

        audit = AuditLog(
            actor=actor,
            action=f"UPDATE_ALERT_STATUS: {alert_id}",
            details={"old_status": old_status, "new_status": new_status, "note": note_text},
            outcome="SUCCESS",
        )
        db.add(audit)
        db.commit()
        db.refresh(alert)
        return alert


class MetricsRepository:
    @staticmethod
    def get_dashboard_metrics(db: Session) -> Dict[str, Any]:
        total_events = db.query(NetworkEvent).count()
        total_alerts = db.query(Alert).count()

        # Priority breakdown
        priority_counts = dict(
            db.query(Alert.priority, func.count(Alert.id)).group_by(Alert.priority).all()
        )

        # Status breakdown
        status_counts = dict(
            db.query(Alert.status, func.count(Alert.id)).group_by(Alert.status).all()
        )

        # Risk score distribution bands
        low_risk = db.query(Alert).filter(Alert.risk_score < 25).count()
        mod_risk = db.query(Alert).filter(Alert.risk_score >= 25, Alert.risk_score < 50).count()
        high_risk = db.query(Alert).filter(Alert.risk_score >= 50, Alert.risk_score < 75).count()
        crit_risk = db.query(Alert).filter(Alert.risk_score >= 75).count()

        # Predicted attack classes count
        class_counts = dict(
            db.query(Prediction.predicted_class, func.count(Prediction.id))
            .group_by(Prediction.predicted_class)
            .all()
        )

        # Last event timestamp
        last_event = db.query(NetworkEvent).order_by(desc(NetworkEvent.timestamp)).first()
        last_event_time = last_event.timestamp.isoformat() if last_event else None

        # Events per minute over last hour
        one_hour_ago = datetime.now(timezone.utc) - timedelta(hours=1)
        recent_events = (
            db.query(NetworkEvent).filter(NetworkEvent.timestamp >= one_hour_ago).count()
        )
        epm = round(recent_events / 60.0, 2)

        return {
            "total_events": total_events,
            "total_alerts": total_alerts,
            "events_per_minute": epm,
            "last_event_timestamp": last_event_time,
            "priority_counts": priority_counts,
            "status_counts": status_counts,
            "risk_distribution": {
                "low": low_risk,
                "moderate": mod_risk,
                "high": high_risk,
                "critical": crit_risk,
            },
            "class_distribution": class_counts,
        }
