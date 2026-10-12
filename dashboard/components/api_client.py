"""API Client for Dashboard communication with backend."""

import os
import requests
from typing import Dict, Any, Optional, List
from threatsense.config import settings
from threatsense.storage.database import SessionLocal
from threatsense.storage.repository import EventRepository, AlertRepository, MetricsRepository
from sensor.health import sensor_tracker

API_BASE_URL = f"http://{settings.api.host}:{settings.api.port}/api/v1"


class DashboardBackendClient:
    """Communicates with FastAPI backend, with graceful fallback to direct DB/modules."""

    def __init__(self, base_url: str = API_BASE_URL, api_key: Optional[str] = None):
        self.base_url = base_url
        self.api_key = api_key or settings.api.api_key
        self.headers = {"X-API-Key": self.api_key}

    def _is_api_alive(self) -> bool:
        try:
            r = requests.get(f"http://{settings.api.host}:{settings.api.port}/health", timeout=1.0)
            return r.status_code == 200
        except Exception:
            return False

    def get_metrics(self) -> Dict[str, Any]:
        try:
            r = requests.get(f"{self.base_url}/metrics", headers=self.headers, timeout=2.0)
            if r.status_code == 200:
                return r.json()
        except Exception:
            pass

        # Fallback to direct repository query
        db = SessionLocal()
        try:
            return MetricsRepository.get_dashboard_metrics(db)
        finally:
            db.close()

    def get_sensor_status(self) -> Dict[str, Any]:
        try:
            r = requests.get(f"{self.base_url}/sensor/status", headers=self.headers, timeout=2.0)
            if r.status_code == 200:
                return r.json()
        except Exception:
            pass

        status = sensor_tracker.get_status()
        return status.model_dump()

    def get_events(self, limit: int = 50, protocol: Optional[str] = None) -> List[Dict[str, Any]]:
        try:
            params = {"limit": limit}
            if protocol:
                params["protocol"] = protocol
            r = requests.get(f"{self.base_url}/events", params=params, headers=self.headers, timeout=2.0)
            if r.status_code == 200:
                return r.json().get("events", [])
        except Exception:
            pass

        db = SessionLocal()
        try:
            evs, _ = EventRepository.list_events(db, limit=limit, protocol=protocol)
            return [
                {
                    "id": e.id,
                    "timestamp": e.timestamp.isoformat(),
                    "src_ip": e.src_ip,
                    "src_port": e.src_port,
                    "dst_ip": e.dst_ip,
                    "dst_port": e.dst_port,
                    "protocol": e.protocol,
                    "duration": e.duration,
                    "orig_bytes": e.orig_bytes,
                    "resp_bytes": e.resp_bytes,
                    "data_source": e.data_source,
                }
                for e in evs
            ]
        finally:
            db.close()

    def get_alerts(self, limit: int = 50, priority: Optional[str] = None, status: Optional[str] = None) -> List[Dict[str, Any]]:
        try:
            params = {"limit": limit}
            if priority:
                params["priority"] = priority
            if status:
                params["status"] = status
            r = requests.get(f"{self.base_url}/alerts", params=params, headers=self.headers, timeout=2.0)
            if r.status_code == 200:
                return r.json().get("alerts", [])
        except Exception:
            pass

        db = SessionLocal()
        try:
            als, _ = AlertRepository.list_alerts(db, limit=limit, priority=priority, status=status)
            out = []
            for a in als:
                out.append({
                    "id": a.id,
                    "event_id": a.event_id,
                    "prediction_id": a.prediction_id,
                    "risk_score": a.risk_score,
                    "priority": a.priority,
                    "status": a.status,
                    "created_at": a.created_at.isoformat() if a.created_at else None,
                    "updated_at": a.updated_at.isoformat() if a.updated_at else None,
                    "contributing_signals": a.contributing_signals,
                    "event": {
                        "src_ip": a.event.src_ip,
                        "src_port": a.event.src_port,
                        "dst_ip": a.event.dst_ip,
                        "dst_port": a.event.dst_port,
                        "protocol": a.event.protocol,
                        "duration": a.event.duration,
                    } if a.event else None,
                    "prediction": {
                        "predicted_class": a.prediction.predicted_class,
                        "confidence": a.prediction.confidence,
                        "anomaly_score": a.prediction.anomaly_score,
                        "uncertainty_state": a.prediction.uncertainty_state,
                        "explanation": {
                            "summary_text": a.prediction.explanation.summary_text if a.prediction.explanation else None,
                            "influential_features": a.prediction.explanation.influential_features if a.prediction.explanation else [],
                        } if a.prediction and a.prediction.explanation else None,
                    } if a.prediction else None,
                    "notes": [{"author": n.author, "note": n.note, "created_at": n.created_at.isoformat()} for n in a.notes],
                })
            return out
        finally:
            db.close()

    def get_alert_detail(self, alert_id: str) -> Optional[Dict[str, Any]]:
        try:
            r = requests.get(f"{self.base_url}/alerts/{alert_id}", headers=self.headers, timeout=2.0)
            if r.status_code == 200:
                return r.json()
        except Exception:
            pass

        db = SessionLocal()
        try:
            a = AlertRepository.get_by_id(db, alert_id)
            if not a:
                return None
            return {
                "id": a.id,
                "event_id": a.event_id,
                "prediction_id": a.prediction_id,
                "risk_score": a.risk_score,
                "priority": a.priority,
                "status": a.status,
                "created_at": a.created_at.isoformat() if a.created_at else None,
                "updated_at": a.updated_at.isoformat() if a.updated_at else None,
                "contributing_signals": a.contributing_signals,
                "event": {
                    "id": a.event.id,
                    "src_ip": a.event.src_ip,
                    "src_port": a.event.src_port,
                    "dst_ip": a.event.dst_ip,
                    "dst_port": a.event.dst_port,
                    "protocol": a.event.protocol,
                    "duration": a.event.duration,
                    "orig_bytes": a.event.orig_bytes,
                    "resp_bytes": a.event.resp_bytes,
                } if a.event else None,
                "prediction": {
                    "id": a.prediction.id,
                    "model_version": a.prediction.model_version,
                    "predicted_class": a.prediction.predicted_class,
                    "confidence": a.prediction.confidence,
                    "anomaly_score": a.prediction.anomaly_score,
                    "uncertainty_state": a.prediction.uncertainty_state,
                    "class_probabilities": a.prediction.class_probabilities,
                    "explanation": {
                        "summary_text": a.prediction.explanation.summary_text if a.prediction.explanation else None,
                        "influential_features": a.prediction.explanation.influential_features if a.prediction.explanation else [],
                    } if a.prediction and a.prediction.explanation else None,
                } if a.prediction else None,
                "notes": [{"id": n.id, "author": n.author, "note": n.note, "created_at": n.created_at.isoformat()} for n in a.notes],
            }
        finally:
            db.close()

    def update_alert(self, alert_id: str, new_status: str, note: Optional[str] = None) -> bool:
        try:
            payload = {"status": new_status, "note": note, "actor": "secops_analyst"}
            r = requests.patch(f"{self.base_url}/alerts/{alert_id}", json=payload, headers=self.headers, timeout=2.0)
            if r.status_code == 200:
                return True
        except Exception:
            pass

        db = SessionLocal()
        try:
            up = AlertRepository.update_status(db, alert_id, new_status, actor="secops_analyst", note_text=note)
            return up is not None
        finally:
            db.close()


backend_client = DashboardBackendClient()
