"""Export endpoint for SIEM/SOAR integration."""

import csv
import io
from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy.orm import Session
from threatsense.api.dependencies import get_db_session
from threatsense.storage.repository import AlertRepository

router = APIRouter(prefix="/export", tags=["Export"])


@router.get("")
def export_alerts(
    format: str = Query("json", pattern="^(json|csv)$"),
    limit: int = Query(500, ge=1, le=5000),
    db: Session = Depends(get_db_session),
):
    alerts, _ = AlertRepository.list_alerts(db=db, skip=0, limit=limit)

    if format == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "alert_id",
            "created_at",
            "priority",
            "status",
            "risk_score",
            "predicted_class",
            "confidence",
            "uncertainty_state",
            "src_ip",
            "src_port",
            "dst_ip",
            "dst_port",
            "protocol",
        ])
        for a in alerts:
            pred = a.prediction
            ev = a.event
            writer.writerow([
                a.id,
                a.created_at.isoformat() if a.created_at else "",
                a.priority,
                a.status,
                a.risk_score,
                pred.predicted_class if pred else "",
                pred.confidence if pred else "",
                pred.uncertainty_state if pred else "",
                ev.src_ip if ev else "",
                ev.src_port if ev else "",
                ev.dst_ip if ev else "",
                ev.dst_port if ev else "",
                ev.protocol if ev else "",
            ])
        output.seek(0)
        return Response(
            content=output.getvalue(),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=threatsense_alerts.csv"},
        )

    # JSON export
    data = []
    for a in alerts:
        pred = a.prediction
        ev = a.event
        data.append({
            "alert_id": a.id,
            "created_at": a.created_at.isoformat() if a.created_at else None,
            "priority": a.priority,
            "status": a.status,
            "risk_score": a.risk_score,
            "predicted_class": pred.predicted_class if pred else None,
            "confidence": pred.confidence if pred else None,
            "anomaly_score": pred.anomaly_score if pred else None,
            "uncertainty_state": pred.uncertainty_state if pred else None,
            "event": {
                "src_ip": ev.src_ip if ev else None,
                "src_port": ev.src_port if ev else None,
                "dst_ip": ev.dst_ip if ev else None,
                "dst_port": ev.dst_port if ev else None,
                "protocol": ev.protocol if ev else None,
            } if ev else None,
        })
    return {"exported_records": len(data), "alerts": data}
