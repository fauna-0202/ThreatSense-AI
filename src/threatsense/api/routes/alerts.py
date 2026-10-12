"""Alerts querying and status workflow endpoints."""

from datetime import datetime
from typing import Optional
from fastapi import APIRouter, Depends, Query, HTTPException, status
from sqlalchemy.orm import Session

from threatsense.api.schemas import (
    PaginatedAlertsResponse,
    AlertDetail,
    UpdateAlertRequest,
)
from threatsense.api.dependencies import get_db_session, verify_api_key
from threatsense.storage.repository import AlertRepository

router = APIRouter(prefix="/alerts", tags=["Alerts"])


@router.get("", response_model=PaginatedAlertsResponse)
def list_alerts(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    priority: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    min_risk: Optional[float] = Query(None, ge=0, le=100),
    start_time: Optional[datetime] = Query(None),
    end_time: Optional[datetime] = Query(None),
    db: Session = Depends(get_db_session),
):
    alerts, total = AlertRepository.list_alerts(
        db=db,
        skip=skip,
        limit=limit,
        priority=priority,
        status=status,
        min_risk=min_risk,
        start_time=start_time,
        end_time=end_time,
    )

    alert_details = [AlertDetail.model_validate(a) for a in alerts]
    return PaginatedAlertsResponse(
        total=total,
        skip=skip,
        limit=limit,
        alerts=alert_details,
    )


@router.get("/{alert_id}", response_model=AlertDetail)
def get_alert(alert_id: str, db: Session = Depends(get_db_session)):
    alert = AlertRepository.get_by_id(db, alert_id)
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert '{alert_id}' not found",
        )
    return AlertDetail.model_validate(alert)


@router.patch("/{alert_id}", response_model=AlertDetail)
def update_alert(
    alert_id: str,
    req: UpdateAlertRequest,
    db: Session = Depends(get_db_session),
    authenticated: bool = Depends(verify_api_key),
):
    updated = AlertRepository.update_status(
        db=db,
        alert_id=alert_id,
        new_status=req.status,
        actor=req.actor,
        note_text=req.note,
    )
    if not updated:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert '{alert_id}' not found",
        )
    return AlertDetail.model_validate(updated)
