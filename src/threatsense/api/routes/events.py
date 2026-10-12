"""Network events querying endpoints."""

from datetime import datetime
from typing import Optional
from fastapi import APIRouter, Depends, Query, HTTPException, status
from sqlalchemy.orm import Session

from threatsense.api.schemas import PaginatedEventsResponse, EventDetail, EventSummary
from threatsense.api.dependencies import get_db_session
from threatsense.storage.repository import EventRepository

router = APIRouter(prefix="/events", tags=["Events"])


@router.get("", response_model=PaginatedEventsResponse)
def list_events(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    protocol: Optional[str] = Query(None),
    src_ip: Optional[str] = Query(None),
    dst_ip: Optional[str] = Query(None),
    start_time: Optional[datetime] = Query(None),
    end_time: Optional[datetime] = Query(None),
    db: Session = Depends(get_db_session),
):
    events, total = EventRepository.list_events(
        db=db,
        skip=skip,
        limit=limit,
        protocol=protocol,
        src_ip=src_ip,
        dst_ip=dst_ip,
        start_time=start_time,
        end_time=end_time,
    )
    summaries = [EventSummary.model_validate(e) for e in events]
    return PaginatedEventsResponse(
        total=total,
        skip=skip,
        limit=limit,
        events=summaries,
    )


@router.get("/{event_id}", response_model=EventDetail)
def get_event(event_id: str, db: Session = Depends(get_db_session)):
    event = EventRepository.get_by_id(db, event_id)
    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Network event '{event_id}' not found",
        )
    return EventDetail.model_validate(event)
