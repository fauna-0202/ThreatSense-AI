"""On-demand event analysis endpoint."""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from threatsense.api.schemas import AnalyzeEventRequest
from threatsense.api.dependencies import get_db_session, verify_api_key
from threatsense.ingestion.parser import ZeekParser
from threatsense.detection.engine import DetectionEngine

router = APIRouter(prefix="/analyze", tags=["Detection"])

# Global detection engine instance
_engine = None


def get_engine() -> DetectionEngine:
    global _engine
    if _engine is None:
        _engine = DetectionEngine()
    return _engine


@router.post("")
def analyze_network_event(
    req: AnalyzeEventRequest,
    db: Session = Depends(get_db_session),
    authenticated: bool = Depends(verify_api_key),
):
    parser = ZeekParser()
    parse_res = parser.parse_dict(req.model_dump(), data_source="api")
    if not parse_res.success or not parse_res.event:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Malformed event payload: {parse_res.error}",
        )

    engine = get_engine()
    result = engine.analyze_event(parse_res.event, db=db)
    return result
