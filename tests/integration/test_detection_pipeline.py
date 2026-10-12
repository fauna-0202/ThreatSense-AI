"""Integration test for full end-to-end detection pipeline."""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from threatsense.storage.models import Base
from threatsense.ingestion.schemas import RawNetworkEvent
from threatsense.ingestion.normalizer import normalize_event
from threatsense.detection.engine import DetectionEngine


@pytest.fixture
def test_db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


def test_end_to_end_pipeline_analysis(test_db):
    engine = DetectionEngine()

    raw = RawNetworkEvent(
        ts=1697040000.0,
        src_ip="192.168.1.105",
        src_port=49152,
        dst_ip="10.0.0.1",
        dst_port=80,
        protocol="tcp",
        duration=0.5,
        orig_bytes=1200,
        resp_bytes=8400,
        orig_pkts=10,
        resp_pkts=15,
    )
    event = normalize_event(raw)

    result = engine.analyze_event(event, db=test_db)

    assert result["status"] == "PROCESSED"
    assert result["event_id"] is not None
    assert result["alert_id"] is not None
    assert "prediction" in result
    assert "predicted_class" in result["prediction"]
    assert "risk" in result
    assert result["risk"]["priority"] in ("LOW", "MODERATE", "HIGH", "CRITICAL")
    assert "uncertainty" in result
    assert "explanation" in result
    assert result["explanation"] is not None
    assert len(result["explanation"]["influential_features"]) > 0
