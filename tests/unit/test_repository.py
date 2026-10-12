"""Unit tests for database models and repository operations."""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from threatsense.storage.models import (
    Base,
    NetworkEvent,
    Prediction,
    Alert,
    AnalystNote,
)
from threatsense.storage.repository import EventRepository, AlertRepository


@pytest.fixture
def in_memory_db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


def test_create_and_query_network_event(in_memory_db):
    event = NetworkEvent(
        src_ip="192.168.1.10",
        src_port=4444,
        dst_ip="10.0.0.1",
        dst_port=80,
        protocol="TCP",
        duration=1.2,
        orig_bytes=500,
        resp_bytes=2000,
        event_fingerprint="unique-hash-12345",
    )
    saved = EventRepository.create(in_memory_db, event)
    assert saved.id is not None

    queried = EventRepository.get_by_id(in_memory_db, saved.id)
    assert queried is not None
    assert queried.src_ip == "192.168.1.10"
    assert queried.event_fingerprint == "unique-hash-12345"


def test_create_and_update_alert_status(in_memory_db):
    event = NetworkEvent(
        src_ip="10.0.0.99",
        src_port=5000,
        dst_ip="10.0.0.1",
        dst_port=22,
        protocol="TCP",
        event_fingerprint="fp-alert-test-01",
    )
    in_memory_db.add(event)
    in_memory_db.commit()

    pred = Prediction(
        event_id=event.id,
        model_version="rf_threatsense_v1",
        predicted_class="BruteForce",
        confidence=0.88,
        anomaly_score=-0.25,
    )
    in_memory_db.add(pred)
    in_memory_db.commit()

    alert = Alert(
        event_id=event.id,
        prediction_id=pred.id,
        risk_score=78.5,
        priority="CRITICAL",
        status="NEW",
    )
    saved_alert = AlertRepository.create(in_memory_db, alert)
    assert saved_alert.status == "NEW"

    # Update status to INVESTIGATING with an analyst note
    updated = AlertRepository.update_status(
        in_memory_db,
        saved_alert.id,
        new_status="INVESTIGATING",
        actor="lead_analyst",
        note_text="Investigating repeated SSH authentication spikes.",
    )
    assert updated.status == "INVESTIGATING"

    # Verify joined relationships
    full_alert = AlertRepository.get_by_id(in_memory_db, saved_alert.id)
    assert len(full_alert.notes) == 1
    assert full_alert.notes[0].author == "lead_analyst"
    assert full_alert.prediction.predicted_class == "BruteForce"
