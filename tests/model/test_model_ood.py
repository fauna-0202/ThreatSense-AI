"""ML test for model uncertainty and out-of-distribution behavior on unfamiliar inputs."""

import pandas as pd
from threatsense.detection.engine import DetectionEngine
from threatsense.features.schema import FEATURE_NAMES
from threatsense.ingestion.schemas import IngestedEvent
from datetime import datetime, timezone


def test_deliberately_unfamiliar_input_triggers_uncertainty():
    engine = DetectionEngine()

    # Extreme outlier flow: duration of 80,000 seconds with massive abnormal byte ratio
    ood_event = IngestedEvent(
        timestamp=datetime.now(timezone.utc),
        src_ip="203.0.113.199",
        src_port=49999,
        dst_ip="198.51.100.2",
        dst_port=65530,
        protocol="TCP",
        duration=75000.0,
        orig_bytes=50000000,
        resp_bytes=10,
        orig_pkts=800000,
        resp_pkts=2,
        data_source="synthetic_test",
        event_fingerprint="deliberate-ood-fingerprint-001",
    )

    result = engine.analyze_event(ood_event)

    assert result["status"] == "PROCESSED"
    # Anomaly detector should flag anomaly
    assert result["anomaly"]["is_anomaly"] == 1
    # Uncertainty state should be elevated
    assert result["uncertainty"]["state"] in ("OUT_OF_DISTRIBUTION", "HIGH_UNCERTAINTY", "DETECTOR_DISAGREEMENT")
    assert result["uncertainty"]["review_required"] is True
