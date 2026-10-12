"""Unit tests for timestamp normalization and event fingerprinting."""

from datetime import datetime, timezone
from threatsense.ingestion.normalizer import (
    normalize_timestamp,
    normalize_protocol,
    compute_event_fingerprint,
    normalize_event,
)
from threatsense.ingestion.schemas import RawNetworkEvent


def test_normalize_timestamp_from_epoch():
    epoch_ts = 1697040000.123
    dt = normalize_timestamp(epoch_ts)
    assert isinstance(dt, datetime)
    assert dt.tzinfo is not None
    assert int(dt.timestamp()) == 1697040000


def test_normalize_timestamp_from_iso_str():
    iso_str = "2026-10-11T12:00:00Z"
    dt = normalize_timestamp(iso_str)
    assert dt.year == 2026
    assert dt.month == 10
    assert dt.day == 11
    assert dt.hour == 12


def test_normalize_timestamp_invalid_fallback():
    dt = normalize_timestamp("not-a-valid-timestamp")
    assert isinstance(dt, datetime)


def test_normalize_protocol():
    assert normalize_protocol("tcp") == "TCP"
    assert normalize_protocol("UDP") == "UDP"
    assert normalize_protocol("6") == "TCP"
    assert normalize_protocol(17) == "UDP"
    assert normalize_protocol("1") == "ICMP"
    assert normalize_protocol(None) == "TCP"


def test_compute_event_fingerprint_deterministic():
    now = datetime(2026, 10, 11, 12, 0, 0, tzinfo=timezone.utc)
    fp1 = compute_event_fingerprint(now, "192.168.1.10", 4000, "10.0.0.1", 80, "TCP", 100, 200, 1.5)
    fp2 = compute_event_fingerprint(now, "192.168.1.10", 4000, "10.0.0.1", 80, "TCP", 100, 200, 1.5)
    assert fp1 == fp2
    assert len(fp1) == 64  # SHA-256


def test_normalize_event_produces_ingested():
    raw = RawNetworkEvent(
        ts=1697040000.0,
        src_ip="10.0.0.5",
        src_port=1234,
        dst_ip="10.0.0.1",
        dst_port=80,
        protocol="tcp",
        orig_bytes=500,
        resp_bytes=1000,
        orig_pkts=5,
        resp_pkts=10,
    )
    ingested = normalize_event(raw)
    assert ingested.src_ip == "10.0.0.5"
    assert ingested.dst_port == 80
    assert ingested.protocol == "TCP"
    assert len(ingested.event_fingerprint) == 64
