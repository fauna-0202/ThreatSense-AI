"""Integration tests for all required FastAPI endpoints."""

from fastapi.testclient import TestClient
from threatsense.api.main import app

client = TestClient(app)


def test_get_health():
    res = client.get("/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ok"
    assert data["app"] == "ThreatSense AI"
    assert data["database_connected"] is True


def test_get_sensor_status():
    res = client.get("/api/v1/sensor/status")
    assert res.status_code == 200
    data = res.json()
    assert "state" in data
    assert "mode" in data


def test_get_events_pagination():
    res = client.get("/api/v1/events?skip=0&limit=10")
    assert res.status_code == 200
    data = res.json()
    assert "total" in data
    assert "events" in data
    assert isinstance(data["events"], list)


def test_get_alerts_pagination_and_filter():
    res = client.get("/api/v1/alerts?skip=0&limit=10")
    assert res.status_code == 200
    data = res.json()
    assert "total" in data
    assert "alerts" in data


def test_get_models():
    res = client.get("/api/v1/models")
    assert res.status_code == 200
    models = res.json()
    assert len(models) >= 2
    types = [m["type"] for m in models]
    assert "SUPERVISED_CLASSIFIER" in types
    assert "ANOMALY_DETECTOR" in types


def test_get_metrics():
    res = client.get("/api/v1/metrics")
    assert res.status_code == 200
    data = res.json()
    assert "total_events" in data
    assert "priority_counts" in data
    assert "risk_distribution" in data


def test_export_alerts_json_and_csv():
    res_json = client.get("/api/v1/export?format=json")
    assert res_json.status_code == 200
    assert "alerts" in res_json.json()

    res_csv = client.get("/api/v1/export?format=csv")
    assert res_csv.status_code == 200
    assert "text/csv" in res_csv.headers["content-type"]
    assert "alert_id" in res_csv.text
