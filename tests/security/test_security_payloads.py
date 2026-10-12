"""Security tests: Malformed payloads, unauthorized mutations, and secret leakage prevention."""

from fastapi.testclient import TestClient
from threatsense.api.main import app
from threatsense.config import settings

client = TestClient(app)


def test_malformed_json_body_returns_422():
    res = client.post("/api/v1/analyze", content="not-a-valid-json", headers={"Content-Type": "application/json"})
    assert res.status_code == 422


def test_invalid_field_types_rejected():
    invalid_payload = {
        "src_ip": "10.0.0.1",
        "src_port": "not-a-port",
        "dst_ip": "10.0.0.2",
        "dst_port": 80,
    }
    res = client.post("/api/v1/analyze", json=invalid_payload)
    assert res.status_code == 422


def test_port_out_of_bounds_rejected():
    out_of_bounds = {
        "src_ip": "10.0.0.1",
        "src_port": 1234,
        "dst_ip": "10.0.0.2",
        "dst_port": 99999,  # Invalid port > 65535
    }
    res = client.post("/api/v1/analyze", json=out_of_bounds)
    assert res.status_code == 422


def test_invalid_alert_status_enum_rejected():
    bad_status = {"status": "DROP_ALL_TABLES"}
    res = client.patch("/api/v1/alerts/dummy-id", json=bad_status)
    assert res.status_code in (404, 422)


def test_error_responses_do_not_leak_internal_paths_or_secrets():
    # Trigger 404
    res = client.get("/api/v1/alerts/nonexistent-uuid-1234")
    assert res.status_code == 404
    body = res.text
    # Ensure no secret keys or database connection strings leaked
    assert settings.api.api_key not in body
    assert "password" not in body.lower()
    assert "traceback" not in body.lower()


def test_unauthorized_state_change_with_invalid_key_rejected():
    payload = {"status": "RESOLVED"}
    res = client.patch(
        "/api/v1/alerts/dummy-alert-id",
        json=payload,
        headers={"X-API-Key": "completely-invalid-attacker-key"},
    )
    assert res.status_code == 401
    assert "Invalid or missing API key" in res.json().get("detail", "")
