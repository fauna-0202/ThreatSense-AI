"""Integration test for SecOps alert lifecycle and workflow status transitions."""

from fastapi.testclient import TestClient
from threatsense.api.main import app
from threatsense.storage.database import SessionLocal, init_db

client = TestClient(app)


def test_alert_lifecycle_workflow():
    init_db()

    # 1. Analyze an attack event via API to generate an alert
    attack_payload = {
        "src_ip": "172.16.0.45",
        "src_port": 38400,
        "dst_ip": "10.0.0.5",
        "dst_port": 80,
        "protocol": "TCP",
        "duration": 0.001,
        "orig_bytes": 40,
        "resp_bytes": 0,
        "orig_pkts": 12000,
        "resp_pkts": 0,
    }
    res = client.post("/api/v1/analyze", json=attack_payload)
    assert res.status_code == 200
    alert_id = res.json()["alert_id"]
    assert alert_id is not None

    # 2. Retrieve alert details
    res_get = client.get(f"/api/v1/alerts/{alert_id}")
    assert res_get.status_code == 200
    alert_body = res_get.json()
    assert alert_body["status"] == "NEW"

    # 3. Transition to INVESTIGATING with an analyst note
    patch_payload = {
        "status": "INVESTIGATING",
        "note": "Investigating high packet-rate DoS signature.",
        "actor": "secops_analyst_01",
    }
    res_patch = client.patch(f"/api/v1/alerts/{alert_id}", json=patch_payload)
    assert res_patch.status_code == 200
    updated_body = res_patch.json()
    assert updated_body["status"] == "INVESTIGATING"
    assert len(updated_body["notes"]) >= 1
    assert updated_body["notes"][-1]["author"] == "secops_analyst_01"

    # 4. Resolve alert
    res_resolve = client.patch(
        f"/api/v1/alerts/{alert_id}",
        json={"status": "RESOLVED", "note": "Mitigated at boundary firewall.", "actor": "secops_lead"},
    )
    assert res_resolve.status_code == 200
    assert res_resolve.json()["status"] == "RESOLVED"
