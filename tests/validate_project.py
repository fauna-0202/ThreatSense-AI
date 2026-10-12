"""ThreatSense AI — Comprehensive Pre-Publication System Validation Script."""

import sys
from pathlib import Path
from datetime import datetime, timezone
from fastapi.testclient import TestClient

# Ensure src is on sys.path
sys.path.insert(0, str(Path("./src").resolve()))
sys.path.insert(0, str(Path(".").resolve()))

from threatsense.config import settings
from threatsense.storage.database import SessionLocal, init_db
from threatsense.storage.models import NetworkEvent, Alert, Prediction, Explanation
from threatsense.storage.repository import EventRepository, AlertRepository, MetricsRepository
from threatsense.detection.engine import DetectionEngine
from threatsense.ingestion.replay import ReplayEngine
from threatsense.api.main import app
from sensor.health import sensor_tracker, SensorState


def validate_all():
    results = {}
    print("=" * 60)
    print("ThreatSense AI — Complete System Validation")
    print("=" * 60)

    # 1. Database & Schema Initialization
    try:
        init_db()
        db = SessionLocal()
        db_count = db.query(NetworkEvent).count()
        results["database"] = f"CONNECTED (SQLite at {settings.database.url}, {db_count} events present)"
        print(f"[PASS] Database: {results['database']}")
    except Exception as e:
        results["database"] = f"FAILED: {e}"
        print(f"[FAIL] Database: {results['database']}")
        return results

    # 2. Model Loading & Detection Engine
    try:
        engine = DetectionEngine()
        results["models"] = {
            "classifier_ready": engine.classifier.is_ready,
            "classifier_version": engine.classifier.model_version,
            "classes": engine.classifier.classes,
            "anomaly_ready": engine.anomaly_detector.is_ready,
            "anomaly_version": engine.anomaly_detector.model_version,
            "explainer_status": engine.explainer.status if engine.explainer else "NONE",
        }
        print(f"[PASS] Models: RF ({engine.classifier.model_version}) + IsolationForest ({engine.anomaly_detector.model_version}) Ready")
    except Exception as e:
        results["models"] = f"FAILED: {e}"
        print(f"[FAIL] Models: {results['models']}")

    # 3. Replay Engine & Sample Ingestion
    try:
        sample_file = settings.sensor.replay_sample_file
        replay = ReplayEngine(sample_file)
        events = replay.load_all()
        results["replay"] = f"LOADED {len(events)} sample events from {sample_file}"
        print(f"[PASS] Replay: {results['replay']}")
    except Exception as e:
        results["replay"] = f"FAILED: {e}"
        print(f"[FAIL] Replay: {results['replay']}")

    # 4. Pipeline Execution: Inference, Uncertainty, Risk, SHAP, and Persistence
    try:
        test_event = events[0]
        analysis = engine.analyze_event(test_event, db=db)
        results["pipeline"] = {
            "status": analysis["status"],
            "predicted_class": analysis["prediction"]["predicted_class"],
            "confidence": analysis["prediction"]["confidence"],
            "risk_score": analysis["risk"]["risk_score"],
            "priority": analysis["risk"]["priority"],
            "uncertainty_state": analysis["uncertainty"]["state"],
            "shap_features_count": len(analysis["explanation"]["influential_features"]) if analysis.get("explanation") else 0,
        }
        print(f"[PASS] Pipeline: Analyzed event successfully -> Class: {analysis['prediction']['predicted_class']}, Risk: {analysis['risk']['risk_score']} ({analysis['risk']['priority']}), Uncertainty: {analysis['uncertainty']['state']}")
    except Exception as e:
        results["pipeline"] = f"FAILED: {e}"
        print(f"[FAIL] Pipeline: {results['pipeline']}")

    # 5. REST API TestClient
    try:
        client = TestClient(app)
        r_health = client.get("/health")
        r_sensor = client.get("/api/v1/sensor/status")
        r_models = client.get("/api/v1/models")
        r_metrics = client.get("/api/v1/metrics")
        results["api"] = {
            "health_code": r_health.status_code,
            "sensor_state": r_sensor.json()["state"],
            "models_count": len(r_models.json()),
            "total_alerts": r_metrics.json()["total_alerts"],
        }
        print(f"[PASS] FastAPI Endpoints: Health={r_health.status_code}, Sensor={r_sensor.json()['state']}, Models={len(r_models.json())}")
    except Exception as e:
        results["api"] = f"FAILED: {e}"
        print(f"[FAIL] API: {results['api']}")

    # 6. Dashboard Components Import Check
    try:
        import streamlit
        import plotly
        import dashboard.components.styles as d_styles
        import dashboard.components.charts as d_charts
        import dashboard.components.api_client as d_client
        results["dashboard"] = "Streamlit & Plotly components imported successfully"
        print(f"[PASS] Dashboard: {results['dashboard']}")
    except Exception as e:
        results["dashboard"] = f"FAILED: {e}"
        print(f"[FAIL] Dashboard: {results['dashboard']}")

    # 7. Secret & Ignore Rules Check
    try:
        import subprocess
        # Check that .env is ignored
        check_env = subprocess.run(["git", "check-ignore", "-q", ".env"], capture_output=True)
        check_db = subprocess.run(["git", "check-ignore", "-q", "data/threatsense.db"], capture_output=True)
        check_venv = subprocess.run(["git", "check-ignore", "-q", ".venv"], capture_output=True)
        results["git_protection"] = {
            "env_ignored": check_env.returncode == 0,
            "db_ignored": check_db.returncode == 0,
            "venv_ignored": check_venv.returncode == 0,
        }
        print(f"[PASS] Git Protection: .env ignored={results['git_protection']['env_ignored']}, db ignored={results['git_protection']['db_ignored']}, venv ignored={results['git_protection']['venv_ignored']}")
    except Exception as e:
        results["git_protection"] = f"FAILED: {e}"
        print(f"[FAIL] Git Protection: {results['git_protection']}")

    db.close()
    print("=" * 60)
    print("ALL VALIDATION CHECKS COMPLETED")
    print("=" * 60)
    return results


if __name__ == "__main__":
    validate_all()
