"""ThreatSense AI Configuration Loader."""

import os
from pathlib import Path
from typing import Any, Dict, List
import yaml
from pydantic import BaseModel, Field


class AppConfig(BaseModel):
    name: str = "ThreatSense AI"
    tagline: str = "Detect. Explain. Defend."
    version: str = "1.0.0"
    env: str = "development"
    debug: bool = True


class ApiConfig(BaseModel):
    host: str = "127.0.0.1"
    port: int = 8000
    prefix: str = "/api/v1"
    cors_origins: List[str] = [
        "http://localhost:8501",
        "http://127.0.0.1:8501",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
    ]
    api_key_header: str = "X-API-Key"
    api_key: str = "ts-demo-api-key-2026"
    rate_limit_per_minute: int = 120


class DatabaseConfig(BaseModel):
    url: str = "sqlite:///./data/threatsense.db"
    echo: bool = False
    pool_pre_ping: bool = True


class ModelsConfig(BaseModel):
    active_classifier_id: str = "rf_threatsense_v1"
    active_anomaly_id: str = "iforest_threatsense_v1"
    artifacts_dir: str = "./artifacts/models"
    reports_dir: str = "./artifacts/reports"
    feature_schema_version: str = "threatsense-features-v1"


class RiskBands(BaseModel):
    low: List[int] = [0, 24]
    moderate: List[int] = [25, 49]
    high: List[int] = [50, 74]
    critical: List[int] = [75, 100]


class RiskScoringConfig(BaseModel):
    bands: RiskBands = Field(default_factory=RiskBands)
    classifier_weight: float = 0.50
    anomaly_weight: float = 0.30
    protocol_weight: float = 0.20
    uncertainty_penalty_factor: float = 0.15
    min_confidence_threshold: float = 0.60
    anomaly_decision_threshold: float = -0.10


class ExplainabilityConfig(BaseModel):
    enabled: bool = True
    max_features: int = 5
    explainer_type: str = "tree"
    cache_size: int = 1000


class SensorConfig(BaseModel):
    id: str = "sensor-node-01"
    mode: str = "replay"  # live, replay, stopped
    authorized_interface: str = "eth0"
    zeek_bin: str = "zeek"
    log_dir: str = "./sensor/zeek_logs"
    conn_log_filename: str = "conn.log"
    replay_sample_file: str = "./data/samples/sample_zeek_conn.log"
    poll_interval_seconds: float = 1.0
    max_batch_size: int = 100
    log_format: str = "json"


class Settings(BaseModel):
    app: AppConfig = Field(default_factory=AppConfig)
    api: ApiConfig = Field(default_factory=ApiConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    models: ModelsConfig = Field(default_factory=ModelsConfig)
    risk_scoring: RiskScoringConfig = Field(default_factory=RiskScoringConfig)
    explainability: ExplainabilityConfig = Field(default_factory=ExplainabilityConfig)
    sensor: SensorConfig = Field(default_factory=SensorConfig)


def load_yaml(path: Path) -> Dict[str, Any]:
    if path.exists():
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
            return data or {}
    return {}


def get_settings() -> Settings:
    base_dir = Path(__file__).resolve().parent.parent.parent
    config_file = base_dir / "configs" / "default.yaml"
    sensor_config_file = base_dir / "configs" / "sensor.yaml"

    cfg = load_yaml(config_file)
    sensor_cfg = load_yaml(sensor_config_file)

    if "sensor" in sensor_cfg:
        cfg["sensor"] = sensor_cfg["sensor"]

    # Environment variable overrides
    env_name = os.getenv("THREATSENSE_ENV")
    if env_name:
        cfg.setdefault("app", {})["env"] = env_name

    debug_val = os.getenv("THREATSENSE_DEBUG")
    if debug_val is not None:
        cfg.setdefault("app", {})["debug"] = debug_val.lower() in ("true", "1", "yes")

    api_host = os.getenv("THREATSENSE_API_HOST")
    if api_host:
        cfg.setdefault("api", {})["host"] = api_host

    api_port = os.getenv("THREATSENSE_API_PORT")
    if api_port:
        try:
            cfg.setdefault("api", {})["port"] = int(api_port)
        except ValueError:
            pass

    db_url = os.getenv("DATABASE_URL")
    if db_url:
        cfg.setdefault("database", {})["url"] = db_url

    api_key = os.getenv("THREATSENSE_API_KEY")
    if api_key:
        cfg.setdefault("api", {})["api_key"] = api_key

    sensor_mode = os.getenv("SENSOR_MODE")
    if sensor_mode:
        cfg.setdefault("sensor", {})["mode"] = sensor_mode

    zeek_bin = os.getenv("ZEEK_BIN_PATH")
    if zeek_bin:
        cfg.setdefault("sensor", {})["zeek_bin"] = zeek_bin

    zeek_iface = os.getenv("ZEEK_INTERFACE")
    if zeek_iface:
        cfg.setdefault("sensor", {})["authorized_interface"] = zeek_iface

    zeek_log_dir = os.getenv("ZEEK_LOG_DIR")
    if zeek_log_dir:
        cfg.setdefault("sensor", {})["log_dir"] = zeek_log_dir

    artifacts_dir = os.getenv("MODEL_ARTIFACTS_DIR")
    if artifacts_dir:
        cfg.setdefault("models", {})["artifacts_dir"] = artifacts_dir

    reports_dir = os.getenv("REPORTS_DIR")
    if reports_dir:
        cfg.setdefault("models", {})["reports_dir"] = reports_dir

    return Settings(**cfg)


settings = get_settings()
