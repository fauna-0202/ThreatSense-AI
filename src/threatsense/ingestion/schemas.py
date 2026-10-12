"""Ingestion schemas and validation models."""

from datetime import datetime, timezone
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field, field_validator


class RawNetworkEvent(BaseModel):
    """Raw incoming network connection event from sensor or client."""
    ts: Optional[float] = None
    timestamp: Optional[datetime] = None
    src_ip: str = Field(default="", alias="id.orig_h")
    src_port: int = Field(default=0, alias="id.orig_p")
    dst_ip: str = Field(default="", alias="id.resp_h")
    dst_port: int = Field(default=0, alias="id.resp_p")
    protocol: str = Field(default="tcp", alias="proto")
    conn_state: Optional[str] = None
    service: Optional[str] = None
    duration: Optional[float] = 0.0
    orig_bytes: Optional[int] = 0
    resp_bytes: Optional[int] = 0
    orig_pkts: Optional[int] = 0
    resp_pkts: Optional[int] = 0
    orig_ip_bytes: Optional[int] = 0
    resp_ip_bytes: Optional[int] = 0
    data_source: str = "zeek"

    model_config = {
        "populate_by_name": True,
        "extra": "allow",
    }

    @field_validator("src_port", "dst_port", mode="before")
    def validate_ports(cls, v):
        if v is None or v == "-":
            return 0
        try:
            val = int(v)
            return max(0, min(65535, val))
        except (ValueError, TypeError):
            return 0

    @field_validator("duration", mode="before")
    def validate_duration(cls, v):
        if v is None or v == "-":
            return 0.0
        try:
            return float(v)
        except (ValueError, TypeError):
            return 0.0

    @field_validator("orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts", mode="before")
    def validate_ints(cls, v):
        if v is None or v == "-":
            return 0
        try:
            return int(v)
        except (ValueError, TypeError):
            return 0


class IngestedEvent(BaseModel):
    """Normalized, validated event ready for feature extraction."""
    timestamp: datetime
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    conn_state: Optional[str] = "SF"
    service: Optional[str] = "unknown"
    duration: float
    orig_bytes: int
    resp_bytes: int
    orig_pkts: int
    resp_pkts: int
    data_source: str
    event_fingerprint: str
    raw_payload: Optional[Dict[str, Any]] = None
