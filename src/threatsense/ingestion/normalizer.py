"""Event normalization, timestamp parsing, and fingerprinting."""

from datetime import datetime, timezone
import hashlib
from typing import Any, Dict
from threatsense.ingestion.schemas import RawNetworkEvent, IngestedEvent


def normalize_timestamp(ts_val: Any) -> datetime:
    """Convert various timestamp formats to UTC datetime."""
    if isinstance(ts_val, datetime):
        if ts_val.tzinfo is None:
            return ts_val.replace(tzinfo=timezone.utc)
        return ts_val.astimezone(timezone.utc)

    if isinstance(ts_val, (int, float)):
        # Handle milliseconds or microseconds if unreasonably large
        if ts_val > 1e11:  # milliseconds
            ts_val /= 1000.0
        elif ts_val > 1e14:  # microseconds
            ts_val /= 1e6
        try:
            return datetime.fromtimestamp(ts_val, tz=timezone.utc)
        except (ValueError, OSError):
            return datetime.now(timezone.utc)

    if isinstance(ts_val, str) and ts_val:
        try:
            # Try ISO format
            dt = datetime.fromisoformat(ts_val.replace("Z", "+00:00"))
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except ValueError:
            try:
                # Try float string
                return datetime.fromtimestamp(float(ts_val), tz=timezone.utc)
            except ValueError:
                pass

    return datetime.now(timezone.utc)


def normalize_protocol(proto: Any) -> str:
    """Normalize protocol string or number into uppercase string."""
    if proto is None:
        return "TCP"
    p_str = str(proto).strip().lower()
    if p_str in ("tcp", "6"):
        return "TCP"
    if p_str in ("udp", "17"):
        return "UDP"
    if p_str in ("icmp", "1"):
        return "ICMP"
    return p_str.upper() if p_str else "TCP"


def compute_event_fingerprint(
    timestamp: datetime,
    src_ip: str,
    src_port: int,
    dst_ip: str,
    dst_port: int,
    protocol: str,
    orig_bytes: int,
    resp_bytes: int,
    duration: float,
) -> str:
    """Compute SHA-256 fingerprint for deduplication."""
    # Round timestamp to 1 second granularity for near-duplicate protection
    ts_sec = int(timestamp.timestamp())
    raw_str = f"{ts_sec}:{src_ip}:{src_port}:{dst_ip}:{dst_port}:{protocol}:{orig_bytes}:{resp_bytes}:{round(duration, 3)}"
    return hashlib.sha256(raw_str.encode("utf-8")).hexdigest()


def normalize_event(raw: RawNetworkEvent) -> IngestedEvent:
    """Transform RawNetworkEvent into IngestedEvent."""
    ts = normalize_timestamp(raw.ts or raw.timestamp)
    proto = normalize_protocol(raw.protocol)

    src_ip = raw.src_ip.strip() if raw.src_ip else "0.0.0.0"
    dst_ip = raw.dst_ip.strip() if raw.dst_ip else "0.0.0.0"

    duration = max(0.0, float(raw.duration or 0.0))
    orig_b = max(0, int(raw.orig_bytes or 0))
    resp_b = max(0, int(raw.resp_bytes or 0))
    orig_p = max(0, int(raw.orig_pkts or 0))
    resp_p = max(0, int(raw.resp_pkts or 0))

    fingerprint = compute_event_fingerprint(
        timestamp=ts,
        src_ip=src_ip,
        src_port=raw.src_port,
        dst_ip=dst_ip,
        dst_port=raw.dst_port,
        protocol=proto,
        orig_bytes=orig_b,
        resp_bytes=resp_b,
        duration=duration,
    )

    raw_dict = raw.model_dump(exclude_unset=True)

    return IngestedEvent(
        timestamp=ts,
        src_ip=src_ip,
        src_port=raw.src_port,
        dst_ip=dst_ip,
        dst_port=raw.dst_port,
        protocol=proto,
        conn_state=raw.conn_state or "SF",
        service=raw.service or "unknown",
        duration=duration,
        orig_bytes=orig_b,
        resp_bytes=resp_b,
        orig_pkts=orig_p,
        resp_pkts=resp_p,
        data_source=raw.data_source,
        event_fingerprint=fingerprint,
        raw_payload=raw_dict,
    )
