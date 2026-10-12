"""ThreatSense AI Canonical Feature Schema Definition."""

from typing import List, Dict, Any
from dataclasses import dataclass


FEATURE_SCHEMA_VERSION = "threatsense-features-v1"


@dataclass(frozen=True)
class FeatureSpec:
    name: str
    dtype: str
    description: str
    unit: str
    min_val: float
    max_val: float
    source_mapping: str


CANONICAL_FEATURES: List[FeatureSpec] = [
    FeatureSpec(
        name="duration",
        dtype="float64",
        description="Total duration of the network connection/flow",
        unit="seconds",
        min_val=0.0,
        max_val=86400.0,
        source_mapping="Zeek 'duration' | CIC-IDS2017 'Flow Duration' (divided by 1e6)",
    ),
    FeatureSpec(
        name="orig_bytes",
        dtype="int64",
        description="Payload/data bytes sent by originator/source",
        unit="bytes",
        min_val=0.0,
        max_val=1e11,
        source_mapping="Zeek 'orig_bytes' | CIC-IDS2017 'Total Length of Fwd Packets'",
    ),
    FeatureSpec(
        name="resp_bytes",
        dtype="int64",
        description="Payload/data bytes sent by responder/destination",
        unit="bytes",
        min_val=0.0,
        max_val=1e11,
        source_mapping="Zeek 'resp_bytes' | CIC-IDS2017 'Total Length of Bwd Packets'",
    ),
    FeatureSpec(
        name="orig_pkts",
        dtype="int64",
        description="Number of packets sent by originator/source",
        unit="packets",
        min_val=0.0,
        max_val=1e9,
        source_mapping="Zeek 'orig_pkts' | CIC-IDS2017 'Total Fwd Packets'",
    ),
    FeatureSpec(
        name="resp_pkts",
        dtype="int64",
        description="Number of packets sent by responder/destination",
        unit="packets",
        min_val=0.0,
        max_val=1e9,
        source_mapping="Zeek 'resp_pkts' | CIC-IDS2017 'Total Backward Packets'",
    ),
    FeatureSpec(
        name="total_bytes",
        dtype="int64",
        description="Sum of originator and responder bytes",
        unit="bytes",
        min_val=0.0,
        max_val=2e11,
        source_mapping="Derived: orig_bytes + resp_bytes",
    ),
    FeatureSpec(
        name="total_pkts",
        dtype="int64",
        description="Sum of originator and responder packets",
        unit="packets",
        min_val=0.0,
        max_val=2e9,
        source_mapping="Derived: orig_pkts + resp_pkts",
    ),
    FeatureSpec(
        name="bytes_per_sec",
        dtype="float64",
        description="Transfer rate in bytes per second",
        unit="bytes/sec",
        min_val=0.0,
        max_val=1e10,
        source_mapping="Derived: total_bytes / (duration + 1e-6) | CIC-IDS2017 'Flow Bytes/s'",
    ),
    FeatureSpec(
        name="pkts_per_sec",
        dtype="float64",
        description="Packet rate in packets per second",
        unit="packets/sec",
        min_val=0.0,
        max_val=1e8,
        source_mapping="Derived: total_pkts / (duration + 1e-6) | CIC-IDS2017 'Flow Packets/s'",
    ),
    FeatureSpec(
        name="orig_to_resp_byte_ratio",
        dtype="float64",
        description="Ratio of originator bytes to responder bytes (with +1 Laplace smoothing)",
        unit="ratio",
        min_val=0.0,
        max_val=1e9,
        source_mapping="Derived: orig_bytes / (resp_bytes + 1.0)",
    ),
    FeatureSpec(
        name="orig_to_resp_pkt_ratio",
        dtype="float64",
        description="Ratio of originator packets to responder packets (with +1 Laplace smoothing)",
        unit="ratio",
        min_val=0.0,
        max_val=1e9,
        source_mapping="Derived: orig_pkts / (resp_pkts + 1.0)",
    ),
    FeatureSpec(
        name="dst_port",
        dtype="int64",
        description="Destination port / target service",
        unit="port number",
        min_val=0.0,
        max_val=65535.0,
        source_mapping="Zeek 'id.resp_p' | CIC-IDS2017 'Destination Port'",
    ),
]

FEATURE_NAMES: List[str] = [f.name for f in CANONICAL_FEATURES]


def get_feature_dict() -> Dict[str, Dict[str, Any]]:
    return {
        f.name: {
            "dtype": f.dtype,
            "description": f.description,
            "unit": f.unit,
            "min_val": f.min_val,
            "max_val": f.max_val,
            "source_mapping": f.source_mapping,
        }
        for f in CANONICAL_FEATURES
    }
