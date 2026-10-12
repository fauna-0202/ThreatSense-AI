"""Flow feature extractor from ingested events."""

import math
from typing import Dict, Any, Union
import numpy as np
import pandas as pd
from threatsense.ingestion.schemas import IngestedEvent
from threatsense.features.schema import FEATURE_NAMES


class FlowFeatureExtractor:
    """Extracts canonical flow features from IngestedEvent or dictionary."""

    @staticmethod
    def extract_features(event: Union[IngestedEvent, Dict[str, Any]]) -> Dict[str, float]:
        if isinstance(event, IngestedEvent):
            duration = max(0.0, float(event.duration))
            orig_bytes = max(0, int(event.orig_bytes))
            resp_bytes = max(0, int(event.resp_bytes))
            orig_pkts = max(0, int(event.orig_pkts))
            resp_pkts = max(0, int(event.resp_pkts))
            dst_port = max(0, min(65535, int(event.dst_port)))
        else:
            duration = max(0.0, float(event.get("duration", 0.0) or 0.0))
            orig_bytes = max(0, int(event.get("orig_bytes", 0) or 0))
            resp_bytes = max(0, int(event.get("resp_bytes", 0) or 0))
            orig_pkts = max(0, int(event.get("orig_pkts", 0) or 0))
            resp_pkts = max(0, int(event.get("resp_pkts", 0) or 0))
            dst_port = max(0, min(65535, int(event.get("dst_port", 0) or 0)))

        total_bytes = orig_bytes + resp_bytes
        total_pkts = orig_pkts + resp_pkts

        # Flow rates using 1e-6 epsilon for zero duration connections
        dur_eps = duration + 1e-6
        bytes_per_sec = total_bytes / dur_eps
        pkts_per_sec = total_pkts / dur_eps

        # Laplace smoothed ratios to prevent division by zero
        orig_to_resp_byte_ratio = float(orig_bytes) / (float(resp_bytes) + 1.0)
        orig_to_resp_pkt_ratio = float(orig_pkts) / (float(resp_pkts) + 1.0)

        # Cap absurd infinity or overflow values
        bytes_per_sec = min(1e10, bytes_per_sec) if math.isfinite(bytes_per_sec) else 0.0
        pkts_per_sec = min(1e8, pkts_per_sec) if math.isfinite(pkts_per_sec) else 0.0

        features = {
            "duration": float(duration),
            "orig_bytes": int(orig_bytes),
            "resp_bytes": int(resp_bytes),
            "orig_pkts": int(orig_pkts),
            "resp_pkts": int(resp_pkts),
            "total_bytes": int(total_bytes),
            "total_pkts": int(total_pkts),
            "bytes_per_sec": float(bytes_per_sec),
            "pkts_per_sec": float(pkts_per_sec),
            "orig_to_resp_byte_ratio": float(orig_to_resp_byte_ratio),
            "orig_to_resp_pkt_ratio": float(orig_to_resp_pkt_ratio),
            "dst_port": int(dst_port),
        }
        return features

    @staticmethod
    def to_dataframe(features: Dict[str, float]) -> pd.DataFrame:
        """Converts extracted features dictionary to an ordered single-row DataFrame."""
        row = {col: [features[col]] for col in FEATURE_NAMES}
        return pd.DataFrame(row, columns=FEATURE_NAMES)

    @staticmethod
    def to_numpy(features: Dict[str, float]) -> np.ndarray:
        """Converts extracted features to 1D ordered numpy array."""
        return np.array([features[col] for col in FEATURE_NAMES], dtype=np.float64)
