"""Human-readable explanation formatter for SecOps analysts."""

from typing import Dict, Any, List
from threatsense.features.schema import get_feature_dict


FEATURE_DESCS = {
    "duration": "connection duration",
    "orig_bytes": "originator payload volume",
    "resp_bytes": "responder payload volume",
    "orig_pkts": "originator packet count",
    "resp_pkts": "responder packet count",
    "total_bytes": "aggregate traffic volume",
    "total_pkts": "aggregate packet volume",
    "bytes_per_sec": "data transfer rate",
    "pkts_per_sec": "packet delivery rate",
    "orig_to_resp_byte_ratio": "traffic volume asymmetry",
    "orig_to_resp_pkt_ratio": "packet transmission asymmetry",
    "dst_port": "targeted destination port",
}


class ExplanationFormatter:
    """Translates raw feature attributions into natural language analyst summaries."""

    @staticmethod
    def generate_narrative(
        predicted_class: str,
        confidence: float,
        top_features: List[Dict[str, Any]],
        uncertainty_state: str,
        is_anomaly: bool,
    ) -> str:
        lines = []

        if predicted_class == "BENIGN":
            lines.append(
                f"Model evidence indicates normal/benign network behavior with {confidence:.1%} statistical confidence."
            )
        else:
            lines.append(
                f"Model evidence suggests patterns consistent with '{predicted_class}' (model confidence: {confidence:.1%})."
            )

        if top_features:
            supporting = [f for f in top_features if f.get("direction") == "supports_prediction"]
            if supporting:
                feats_str = ", ".join(
                    f"{FEATURE_DESCS.get(f['feature'], f['feature'])} ({f['feature']} = {f['actual_value']})"
                    for f in supporting[:3]
                )
                lines.append(f"Primary driving indicators: {feats_str}.")

        if is_anomaly:
            lines.append(
                "Unsupervised anomaly detection flagged this connection as deviating from baseline normality."
            )

        if uncertainty_state != "CONFIDENT":
            lines.append(
                f"Note: Prediction flagged with uncertainty state '{uncertainty_state}'. Independent analyst verification recommended."
            )

        lines.append(
            "Security disclaimer: Machine learning attributions reflect statistical pattern matching and must not be treated as absolute proof of compromise."
        )

        return " ".join(lines)
