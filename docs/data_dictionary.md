# ThreatSense AI — Data Dictionary & Canonical Schema Specification

**Feature Schema Version:** `threatsense-features-v1`

---

## 1. Canonical Flow Feature Specification

Network flow benchmark datasets (e.g. CIC-IDS2017) and live Zeek connection logs (`conn.log`) do not share identical column naming conventions or native feature sets. 

To ensure **mathematical validity** and **prevent silent feature fabrication**, ThreatSense AI enforces a strict 12-feature canonical contract. If any feature is missing, NaN, or violates physical domain boundaries, the system raises an explicit `FEATURE_SCHEMA_INCOMPATIBLE` diagnostic rather than generating misleading predictions.

| Feature Name | Data Type | Physical Unit | Valid Range | Source Compatibility Mapping | Mathematical Definition & Rationale |
|---|---|---|---|---|---|
| `duration` | `float64` | seconds | `[0.0, 86400.0]` | Zeek `duration`<br/>CIC `Flow Duration / 1e6` | Elapsed time from first packet to connection termination. Zero-duration sessions represent single-packet probes. |
| `orig_bytes` | `int64` | bytes | `[0, 1e11]` | Zeek `orig_bytes`<br/>CIC `Total Length of Fwd Packets` | Total TCP/UDP application payload volume sent from originator to responder. |
| `resp_bytes` | `int64` | bytes | `[0, 1e11]` | Zeek `resp_bytes`<br/>CIC `Total Length of Bwd Packets` | Total TCP/UDP application payload volume sent from responder back to originator. |
| `orig_pkts` | `int64` | packets | `[0, 1e9]` | Zeek `orig_pkts`<br/>CIC `Total Fwd Packets` | Total packet count transmitted by originator. |
| `resp_pkts` | `int64` | packets | `[0, 1e9]` | Zeek `resp_pkts`<br/>CIC `Total Backward Packets` | Total packet count transmitted by responder. |
| `total_bytes` | `int64` | bytes | `[0, 2e11]` | Derived: `orig_bytes + resp_bytes` | Aggregate session payload volume. |
| `total_pkts` | `int64` | packets | `[0, 2e9]` | Derived: `orig_pkts + resp_pkts` | Aggregate packet exchange count. |
| `bytes_per_sec` | `float64` | bytes/sec | `[0.0, 1e10]` | Derived: `total_bytes / (duration + 1e-6)` | Transfer bandwidth rate. Uses $\epsilon = 10^{-6}$ smoothing to prevent division by zero on zero-duration connections. |
| `pkts_per_sec` | `float64` | packets/sec | `[0.0, 1e8]` | Derived: `total_pkts / (duration + 1e-6)` | Packet throughput rate. Key metric for DoS/DDoS detection. |
| `orig_to_resp_byte_ratio` | `float64` | ratio | `[0.0, 1e9]` | Derived: `orig_bytes / (resp_bytes + 1.0)` | Volume transfer asymmetry. Attacked endpoints often show massive outgoing-to-incoming volume disparities. |
| `orig_to_resp_pkt_ratio` | `float64` | ratio | `[0.0, 1e9]` | Derived: `orig_pkts / (resp_pkts + 1.0)` | Packet transmission asymmetry. High ratios indicate unacknowledged probes or SYN floods. |
| `dst_port` | `int64` | port number | `[0, 65535]` | Zeek `id.resp_p`<br/>CIC `Destination Port` | Targeted destination service port. |

---

## 2. Threat Classification Taxonomy

| Class Label | Category Description | Distinctive Flow Fingerprint |
|---|---|---|
| `BENIGN` | Legitimate operational traffic | Symmetric packet exchanges, appropriate payload-to-packet ratios, typical ports (80, 443, 53). |
| `DoS/DDoS` | Denial of Service flooding | Extremely elevated packet rate (`pkts_per_sec`), near-zero response payload (`resp_bytes = 0`), asymmetric orig-to-resp packet ratio. |
| `PortScan` | Network reconnaissance | Very short duration ($< 10$ ms), 1–2 originator packets, zero response payload, diversified target ports. |
| `BruteForce` | Repeated authentication guessing | Successive short-lived connections to administrative ports (22 SSH, 21 FTP, 3389 RDP) with small, uniform payload frames. |
| `Botnet` | Command & Control (C2) / beaconing | Long session durations, periodic interval traffic, connections to non-standard or IRC ports (e.g. 6667, 8088). |

---

## 3. Database Entity Schema (SQLAlchemy / SQLite)

### `network_events`
Persists raw ingested network connection sessions.
- `id` (VARCHAR(36), PK): UUID.
- `timestamp` (DATETIME, Indexed): Event timestamp normalized to UTC.
- `src_ip` (VARCHAR(45), Indexed): Originator IP address.
- `src_port` (INTEGER): Originator source port.
- `dst_ip` (VARCHAR(45), Indexed): Responder IP address.
- `dst_port` (INTEGER, Indexed): Target destination port.
- `protocol` (VARCHAR(16), Indexed): Normalized transport protocol (`TCP`, `UDP`, `ICMP`).
- `conn_state` (VARCHAR(32)): Connection state flag (e.g. `SF`, `S0`, `REJ`).
- `duration` (FLOAT): Flow duration in seconds.
- `orig_bytes` (INTEGER): Originator payload bytes.
- `resp_bytes` (INTEGER): Responder payload bytes.
- `orig_pkts` (INTEGER): Originator packet count.
- `resp_pkts` (INTEGER): Responder packet count.
- `data_source` (VARCHAR(32)): Source origin (`zeek`, `replay`, `api`).
- `event_fingerprint` (VARCHAR(64), Unique Indexed): SHA-256 hash ensuring idempotency and deduplication.
- `raw_payload` (JSON): Retained raw input metadata dictionary.

### `predictions`
Persists model inference outputs.
- `id` (VARCHAR(36), PK): UUID.
- `event_id` (VARCHAR(36), FK -> `network_events.id`, CASCADE).
- `model_version` (VARCHAR(64), Indexed): Identifier of classifier model version.
- `predicted_class` (VARCHAR(64), Indexed): Predicted threat class.
- `confidence` (FLOAT): Softmax probability of predicted class ($0.0 - 1.0$).
- `class_probabilities` (JSON): Probability dictionary for all candidate classes.
- `anomaly_score` (FLOAT): Raw Isolation Forest anomaly score ($< -0.1$ denotes abnormality).
- `is_anomaly` (INTEGER): Flag ($1 = \text{Anomalous}, 0 = \text{Normal}$).
- `uncertainty_state` (VARCHAR(64), Indexed): Uncertainty diagnostic (`CONFIDENT`, `HIGH_UNCERTAINTY`, `OUT_OF_DISTRIBUTION`, `DETECTOR_DISAGREEMENT`, `REVIEW_REQUIRED`).
- `schema_status` (VARCHAR(64)): Feature compatibility status (`VALID`, `FEATURE_SCHEMA_INCOMPATIBLE`).
- `created_at` (DATETIME, Indexed): Creation timestamp.

### `alerts`
Persists prioritized operational triage alerts.
- `id` (VARCHAR(36), PK): UUID.
- `event_id` (VARCHAR(36), FK -> `network_events.id`, CASCADE).
- `prediction_id` (VARCHAR(36), FK -> `predictions.id`, CASCADE).
- `risk_score` (FLOAT, Indexed): Operational risk indicator ($0.0 - 100.0$).
- `priority` (VARCHAR(16), Indexed): Priority band (`LOW`, `MODERATE`, `HIGH`, `CRITICAL`).
- `status` (VARCHAR(32), Indexed): Triage status (`NEW`, `INVESTIGATING`, `RESOLVED`, `FALSE_POSITIVE`).
- `contributing_signals` (JSON): Breakdown of weights, components, and uncertainty factors.
- `created_at` (DATETIME, Indexed): UTC timestamp.
- `updated_at` (DATETIME): Last updated UTC timestamp.

### `explanations`
Persists explainable AI attributions.
- `id` (VARCHAR(36), PK): UUID.
- `prediction_id` (VARCHAR(36), FK -> `predictions.id`, CASCADE).
- `influential_features` (JSON): Ranked list of features, SHAP values, actual values, and directions.
- `explanation_metadata` (JSON): Explainer algorithm details.
- `summary_text` (TEXT): Natural language SecOps explanation narrative with legal/security disclaimers.
- `explanation_status` (VARCHAR(32)): `SUCCESS` or `FALLBACK`.
- `created_at` (DATETIME): Timestamp.

### `analyst_notes`
- `id` (VARCHAR(36), PK): UUID.
- `alert_id` (VARCHAR(36), FK -> `alerts.id`, CASCADE).
- `author` (VARCHAR(64)): Analyst identifier.
- `note` (TEXT): Investigation findings or resolution rationale.
- `created_at` (DATETIME, Indexed): Timestamp.

### `audit_logs`
- `id` (VARCHAR(36), PK): UUID.
- `actor` (VARCHAR(64), Indexed): Initiator of the state change.
- `action` (VARCHAR(128), Indexed): Action type (e.g. `UPDATE_ALERT_STATUS`).
- `details` (JSON): Payload containing old and new values.
- `outcome` (VARCHAR(32)): Result status (`SUCCESS`, `FAILED`).
- `timestamp` (DATETIME, Indexed): UTC timestamp.
