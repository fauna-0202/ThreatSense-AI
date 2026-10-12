# ThreatSense AI — Model Evaluation & Benchmarking Report

**Evaluation Timestamp:** `2026-10-11T14:04:45Z`  
**Evaluation Protocol:** Stratified hold-out split (80% train / 20% test)  
**Sample Sizes:** 12,000 training records, 3,000 hold-out test records  
**Feature Schema Version:** `threatsense-features-v1` (12 canonical flow metrics)

---

## 1. Primary Model Performance (Random Forest Classifier)

The primary detection model is an ensemble of 100 decision trees (`n_estimators=100`, `max_depth=12`, `random_state=42`) trained on normalized flow features.

- **Overall Accuracy:** **99.90%**
- **Macro F1-Score:** **0.9978**
- **Macro Precision:** **0.9984**
- **Macro Recall:** **0.9972**
- **Benign False Positive Rate (FPR):** **0.0005** (Target $< 0.0100$)

### Per-Class Detailed Performance

| Threat Class | Precision | Recall | F1-Score | Test Support | Security Interpretation |
|---|---|---|---|---|---|
| **BENIGN** | `0.9990` | `0.9995` | `0.9992` | 1,955 | Exceptional specificity; minimizes analyst alert fatigue. |
| **Botnet** | `1.0000` | `0.9865` | `0.9932` | 148 | Zero false alarms on C2 traffic; 98.65% true positive recall. |
| **BruteForce** | `0.9932` | `1.0000` | `0.9966` | 146 | 100% recall on authentication attack signatures. |
| **DoS/DDoS** | `1.0000` | `1.0000` | `1.0000` | 459 | Perfect detection on asymmetric high-rate packet floods. |
| **PortScan** | `1.0000` | `1.0000` | `1.0000` | 292 | Perfect detection on single-packet reconnaissance sweeps. |

---

## 2. Confusion Matrix (Hold-Out Test Set)

Rows represent ground-truth classes; columns represent model predictions:

| Ground Truth \ Predicted | BENIGN | Botnet | BruteForce | DoS/DDoS | PortScan | Total |
|---|---|---|---|---|---|---|
| **BENIGN** | **1,954** | 0 | 1 | 0 | 0 | 1,955 |
| **Botnet** | 2 | **146** | 0 | 0 | 0 | 148 |
| **BruteForce** | 0 | 0 | **146** | 0 | 0 | 146 |
| **DoS/DDoS** | 0 | 0 | 0 | **459** | 0 | 459 |
| **PortScan** | 0 | 0 | 0 | 0 | **292** | 292 |

---

## 3. Baseline Model Comparison

To validate ensemble architecture selection, the primary Random Forest classifier was benchmarked against a Gradient Boosting Classifier (`n_estimators=50`, `max_depth=5`):

| Architecture | Role | Accuracy | Macro F1 | Inference Latency | Explainability |
|---|---|---|---|---|---|
| **Random Forest (Primary)** | Operational Classifier | **99.90%** | **0.9978** | **38.51 ms** | Native TreeSHAP support |
| **Gradient Boosting (Baseline)** | Benchmark Comparison | **99.97%** | **0.9993** | 42.10 ms | Slower TreeSHAP convergence |

---

## 4. Unsupervised Anomaly Detection (Isolation Forest)

An Isolation Forest (`n_estimators=100`, `contamination=0.05`) was trained on baseline normal traffic to learn normality bounds without attack labels:

- **Flagged Outliers:** 1,041 flows ($34.70\%$ of test set, which deliberately contains $35\%$ attack flows).
- **Agreement with Supervised Classifier:** **93.63%** mutual agreement between the anomaly detector and the supervised attack predictions.
- **Detector Disagreement:** Where the models diverge, the uncertainty engine triggers a `DETECTOR_DISAGREEMENT` state, signaling the need for independent analyst investigation.

---

## 5. Global Feature Importance (Gini Impurity)

The top flow features driving classifier splits:

| Feature Name | Importance Weight | Physical Role |
|---|---|---|
| `resp_bytes` | `0.1882` | Distinguishes successful transfers from one-way floods and scans. |
| `total_pkts` | `0.1267` | Distinguishes high-volume volumetric floods from lightweight sessions. |
| `orig_to_resp_byte_ratio` | `0.1175` | Captures volumetric transfer asymmetry. |
| `total_bytes` | `0.1155` | Measures overall data volume exchange. |
| `orig_bytes` | `0.0905` | Distinguishes probes ($0$ bytes) from exfiltration and file transfer. |
| `orig_pkts` | `0.0801` | Packet frequency indicator. |
| `duration` | `0.0745` | Separates sub-millisecond scans from long-lived C2 beacons. |
| `orig_to_resp_pkt_ratio` | `0.0697` | Detects unacknowledged SYN or UDP packets. |

---

## 6. Reproducibility Instructions

To regenerate all model weights, evaluation reports, and benchmarks identically from source:

```bash
# Set PYTHONPATH
$env:PYTHONPATH="src;."

# Train models
python -m training.train

# Evaluate on test set
python -m training.evaluate

# Run performance and latency benchmark
python -m training.benchmark
```
All outputs are recorded in `artifacts/models/` and `artifacts/reports/`.
