# ThreatSense AI — Model Evaluation Report

**Generated:** 2026-10-11T14:04:45.786187+00:00  
**Test Sample Count:** 3000  

## 1. Primary Model Performance (Random Forest)

- **Accuracy:** 99.90%
- **Macro F1 Score:** 0.9978
- **Macro Precision:** 0.9984
- **Macro Recall:** 0.9972
- **Benign False Positive Rate (FPR):** 0.0005

### Per-Class Metrics

| Class | Precision | Recall | F1-Score | Support |
|---|---|---|---|---|
| **BENIGN** | 0.9990 | 0.9995 | 0.9992 | 1955.0 |
| **Botnet** | 1.0000 | 0.9865 | 0.9932 | 148.0 |
| **BruteForce** | 0.9932 | 1.0000 | 0.9966 | 146.0 |
| **DoS/DDoS** | 1.0000 | 1.0000 | 1.0000 | 459.0 |
| **PortScan** | 1.0000 | 1.0000 | 1.0000 | 292.0 |

## 2. Baseline Model Comparison

- **Random Forest:** Accuracy: 99.90%, Macro F1: 0.9978
- **Gradient Boosting:** Accuracy: 99.97%, Macro F1: 0.9993

## 3. Unsupervised Anomaly Detection (Isolation Forest)

- **Total Anomalies Flagged:** 1041 (34.70%)
- **Agreement with Supervised Classifier:** 93.63%

## 4. Top Feature Importances

| Feature | Importance Weight |
|---|---|
| `resp_bytes` | 0.1882 |
| `total_pkts` | 0.1267 |
| `orig_to_resp_byte_ratio` | 0.1175 |
| `total_bytes` | 0.1155 |
| `orig_bytes` | 0.0905 |
| `orig_pkts` | 0.0801 |
| `duration` | 0.0745 |
| `orig_to_resp_pkt_ratio` | 0.0697 |
