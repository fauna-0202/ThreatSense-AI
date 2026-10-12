# ThreatSense AI — Setup & Deployment Guide

This guide walks through setting up, configuring, training, and running ThreatSense AI on Windows, Linux, and macOS.

---

## 1. Prerequisites

- **Python:** 3.11 or 3.13 (verified compatible with 3.13.7)
- **Virtual Environment Tool:** `venv`
- **Optional Network Sensor:** Zeek 5.0+ (native Linux or Windows WSL2 Ubuntu)
- **Optional Containerization:** Docker 24.0+ & Docker Compose

---

## 2. Installation & Quickstart

### Step 1: Clone Repository & Create Virtual Environment

```bash
# Windows PowerShell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e .
```

```bash
# Linux / macOS / WSL2
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -e .
```

### Step 2: Configure Environment Variables

```bash
# Copy template
cp .env.example .env
```

### Step 3: Train Reproducible Models

Generate dataset splits, train the Random Forest and Isolation Forest models, and produce evaluation metrics:

```bash
python -m training.train
python -m training.evaluate
```

Model artifacts are stored in `artifacts/models/` and evaluation benchmarks are saved to `artifacts/reports/`.

---

## 3. Starting the Services

### Start the FastAPI Backend

```bash
uvicorn threatsense.api.main:app --host 127.0.0.1 --port 8000 --reload
```
Interactive OpenAPI documentation will be accessible at: `http://127.0.0.1:8000/docs`

### Start the Streamlit Operations Dashboard

In a separate terminal:

```bash
streamlit run dashboard/app.py --server.port 8501
```
The SecOps dashboard will open at: `http://localhost:8501`

---

## 4. Running Offline Replay Mode

To demonstrate deterministic traffic ingestion without needing elevated packet capture privileges:

1. Use the pre-packaged sample connection file at `data/samples/sample_zeek_conn.log`.
2. Click **▶ Run Replay Demo Batch** directly in the dashboard sidebar, or invoke via API:

```bash
curl -X POST "http://127.0.0.1:8000/api/v1/sensor/replay?limit=50" -H "X-API-Key: ts-demo-api-key-2026"
```

---

## 5. Live Zeek Sensor Configuration (WSL2 / Linux)

Because native Windows Zeek builds are experimental, the recommended workflow on Windows is **WSL2 Ubuntu**:

```bash
# In WSL2 Ubuntu
sudo apt update
sudo apt install zeek zeek-core

# Verify installation
zeek --version

# Set capabilities for unprivileged interface capture
sudo setcap cap_net_raw,cap_net_admin=eip $(which zeek)
```

In `.env`, set:
```ini
ZEEK_BIN_PATH=/usr/bin/zeek
ZEEK_INTERFACE=eth0
SENSOR_MODE=live
```

---

## 6. Real CIC-IDS2017 Dataset Acquisition (Optional)

To train on the complete 3-million-record University of New Brunswick CIC-IDS2017 dataset:

1. Download the generated flow CSV files from the official UNB repository:
   https://www.unb.ca/cic/datasets/ids-2017.html
2. Place the extracted CSV files (e.g. `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv`) into:
   `data/raw/`
3. Re-run training:
   ```bash
   python -m training.train
   python -m training.evaluate
   ```
ThreatSense AI's dataset loader will automatically detect and ingest real CSV files, map their columns to the 12 canonical flow metrics, clean NaNs, and retrain the models.

---

## 7. Running the Automated Test Suite

```bash
# Run full suite
pytest -v

# Run with coverage report
pytest --tb=short
```
All 49 unit, integration, machine learning, and security tests will execute in ~3.5 seconds.
