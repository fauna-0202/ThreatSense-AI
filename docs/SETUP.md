# ThreatSense AI — Setup & Deployment Guide

This guide details the steps to set up, configure, train, and run ThreatSense AI across Windows, Linux, WSL2, and Docker environments.

---

## 1. Prerequisites

- **Python Version:** Python 3.11 or Python 3.13 (verified on Python 3.13.7)
- **Git:** Git 2.30+
- **Virtual Environment:** Python standard `venv`
- **Optional Network Sensor:** Zeek 5.0+ (recommended via WSL2 Ubuntu for Windows users)
- **Optional Containerization:** Docker 24.0+ & Docker Compose

---

## 2. Installation (Windows PowerShell)

```powershell
# 1. Clone repository (or enter project workspace)
cd "E:\ThreatSense AI"

# 2. Create isolated virtual environment
python -m venv .venv

# 3. Activate virtual environment
.\.venv\Scripts\Activate.ps1

# 4. Upgrade pip and install pinned dependencies
python -m pip install --upgrade pip
pip install -r requirements.txt
pip install -e .

# 5. Initialize environment file from safe template
Copy-Item .env.example .env
```

---

## 3. Installation (Linux / macOS / WSL2)

```bash
# 1. Clone repository
cd ThreatSense-AI

# 2. Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 3. Install dependencies
pip install --upgrade pip
pip install -r requirements.txt
pip install -e .

# 4. Initialize environment configuration
cp .env.example .env
```

---

## 4. Model Training & Evaluation

ThreatSense AI generates deterministic, reproducible models from structured feature sets:

```powershell
# In PowerShell with virtual environment activated:
$env:PYTHONPATH="src;."

# 1. Prepare dataset splits and train Random Forest & Isolation Forest models
.\.venv\Scripts\python.exe -m training.train

# 2. Run hold-out test set evaluation and generate benchmark reports
.\.venv\Scripts\python.exe -m training.evaluate
```

This creates model artifacts in `artifacts/models/` and reports in `artifacts/reports/`:
- `artifacts/models/rf_classifier.joblib`
- `artifacts/models/isolation_forest.joblib`
- `artifacts/models/baseline_model.joblib`
- `artifacts/models/scaler.joblib`
- `artifacts/models/metadata.json`
- `artifacts/reports/evaluation_report.json`
- `docs/EVALUATION.md`

---

## 5. Starting the Application Services

Start the backend and dashboard in **two separate PowerShell terminals**:

### Terminal 1: FastAPI REST Backend
```powershell
cd "E:\ThreatSense AI"
$env:PYTHONPATH="src;."
.\.venv\Scripts\python.exe -m uvicorn threatsense.api.main:app --host 127.0.0.1 --port 8000 --reload
```
- Interactive Swagger UI: **http://127.0.0.1:8000/docs**
- ReDoc Documentation: **http://127.0.0.1:8000/redoc**
- Health Check: **http://127.0.0.1:8000/health**

### Terminal 2: Streamlit Security Operations Dashboard
```powershell
cd "E:\ThreatSense AI"
$env:PYTHONPATH="src;."
.\.venv\Scripts\python.exe -m streamlit run dashboard/app.py --server.port 8501
```
- SecOps Dashboard: **http://localhost:8501**

---

## 6. Offline Replay Demonstration (Zero Privilege Required)

ThreatSense AI includes a deterministic offline replay engine that ingests structured connection records without needing elevated root/admin packet-capture permissions:

1. Open the dashboard at `http://localhost:8501`.
2. Click **▶ Run Replay Demo Batch** in the left sidebar.
3. Observe real-time ingestion, feature normalization, dual model classification, risk scoring, and SHAP explanation generation.
4. Or trigger replay via the REST API:
   ```bash
   curl -X POST "http://127.0.0.1:8000/api/v1/sensor/replay?limit=50" -H "X-API-Key: replace-with-your-secure-api-key"
   ```

---

## 7. Live Zeek Sensor Setup (WSL2 Ubuntu / Linux)

For environments with authorized live network interfaces:

```bash
# In Ubuntu / WSL2:
sudo apt update
sudo apt install zeek zeek-core

# Verify binary
zeek --version

# Grant non-root packet capture capability
sudo setcap cap_net_raw,cap_net_admin=eip $(which zeek)
```

In `.env`, configure:
```ini
SENSOR_MODE=live
ZEEK_BIN_PATH=/usr/bin/zeek
ZEEK_INTERFACE=eth0
```

> **Important Security Requirement:** Live monitoring must only be activated on interfaces and networks for which you possess explicit authorization.

---

## 8. Docker & Docker Compose Deployment

```bash
# Build and start both backend and dashboard containers
docker-compose up --build -d

# View service logs
docker-compose logs -f

# Shut down services safely
docker-compose down
```

---

## 9. Running Automated Tests

```powershell
$env:PYTHONPATH="src;."
.\.venv\Scripts\pytest.exe -v
```
All 50 unit, integration, machine learning, and security tests execute locally in under 4 seconds.
