# ThreatSense AI — Threat Model & Security Posture

## 1. Security Architecture & Defensive Philosophy

ThreatSense AI is intentionally designed as a **strictly passive, non-intrusive network detection and explainability system**:

- **Zero Disruptive Action:** The system never transmits counter-attack traffic, resets remote TCP connections, scans unauthorized targets, or alters network routing. It contains no active intrusion-prevention or blocking mechanisms.
- **Payload Privacy:** The canonical pipeline operates exclusively on flow metadata (timestamps, packet rates, directional byte volumes, port numbers). Raw packet payloads are neither inspected, parsed, nor persisted.
- **Principle of Least Privilege:** Sensor components require only read access to network interfaces (e.g. `CAP_NET_RAW` / `CAP_NET_ADMIN` on Linux/WSL2) or pre-recorded PCAP/log files. Unprivileged users can safely run offline replay mode.
- **Authorized Network Scope:** Live monitoring is restricted to explicitly configured interfaces on networks for which the operating organization has verified legal authority.

---

## 2. Threat Vector Analysis & Countermeasures

| Threat Vector | Risk Description | ThreatSense AI Countermeasure |
|---|---|---|
| **Adversarial Flow Manipulation** | An adversary pads packet sizes, inserts micro-delays, or introduces jitter to shift flows across the decision boundary of the supervised model. | **Dual-Engine Fusion:** Isolation Forest flags statistical unfamiliarity even if supervised classifier predicts `BENIGN`. The uncertainty engine identifies `DETECTOR_DISAGREEMENT` and elevates operational risk. |
| **Out-Of-Distribution (OOD) Zero-Days** | An unobserved attack pattern or novel protocol abuse unrepresented in the training dataset. | **Distribution Scoring:** Uncertainty engine assigns `OUT_OF_DISTRIBUTION` status, treats high anomaly as an estimate of unfamiliarity (rather than proof of attack), and sets `review_required=True`. |
| **Command Injection via Sensor Configuration** | An untrusted actor injects shell metacharacters into interface or binary configurations to achieve remote command execution. | **Safe Subprocess Tokenization:** Subprocess invocations in `sensor/zeek_runner.py` strictly pass argument lists (`[zeek_bin, "-i", interface, ...]`). Execution via raw shell interpolation (`shell=True`) is strictly prohibited and validated by automated tests. |
| **API Denial of Service / Memory Exhaustion** | Flooding the `/analyze` or `/events` endpoints with malformed payloads or massive queries. | **Strict Input Validation & Bounded Limits:** Pydantic models enforce type validation and port limits $[0, 65535]$. Pagination parameters are strictly bounded (e.g. `limit` capped at 200). |
| **Information & Secret Leakage** | Database errors or 500 exceptions leaking internal filesystem paths, connection strings, or environment secrets. | **Sanitized Exception Handling:** Global FastAPI exception handlers intercept unhandled exceptions and return structured errors (`INTERNAL_SERVER_ERROR`), suppressing internal tracebacks and credentials. |
| **Unauthorized State Mutation** | An unauthenticated attacker modifies alert triage states or injects false analyst notes. | **Authentication & Role Safeguards:** State-changing endpoints (`PATCH /alerts/{id}`, `POST /sensor/replay`) are protected by the `X-API-Key` dependency, which fails closed in production mode. |

---

## 3. Visibility Limitations

1. **Encrypted Traffic Payloads:** TLS 1.3, SSH, and VPN tunnels encrypt application-layer payloads. ThreatSense AI models behavioral flow dynamics (volume asymmetry, transfer rates, session durations, port mappings), but cannot decrypt or inspect application data.
2. **Asymmetric Routing:** If only one direction of a bidirectional network conversation is captured by the mirrored interface, directional features (`resp_bytes`, `resp_pkts`) will be zero, triggering schema boundary warnings.
3. **High-Bandwidth Sampling Drift:** On saturated links operating without hardware capture acceleration, dropped packets may distort flow-rate calculations.
