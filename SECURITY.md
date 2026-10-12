# Security Policy — ThreatSense AI

The ThreatSense AI team takes the security and integrity of this software seriously. This document outlines our vulnerability disclosure policy and best practices for secure deployment.

---

## Supported Versions

| Version | Supported |
|---|---|
| `1.0.x` | :white_check_mark: |
| `< 1.0.0` | :x: |

---

## Reporting a Vulnerability

If you discover a security vulnerability within ThreatSense AI (such as an authentication bypass, command injection, secret leakage, or input validation flaw):

1. **Do not create a public GitHub Issue.**
2. Report the vulnerability privately by emailing the maintainer or opening a private GitHub Security Advisory.
3. Include:
   - Description of the vulnerability.
   - Minimal reproduction steps, request payloads, or Proof of Concept.
   - Impact assessment.
   - Any suggested remediations or mitigations.

### Response Timeframe
- **Initial acknowledgment:** Within 48 hours.
- **Triage & severity assessment:** Within 5 business days.
- **Remediation release:** Coordinated disclosure based on vulnerability severity.

---

## Deployment Security Guidelines

1. **Environment Variables & Secrets:**
   - Never commit your `.env` file to version control.
   - In production environments, always set `THREATSENSE_ENV=production` and `THREATSENSE_DEBUG=false`.
   - Generate a strong, random `THREATSENSE_API_KEY` (minimum 32 characters) and pass it in the `X-API-Key` header for administrative or state-mutating requests.

2. **Network Binding:**
   - In local setups, bind FastAPI (`127.0.0.1`) and Streamlit (`127.0.0.1`) to localhost only.
   - In production, deploy behind a TLS-terminating reverse proxy (e.g. Nginx, Caddy, or Envoy) with strict rate-limiting and WAF protection.

3. **Sensor Execution Privileges:**
   - Do not run the backend or dashboard processes as root/administrator.
   - On Linux/WSL2, assign interface sniffing capabilities specifically to the Zeek binary using Linux capabilities (`setcap cap_net_raw,cap_net_admin=eip $(which zeek)`) rather than running entire services as superuser.

4. **Monitoring Authorization:**
   - ThreatSense AI must only monitor authorized interfaces and authorized network segments.
