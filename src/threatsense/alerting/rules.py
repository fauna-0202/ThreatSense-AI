"""Heuristic security rules and port risk definitions."""

from typing import Dict, Any, List

SENSITIVE_PORTS = {
    21: {"service": "FTP", "risk_weight": 0.6, "desc": "Cleartext file transfer"},
    22: {"service": "SSH", "risk_weight": 0.8, "desc": "Secure shell administrative access"},
    23: {"service": "Telnet", "risk_weight": 0.9, "desc": "Insecure legacy administrative protocol"},
    25: {"service": "SMTP", "risk_weight": 0.5, "desc": "Mail transfer protocol"},
    53: {"service": "DNS", "risk_weight": 0.4, "desc": "Domain name resolution"},
    80: {"service": "HTTP", "risk_weight": 0.4, "desc": "Web HTTP service"},
    88: {"service": "Kerberos", "risk_weight": 0.8, "desc": "Active Directory authentication"},
    443: {"service": "HTTPS", "risk_weight": 0.4, "desc": "Encrypted web service"},
    445: {"service": "SMB", "risk_weight": 0.9, "desc": "Windows Server Message Block / Lateral movement vector"},
    1433: {"service": "MSSQL", "risk_weight": 0.8, "desc": "Database server access"},
    3306: {"service": "MySQL", "risk_weight": 0.8, "desc": "Database server access"},
    3389: {"service": "RDP", "risk_weight": 0.9, "desc": "Remote desktop management"},
    4444: {"service": "Metasploit", "risk_weight": 1.0, "desc": "Known default payload handler port"},
    6667: {"service": "IRC", "risk_weight": 0.9, "desc": "Legacy IRC botnet command-and-control channel"},
}

ATTACK_BASE_SEVERITIES = {
    "BENIGN": 5.0,
    "PortScan": 45.0,
    "BruteForce": 70.0,
    "DoS/DDoS": 80.0,
    "Botnet": 90.0,
}


def get_port_risk(port: int) -> Dict[str, Any]:
    if port in SENSITIVE_PORTS:
        return SENSITIVE_PORTS[port]
    # High unprivileged port or unknown service
    return {"service": "Custom/Ephemeral", "risk_weight": 0.3, "desc": "Standard unprivileged or non-standard port"}
