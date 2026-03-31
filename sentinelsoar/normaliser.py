"""
Log Normaliser — parses raw log lines into a common JSON schema.

Expected raw format from all services:
  <timestamp> <src_ip>:<src_port> -> <dst_ip>:<dst_port> <protocol> <action> [<extra>...]

Output schema:
  {
    timestamp, source_type, src_ip, src_port, dst_ip, dst_port,
    protocol, action, status, detail, raw
  }
"""

import re
from datetime import datetime

# Regex to parse the structured log lines emitted by our services
LOG_PATTERN = re.compile(
    r"^(?P<timestamp>\S+)\s+"
    r"(?P<src_ip>[\d.]+):(?P<src_port>\d+)\s+->\s+"
    r"(?P<dst_ip>[\d.]+):(?P<dst_port>\d+)\s+"
    r"(?P<protocol>\S+)\s+"
    r"(?P<rest>.+)$"
)

# Service-specific patterns for the 'rest' portion
WEB_REST = re.compile(r"^(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<status>\d+)$")
AUTH_REST = re.compile(r"^(?P<action>\S+)$")
DB_REST = re.compile(r"^(?P<query_type>\S+)$")

# Map dst_port -> internal service IP (for enriching dst_ip when services log 0.0.0.0)
SERVICE_IP_MAP = {
    80: "10.10.0.10",
    22: "10.10.0.11",
    3306: "10.10.0.12",
}


def normalise(source_type: str, raw_line: str) -> dict | None:
    """
    Parse a raw log line into a normalised event dict.
    Returns None if the line cannot be parsed.
    """
    match = LOG_PATTERN.match(raw_line)
    if not match:
        return None

    g = match.groupdict()
    dst_port = int(g["dst_port"])
    dst_ip = g["dst_ip"]

    # Enrich dst_ip if the service logged 0.0.0.0
    if dst_ip == "0.0.0.0":
        dst_ip = SERVICE_IP_MAP.get(dst_port, dst_ip)

    event = {
        "timestamp": g["timestamp"],
        "source_type": source_type,
        "src_ip": g["src_ip"],
        "src_port": int(g["src_port"]),
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "protocol": g["protocol"],
        "action": "",
        "status": "",
        "detail": "",
        "raw": raw_line,
    }

    rest = g["rest"].strip()

    if source_type == "web":
        m = WEB_REST.match(rest)
        if m:
            event["action"] = f"HTTP_{m.group('method')}"
            event["status"] = m.group("status")
            event["detail"] = f"{m.group('method')} {m.group('path')}"
        else:
            event["action"] = rest
            event["detail"] = rest
    elif source_type == "auth":
        m = AUTH_REST.match(rest)
        if m:
            event["action"] = m.group("action")
            event["detail"] = m.group("action")
        else:
            event["action"] = rest
            event["detail"] = rest
    elif source_type == "db":
        m = DB_REST.match(rest)
        if m:
            event["action"] = m.group("query_type")
            event["detail"] = m.group("query_type")
        else:
            event["action"] = rest
            event["detail"] = rest
    else:
        event["action"] = rest
        event["detail"] = rest

    return event
