"""
DB Server Simulator — simulates a MySQL-like database service.
Logs every connection/query attempt.
Writes structured logs to /logs/db.log.
"""

import os
import datetime
from flask import Flask, request, jsonify

app = Flask(__name__)

LOG_PATH = os.environ.get("LOG_PATH", "/logs/db.log")

IST = datetime.timezone(datetime.timedelta(hours=5, minutes=30))


def log_event(req, query_type):
    ts = datetime.datetime.now(IST).strftime("%Y-%m-%dT%H:%M:%S.%f+05:30")
    src_ip = req.remote_addr or "0.0.0.0"
    src_port = req.environ.get("REMOTE_PORT", 0)
    dst_port = int(os.environ.get("SERVICE_PORT", 3306))
    line = f"{ts} {src_ip}:{src_port} -> 0.0.0.0:{dst_port} TCP {query_type}\n"
    with open(LOG_PATH, "a") as f:
        f.write(line)


@app.route("/query", methods=["POST"])
def query():
    """Simulate a DB query."""
    data = request.get_json(silent=True) or {}
    query_type = data.get("type", "SELECT").upper()
    log_event(request, f"QUERY_{query_type}")
    return jsonify({"status": "ok", "rows": 0}), 200


@app.route("/", methods=["GET", "POST"])
def index():
    """Generic connection attempt."""
    log_event(request, "CONNECTION")
    return "DB Service", 200


@app.route("/health")
def health():
    return "OK", 200


if __name__ == "__main__":
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    app.run(host="0.0.0.0", port=int(os.environ.get("SERVICE_PORT", 3306)))
