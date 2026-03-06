"""
Web Server Simulator — logs every HTTP request with network-layer details.
Writes structured logs to /logs/web.log (shared Docker volume).
"""

import os
import datetime
from flask import Flask, request

app = Flask(__name__)

LOG_PATH = os.environ.get("LOG_PATH", "/logs/web.log")

IST = datetime.timezone(datetime.timedelta(hours=5, minutes=30))


def log_event(req, status_code):
    """Write a structured log line for every request."""
    ts = datetime.datetime.now(IST).strftime("%Y-%m-%dT%H:%M:%S.%f+05:30")
    src_ip = req.remote_addr or "0.0.0.0"
    src_port = req.environ.get("REMOTE_PORT", 0)
    dst_port = int(os.environ.get("SERVICE_PORT", 80))
    method = req.method
    path = req.path
    line = f"{ts} {src_ip}:{src_port} -> 0.0.0.0:{dst_port} TCP {method} {path} {status_code}\n"
    with open(LOG_PATH, "a") as f:
        f.write(line)


@app.route("/", defaults={"path": ""})
@app.route("/<path:path>", methods=["GET", "POST", "PUT", "DELETE"])
def catch_all(path):
    """Catch-all route that logs and returns 200 for any request."""
    status = 200
    log_event(request, status)
    return f"OK /{path}", status


@app.route("/health")
def health():
    return "OK", 200


if __name__ == "__main__":
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    app.run(host="0.0.0.0", port=int(os.environ.get("SERVICE_PORT", 80)))
