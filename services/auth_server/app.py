"""
Auth Server Simulator — simulates an SSH/auth service.
Logs every connection attempt with action (login_attempt, login_success, login_fail).
Writes structured logs to /logs/auth.log.
"""

import os
import datetime
from flask import Flask, request, jsonify

app = Flask(__name__)

LOG_PATH = os.environ.get("LOG_PATH", "/logs/auth.log")

# Simple credential store for simulation
VALID_CREDS = {"admin": "admin123", "user1": "password1"}

IST = datetime.timezone(datetime.timedelta(hours=5, minutes=30))


def log_event(req, action):
    ts = datetime.datetime.now(IST).strftime("%Y-%m-%dT%H:%M:%S.%f+05:30")
    src_ip = req.remote_addr or "0.0.0.0"
    src_port = req.environ.get("REMOTE_PORT", 0)
    dst_port = int(os.environ.get("SERVICE_PORT", 22))
    line = f"{ts} {src_ip}:{src_port} -> 0.0.0.0:{dst_port} TCP {action}\n"
    with open(LOG_PATH, "a") as f:
        f.write(line)


@app.route("/login", methods=["POST"])
def login():
    """Simulate SSH login attempt."""
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")

    log_event(request, "LOGIN_ATTEMPT")

    if VALID_CREDS.get(username) == password:
        log_event(request, "LOGIN_SUCCESS")
        return jsonify({"status": "success"}), 200
    else:
        log_event(request, "LOGIN_FAIL")
        return jsonify({"status": "fail"}), 401


@app.route("/", methods=["GET", "POST"])
def index():
    """Any other connection is logged as a generic attempt."""
    log_event(request, "CONNECTION")
    return "Auth Service", 200


@app.route("/health")
def health():
    return "OK", 200


if __name__ == "__main__":
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    app.run(host="0.0.0.0", port=int(os.environ.get("SERVICE_PORT", 22)))
