"""
Dashboard — Flask web app serving the SIEM UI.
Provides real-time log view, alert table, and blocked IP list.
Also runs the SIEM core in a background thread.
"""

import os
import threading
from flask import Flask, render_template, jsonify, request

from siem.core import SIEMCore

app = Flask(
    __name__,
    template_folder="dashboard/templates",
    static_folder="dashboard/static",
)

# Initialise SIEM core
siem = SIEMCore(
    log_dir=os.environ.get("LOG_DIR", "/logs"),
    config_path=os.environ.get("CONFIG_PATH", "/app/config/rules.yaml"),
    data_dir=os.environ.get("DATA_DIR", "/app/data"),
)


# ── Web Routes ────────────────────────────────────────

@app.route("/")
def index():
    """Main dashboard page."""
    return render_template("index.html")


# ── API Routes ────────────────────────────────────────

@app.route("/api/events")
def api_events():
    """Return recent normalised log events."""
    limit = request.args.get("limit", 200, type=int)
    events = siem.get_recent_events(limit=limit)
    return jsonify(events)


@app.route("/api/alerts")
def api_alerts():
    """Return recent alerts."""
    limit = request.args.get("limit", 100, type=int)
    alerts = siem.alert_manager.get_alerts(limit=limit)
    return jsonify(alerts)


@app.route("/api/blocklist")
def api_blocklist():
    """Return the current blocklist."""
    return jsonify(siem.blocklist.get_all())


@app.route("/api/blocklist/unblock", methods=["POST"])
def api_unblock():
    """Remove an IP from the blocklist."""
    data = request.get_json(silent=True) or {}
    ip = data.get("ip", "")
    if ip and siem.blocklist.unblock(ip):
        return jsonify({"status": "unblocked", "ip": ip})
    return jsonify({"status": "not_found", "ip": ip}), 404


@app.route("/api/stats")
def api_stats():
    """Return SIEM processing statistics."""
    return jsonify(siem.stats)


@app.route("/api/timeseries")
def api_timeseries():
    """Return per-source-IP event counts bucketed by second."""
    window = request.args.get("window", 60, type=int)
    last_n = request.args.get("last", 0, type=int)
    return jsonify(siem.get_timeseries(window=min(window, 300), last_n=min(last_n, 5000)))


@app.route("/api/service-distribution")
def api_service_distribution():
    """Return event counts per service type."""
    return jsonify(siem.get_service_distribution())


@app.route("/api/alert-summary")
def api_alert_summary():
    """Return alert counts grouped by rule."""
    alerts = siem.alert_manager.get_alerts(limit=1000)
    summary = {}
    for a in alerts:
        rule = a.get("rule", "unknown")
        if rule not in summary:
            summary[rule] = {"rule": rule, "severity": a.get("severity", ""), "count": 0}
        summary[rule]["count"] += 1
    return jsonify(list(summary.values()))


# ── Start SIEM in background thread ──────────────────

def start_siem_thread():
    t = threading.Thread(target=siem.run, kwargs={"poll_interval": 1.0}, daemon=True)
    t.start()
    print("[dashboard] SIEM core thread started")


if __name__ == "__main__":
    start_siem_thread()
    app.run(host="0.0.0.0", port=5000, debug=False)
