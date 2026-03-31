"""
SentinelSOAR Dashboard — Flask web app serving the platform UI.
Provides real-time log view, alert table, blocked IP list,
AI-powered analysis, threat intel, SOAR playbooks, and incident management.
Also runs the SentinelSOAR core in a background thread.
"""

import os
import io
import csv
import time
import threading
from flask import Flask, render_template, jsonify, request, Response

from sentinelsoar.core import SentinelSOARCore

app = Flask(
    __name__,
    template_folder="dashboard/templates",
    static_folder="dashboard/static",
)

# Initialise SentinelSOAR core
engine = SentinelSOARCore(
    log_dir=os.environ.get("LOG_DIR", "/logs"),
    config_path=os.environ.get("CONFIG_PATH", "/app/config/rules.yaml"),
    data_dir=os.environ.get("DATA_DIR", "/app/data"),
)


# ── Web Routes ────────────────────────────────────────

@app.route("/")
def index():
    """Main dashboard page."""
    return render_template("index.html")


# ── Original API Routes ──────────────────────────────

@app.route("/api/events")
def api_events():
    """Return recent normalised log events."""
    limit = request.args.get("limit", 200, type=int)
    events = engine.get_recent_events(limit=limit)
    return jsonify(events)


@app.route("/api/alerts")
def api_alerts():
    """Return recent alerts."""
    limit = request.args.get("limit", 100, type=int)
    alerts = engine.alert_manager.get_alerts(limit=limit)
    return jsonify(alerts)


@app.route("/api/blocklist")
def api_blocklist():
    """Return the current blocklist."""
    return jsonify(engine.blocklist.get_all())


@app.route("/api/blocklist/unblock", methods=["POST"])
def api_unblock():
    """Remove an IP from the blocklist."""
    data = request.get_json(silent=True) or {}
    ip = data.get("ip", "")
    if ip and engine.blocklist.unblock(ip):
        engine.audit.log("unblock_ip", {"ip": ip}, user="dashboard")
        return jsonify({"status": "unblocked", "ip": ip})
    return jsonify({"status": "not_found", "ip": ip}), 404


@app.route("/api/stats")
def api_stats():
    """Return SentinelSOAR processing statistics."""
    return jsonify(engine.stats)


@app.route("/api/timeseries")
def api_timeseries():
    """Return per-source-IP event counts bucketed by second."""
    window = request.args.get("window", 60, type=int)
    last_n = request.args.get("last", 0, type=int)
    return jsonify(engine.get_timeseries(window=min(window, 300), last_n=min(last_n, 5000)))


@app.route("/api/service-distribution")
def api_service_distribution():
    """Return event counts per service type."""
    return jsonify(engine.get_service_distribution())


@app.route("/api/alert-summary")
def api_alert_summary():
    """Return alert counts grouped by rule."""
    alerts = engine.alert_manager.get_alerts(limit=1000)
    summary = {}
    for a in alerts:
        rule = a.get("rule", "unknown")
        if rule not in summary:
            summary[rule] = {"rule": rule, "severity": a.get("severity", ""), "count": 0}
        summary[rule]["count"] += 1
    return jsonify(list(summary.values()))


# ══════════════════════════════════════════════════════
# NEW API ENDPOINTS
# ══════════════════════════════════════════════════════


# ── AI Analysis ──────────────────────────────────────

@app.route("/api/ai/explain-alert", methods=["POST"])
def api_ai_explain_alert():
    """AI-powered alert analysis and threat assessment."""
    data = request.get_json(silent=True) or {}
    alert_id = data.get("alert_id", 0)

    # Find the alert
    alerts = engine.alert_manager.get_alerts(limit=1000)
    alert = None
    for a in alerts:
        if a.get("id") == alert_id:
            alert = a
            break

    if not alert:
        return jsonify({"error": f"Alert #{alert_id} not found"}), 404

    # Get recent events from same IP for context
    src_ip = alert.get("src_ip", "")
    recent = [e for e in engine.get_recent_events(limit=500) if e.get("src_ip") == src_ip]

    result = engine.ai_analyst.explain_alert(alert, recent_events=recent[-50:])
    result.pop("_cached_at", None)
    return jsonify(result)


@app.route("/api/ai/summarize")
def api_ai_summarize():
    """AI-powered summary of recent log activity."""
    minutes = request.args.get("minutes", 5, type=int)
    events = engine.get_recent_events(limit=500)
    result = engine.ai_analyst.summarize_logs(events, window_minutes=min(minutes, 60))
    result.pop("_cached_at", None)
    return jsonify(result)


# ── Threat Intelligence ──────────────────────────────

@app.route("/api/intel/lookup")
def api_intel_lookup():
    """Threat intelligence lookup for an IP address."""
    ip = request.args.get("ip", "")
    if not ip:
        return jsonify({"error": "Missing 'ip' parameter"}), 400

    result = engine.threat_intel.lookup(ip)
    result.pop("_cached_at", None)
    return jsonify(result)


@app.route("/api/intel/cache-stats")
def api_intel_cache():
    """Return threat intel cache statistics."""
    return jsonify(engine.threat_intel.get_cache_stats())


# ── SOAR Playbooks ───────────────────────────────────

@app.route("/api/soar/playbooks")
def api_soar_playbooks():
    """Return configured SOAR playbooks."""
    return jsonify(engine.playbook_engine.playbooks)


@app.route("/api/soar/executions")
def api_soar_executions():
    """Return recent SOAR playbook execution log."""
    limit = request.args.get("limit", 50, type=int)
    return jsonify(engine.playbook_engine.get_execution_log(limit=limit))


# ── Incident Management ─────────────────────────────

@app.route("/api/incidents")
def api_incidents():
    """Return all incidents, optionally filtered by status."""
    status = request.args.get("status", None)
    limit = request.args.get("limit", 50, type=int)
    return jsonify(engine.incident_manager.get_incidents(status_filter=status, limit=limit))


@app.route("/api/incidents/<int:incident_id>")
def api_incident_detail(incident_id):
    """Return a single incident by ID."""
    incident = engine.incident_manager.get_incident(incident_id)
    if not incident:
        return jsonify({"error": f"Incident #{incident_id} not found"}), 404
    return jsonify(incident)


@app.route("/api/incidents/<int:incident_id>/status", methods=["POST"])
def api_incident_status(incident_id):
    """Update incident status."""
    data = request.get_json(silent=True) or {}
    new_status = data.get("status", "")
    result = engine.incident_manager.update_status(incident_id, new_status)
    if not result:
        return jsonify({"error": "Invalid incident ID or status"}), 400
    engine.audit.log("update_incident_status", {
        "incident_id": incident_id,
        "new_status": new_status,
    }, user="dashboard")
    return jsonify(result)


@app.route("/api/incidents/<int:incident_id>/notes", methods=["POST"])
def api_incident_notes(incident_id):
    """Add an investigation note to an incident."""
    data = request.get_json(silent=True) or {}
    note = data.get("note", "")
    author = data.get("author", "analyst")
    if not note:
        return jsonify({"error": "Missing 'note' field"}), 400
    result = engine.incident_manager.add_note(incident_id, note, author=author)
    if not result:
        return jsonify({"error": f"Incident #{incident_id} not found"}), 404
    return jsonify(result)


# ── Export & Search ──────────────────────────────────

@app.route("/api/export/alerts")
def api_export_alerts():
    """Export alerts as CSV."""
    fmt = request.args.get("format", "csv")
    alerts = engine.alert_manager.get_alerts(limit=1000)

    if fmt == "json":
        return jsonify(alerts)

    # CSV export
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "created_at", "rule", "severity", "src_ip", "trigger"])
    for a in alerts:
        writer.writerow([
            a.get("id", ""),
            a.get("created_at", a.get("timestamp", "")),
            a.get("rule", ""),
            a.get("severity", ""),
            a.get("src_ip", ""),
            a.get("trigger", ""),
        ])

    engine.audit.log("export_alerts", {"format": fmt, "count": len(alerts)}, user="dashboard")
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=alerts.csv"},
    )


@app.route("/api/export/events")
def api_export_events():
    """Export events as CSV."""
    fmt = request.args.get("format", "csv")
    events = engine.get_recent_events(limit=500)

    if fmt == "json":
        return jsonify(events)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["timestamp", "source_type", "src_ip", "dst_ip", "dst_port", "action", "status", "detail"])
    for e in events:
        writer.writerow([
            e.get("timestamp", ""),
            e.get("source_type", ""),
            e.get("src_ip", ""),
            e.get("dst_ip", ""),
            e.get("dst_port", ""),
            e.get("action", ""),
            e.get("status", ""),
            e.get("detail", ""),
        ])

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=events.csv"},
    )


@app.route("/api/search")
def api_search():
    """Search events by query string, source IP, and time range."""
    q = request.args.get("q", "").lower()
    src_ip = request.args.get("src_ip", "")
    source_type = request.args.get("source_type", "")
    limit = request.args.get("limit", 200, type=int)

    events = engine.get_recent_events(limit=500)
    results = []

    for e in events:
        # Filter by src_ip
        if src_ip and e.get("src_ip") != src_ip:
            continue
        # Filter by source_type
        if source_type and e.get("source_type") != source_type:
            continue
        # Filter by query string (searches across all fields)
        if q and q not in str(e).lower():
            continue
        results.append(e)

    return jsonify(results[-limit:])


# ── Health & Audit ───────────────────────────────────

@app.route("/api/health")
def api_health():
    """Return SentinelSOAR system health status."""
    uptime = time.time() - engine.start_time if engine.start_time else 0
    return jsonify({
        "status": "running" if engine.running else "stopped",
        "uptime_seconds": round(uptime),
        "events_processed": engine.stats.get("events_processed", 0),
        "alerts_generated": engine.stats.get("alerts_generated", 0),
        "ips_blocked": engine.stats.get("ips_blocked", 0),
        "active_rules": len(engine.rule_engine.rules),
        "active_playbooks": len(engine.playbook_engine.playbooks),
        "blocked_ips": len(engine.blocklist.get_all()),
        "open_incidents": len([i for i in engine.incident_manager.get_incidents() if i.get("status") == "open"]),
        "ai_mode": "gemini" if engine.ai_analyst.model else "static",
        "threat_intel_cache": engine.threat_intel.get_cache_stats(),
    })


@app.route("/api/audit")
def api_audit():
    """Return audit log entries."""
    limit = request.args.get("limit", 100, type=int)
    action = request.args.get("action", None)
    return jsonify(engine.audit.get_entries(limit=limit, action_filter=action))


# ── Start SentinelSOAR in background thread ──────────

def start_engine_thread():
    t = threading.Thread(target=engine.run, kwargs={"poll_interval": 1.0}, daemon=True)
    t.start()
    print("[dashboard] SentinelSOAR core thread started")


if __name__ == "__main__":
    start_engine_thread()
    app.run(host="0.0.0.0", port=5000, debug=False)
