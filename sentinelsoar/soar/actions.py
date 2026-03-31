"""
SOAR Action Library — callable actions used by playbooks.

Each action function takes standardised parameters and returns a result dict.
Actions are designed to be composable within playbook steps.
"""

import time
from datetime import datetime, timezone, timedelta


IST = timezone(timedelta(hours=5, minutes=30))


def action_block_ip(context, **kwargs):
    """Block the source IP via the blocklist manager."""
    src_ip = context.get("src_ip", "")
    rule = context.get("rule", "unknown")
    blocklist = context.get("_blocklist")

    if not blocklist or not src_ip:
        return {"status": "skipped", "reason": "No blocklist manager or src_ip"}

    blocked = blocklist.block(src_ip, f"SOAR playbook — triggered by {rule}")
    return {
        "status": "blocked" if blocked else "already_blocked",
        "ip": src_ip,
    }


def action_enrich_ip(context, **kwargs):
    """Enrich the source IP with threat intelligence."""
    src_ip = context.get("src_ip", "")
    intel = context.get("_threat_intel")

    if not intel or not src_ip:
        return {"status": "skipped", "reason": "No threat intel manager or src_ip"}

    result = intel.lookup(src_ip)
    # Remove internal cache key
    result.pop("_cached_at", None)
    return {"status": "enriched", "ip": src_ip, "intel": result}


def action_notify(context, **kwargs):
    """Send a notification about the alert."""
    notifier = context.get("_notifier")
    if not notifier:
        # Log-only notification
        rule = context.get("rule", "unknown")
        severity = context.get("severity", "unknown")
        src_ip = context.get("src_ip", "unknown")
        msg = f"[SOAR NOTIFY] Alert: {rule} | Severity: {severity} | Source: {src_ip}"
        print(msg)
        return {"status": "logged", "message": msg}

    channel = kwargs.get("channel", "log")
    return notifier.send(
        channel=channel,
        subject=f"SentinelSOAR Alert: {context.get('rule', 'unknown')}",
        body=f"Severity: {context.get('severity', '?')}, Source IP: {context.get('src_ip', '?')}, "
             f"Trigger: {context.get('trigger', '?')}",
    )


def action_escalate(context, **kwargs):
    """Escalate alert severity."""
    current = context.get("severity", "medium")
    escalation_map = {"low": "medium", "medium": "high", "high": "critical"}
    new_severity = escalation_map.get(current, current)

    print(f"[SOAR ESCALATE] {context.get('src_ip', '?')} severity {current} → {new_severity}")
    return {
        "status": "escalated",
        "from": current,
        "to": new_severity,
    }


def action_add_to_watchlist(context, **kwargs):
    """Add IP to a monitoring watchlist (logged for now)."""
    src_ip = context.get("src_ip", "")
    duration = kwargs.get("duration", "24h")
    print(f"[SOAR WATCHLIST] {src_ip} added to watchlist for {duration}")
    return {
        "status": "watchlisted",
        "ip": src_ip,
        "duration": duration,
    }


def action_log_incident(context, **kwargs):
    """Log the alert to the incident management system."""
    incident_mgr = context.get("_incident_manager")
    if not incident_mgr:
        return {"status": "skipped", "reason": "No incident manager"}

    alert = {
        "rule": context.get("rule", ""),
        "severity": context.get("severity", ""),
        "src_ip": context.get("src_ip", ""),
        "trigger": context.get("trigger", ""),
        "timestamp": context.get("timestamp", ""),
        "id": context.get("alert_id", 0),
    }
    incident = incident_mgr.correlate_alert(alert)
    return {
        "status": "incident_logged",
        "incident_id": incident.get("id", 0),
    }


# Action registry — maps action names to callables
ACTION_REGISTRY = {
    "block_ip": action_block_ip,
    "enrich_ip": action_enrich_ip,
    "notify": action_notify,
    "escalate": action_escalate,
    "add_to_watchlist": action_add_to_watchlist,
    "log_incident": action_log_incident,
}
