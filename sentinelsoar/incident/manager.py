"""
Incident Manager — groups related alerts into incidents for investigation.

Features:
  - Automatic alert correlation by src_ip + time proximity
  - Incident lifecycle: open → investigating → resolved → closed
  - Analyst notes per incident
  - JSON persistence
"""

import json
import os
import time
import threading
from datetime import datetime, timezone, timedelta
from collections import deque

IST = timezone(timedelta(hours=5, minutes=30))


class IncidentManager:
    """Thread-safe incident management with alert correlation."""

    CORRELATION_WINDOW = 300  # 5 minutes — alerts within this window from same IP group together
    VALID_STATUSES = {"open", "investigating", "resolved", "closed"}

    def __init__(self, data_dir="/app/data"):
        self.data_dir = data_dir
        self.incidents_file = os.path.join(data_dir, "incidents.json")
        self.incidents = []
        self.next_id = 1
        self.lock = threading.Lock()
        os.makedirs(data_dir, exist_ok=True)
        self._load()

    def _load(self):
        """Load persisted incidents on startup."""
        try:
            if os.path.exists(self.incidents_file):
                with open(self.incidents_file, "r") as f:
                    data = json.load(f)
                    self.incidents = data if isinstance(data, list) else []
                    if self.incidents:
                        self.next_id = max(i.get("id", 0) for i in self.incidents) + 1
                print(f"[incident_mgr] Loaded {len(self.incidents)} existing incidents")
        except Exception as e:
            print(f"[incident_mgr] Could not load incidents: {e}")

    def _persist(self):
        """Write incidents to disk."""
        try:
            with open(self.incidents_file, "w") as f:
                json.dump(self.incidents, f, indent=2)
        except Exception as e:
            print(f"[incident_mgr] Persist error: {e}")

    def correlate_alert(self, alert: dict) -> dict:
        """
        Correlate an alert to an existing incident or create a new one.
        Alerts from the same src_ip within the correlation window are grouped.
        """
        src_ip = alert.get("src_ip", "")
        now = time.time()

        with self.lock:
            # Look for an open incident from the same IP within the time window
            for incident in reversed(self.incidents):
                if (
                    incident.get("src_ip") == src_ip
                    and incident.get("status") in ("open", "investigating")
                    and now - incident.get("_last_alert_epoch", 0) < self.CORRELATION_WINDOW
                ):
                    # Add alert to existing incident
                    incident["alert_ids"].append(alert.get("id", 0))
                    incident["alert_rules"].append(alert.get("rule", ""))
                    incident["alert_count"] = len(incident["alert_ids"])
                    incident["_last_alert_epoch"] = now
                    incident["updated_at"] = datetime.now(IST).strftime("%Y-%m-%dT%H:%M:%S+05:30")

                    # Escalate severity if new alert is higher
                    sev_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
                    current_sev = sev_order.get(incident.get("severity", ""), 0)
                    alert_sev = sev_order.get(alert.get("severity", ""), 0)
                    if alert_sev > current_sev:
                        incident["severity"] = alert.get("severity", incident["severity"])

                    # Detect kill chain progression
                    incident["kill_chain"] = self._detect_kill_chain(incident["alert_rules"])

                    self._persist()
                    print(f"[incident_mgr] Alert #{alert.get('id', '?')} correlated to Incident #{incident['id']}")
                    return incident

            # Create new incident
            incident = {
                "id": self.next_id,
                "status": "open",
                "severity": alert.get("severity", "medium"),
                "src_ip": src_ip,
                "title": f"{alert.get('rule', 'Unknown')} from {src_ip}",
                "alert_ids": [alert.get("id", 0)],
                "alert_rules": [alert.get("rule", "")],
                "alert_count": 1,
                "kill_chain": self._detect_kill_chain([alert.get("rule", "")]),
                "notes": [],
                "created_at": datetime.now(IST).strftime("%Y-%m-%dT%H:%M:%S+05:30"),
                "updated_at": datetime.now(IST).strftime("%Y-%m-%dT%H:%M:%S+05:30"),
                "_last_alert_epoch": now,
            }
            self.incidents.append(incident)
            self.next_id += 1
            self._persist()

            print(f"[incident_mgr] New Incident #{incident['id']}: {incident['title']}")
            return incident

    def _detect_kill_chain(self, rules: list) -> list:
        """Detect cyber kill chain stages from alert rules."""
        stage_map = {
            "PORT_SCAN": "Reconnaissance",
            "BRUTE_FORCE": "Weaponization",
            "FLOODING": "Delivery",
            "LATERAL_MOVEMENT": "Lateral Movement",
            "BEACONING": "Command & Control",
            "ANOMALY_DETECTION": "Unknown Stage",
        }
        seen = set()
        stages = []
        for rule in rules:
            stage = stage_map.get(rule)
            if stage and stage not in seen:
                seen.add(stage)
                stages.append(stage)
        return stages

    def get_incidents(self, status_filter=None, limit=50) -> list:
        """Return incidents, optionally filtered by status."""
        with self.lock:
            incidents = list(self.incidents)
            if status_filter:
                incidents = [i for i in incidents if i.get("status") == status_filter]
            # Remove internal fields
            result = []
            for i in incidents[-limit:]:
                clean = {k: v for k, v in i.items() if not k.startswith("_")}
                result.append(clean)
            return result

    def get_incident(self, incident_id: int) -> dict | None:
        """Return a single incident by ID."""
        with self.lock:
            for i in self.incidents:
                if i.get("id") == incident_id:
                    return {k: v for k, v in i.items() if not k.startswith("_")}
            return None

    def update_status(self, incident_id: int, new_status: str) -> dict | None:
        """Update incident status."""
        if new_status not in self.VALID_STATUSES:
            return None

        with self.lock:
            for i in self.incidents:
                if i.get("id") == incident_id:
                    old_status = i["status"]
                    i["status"] = new_status
                    i["updated_at"] = datetime.now(IST).strftime("%Y-%m-%dT%H:%M:%S+05:30")
                    self._persist()
                    print(f"[incident_mgr] Incident #{incident_id} status: {old_status} → {new_status}")
                    return {k: v for k, v in i.items() if not k.startswith("_")}
            return None

    def add_note(self, incident_id: int, note: str, author: str = "analyst") -> dict | None:
        """Add an investigation note to an incident."""
        with self.lock:
            for i in self.incidents:
                if i.get("id") == incident_id:
                    note_entry = {
                        "author": author,
                        "text": note,
                        "created_at": datetime.now(IST).strftime("%Y-%m-%dT%H:%M:%S+05:30"),
                    }
                    i.setdefault("notes", []).append(note_entry)
                    i["updated_at"] = datetime.now(IST).strftime("%Y-%m-%dT%H:%M:%S+05:30")
                    self._persist()
                    return {k: v for k, v in i.items() if not k.startswith("_")}
            return None
