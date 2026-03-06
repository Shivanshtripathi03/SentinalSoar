"""
Alert Manager — creates, persists, and serves alert objects.
"""

import json
import os
import time
import threading
from datetime import datetime, timezone, timedelta
from collections import deque


class AlertManager:
    """Thread-safe alert storage with JSON persistence."""

    def __init__(self, data_dir="/app/data"):
        self.data_dir = data_dir
        self.alerts_file = os.path.join(data_dir, "alerts.json")
        self.alerts = deque(maxlen=500)
        self.lock = threading.Lock()
        os.makedirs(data_dir, exist_ok=True)
        self._load()

    def _load(self):
        """Load persisted alerts on startup."""
        try:
            if os.path.exists(self.alerts_file):
                with open(self.alerts_file, "r") as f:
                    data = json.load(f)
                    for a in data:
                        self.alerts.append(a)
                print(f"[alert_manager] Loaded {len(self.alerts)} existing alerts")
        except Exception as e:
            print(f"[alert_manager] Could not load alerts: {e}")

    def _persist(self):
        """Write alerts to disk."""
        try:
            with open(self.alerts_file, "w") as f:
                json.dump(list(self.alerts), f, indent=2)
        except Exception as e:
            print(f"[alert_manager] Persist error: {e}")

    def add_alert(self, alert_data: dict):
        """Add a new alert and persist."""
        alert = {
            "id": len(self.alerts) + 1,
            "created_at": datetime.now(timezone(timedelta(hours=5, minutes=30))).strftime("%Y-%m-%dT%H:%M:%S.%f+05:30"),
            **alert_data,
        }
        with self.lock:
            self.alerts.append(alert)
            self._persist()
        print(
            f"[ALERT] #{alert['id']} | {alert.get('rule', '?')} | "
            f"severity={alert.get('severity', '?')} | src_ip={alert.get('src_ip', '?')} | "
            f"{alert.get('trigger', '')}"
        )
        return alert

    def get_alerts(self, limit=100):
        """Return the most recent alerts."""
        with self.lock:
            return list(self.alerts)[-limit:]

    def clear(self):
        with self.lock:
            self.alerts.clear()
            self._persist()
