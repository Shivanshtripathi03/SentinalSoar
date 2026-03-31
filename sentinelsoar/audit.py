"""
Audit Logger — tracks administrative actions for compliance.

Logs actions like: unblock IP, config changes, incident status updates.
Persisted to data/audit.json.
"""

import json
import os
import threading
from datetime import datetime, timezone, timedelta
from collections import deque

IST = timezone(timedelta(hours=5, minutes=30))


class AuditLogger:
    """Thread-safe audit log with JSON persistence."""

    def __init__(self, data_dir="/app/data"):
        self.data_dir = data_dir
        self.audit_file = os.path.join(data_dir, "audit.json")
        self.entries = deque(maxlen=1000)
        self.lock = threading.Lock()
        os.makedirs(data_dir, exist_ok=True)
        self._load()

    def _load(self):
        try:
            if os.path.exists(self.audit_file):
                with open(self.audit_file, "r") as f:
                    data = json.load(f)
                    for entry in data:
                        self.entries.append(entry)
                print(f"[audit] Loaded {len(self.entries)} audit entries")
        except Exception as e:
            print(f"[audit] Could not load: {e}")

    def _persist(self):
        try:
            with open(self.audit_file, "w") as f:
                json.dump(list(self.entries), f, indent=2)
        except Exception as e:
            print(f"[audit] Persist error: {e}")

    def log(self, action: str, details: dict = None, user: str = "system"):
        """Record an audit event."""
        entry = {
            "timestamp": datetime.now(IST).strftime("%Y-%m-%dT%H:%M:%S+05:30"),
            "action": action,
            "user": user,
            "details": details or {},
        }
        with self.lock:
            self.entries.append(entry)
            self._persist()

    def get_entries(self, limit=100, action_filter=None) -> list:
        """Return recent audit log entries."""
        with self.lock:
            entries = list(self.entries)
            if action_filter:
                entries = [e for e in entries if e.get("action") == action_filter]
            return entries[-limit:]
