"""
Blocklist Manager — maintains a set of blocked IPs.
Auto-blocks IPs from high-severity alerts.
"""

import json
import os
import threading
from datetime import datetime, timezone, timedelta


class BlocklistManager:
    """Thread-safe IP blocklist with JSON persistence."""

    def __init__(self, data_dir="/app/data"):
        self.data_dir = data_dir
        self.blocklist_file = os.path.join(data_dir, "blocklist.json")
        self.blocked = {}  # ip -> {"blocked_at": ..., "reason": ...}
        self.lock = threading.Lock()
        os.makedirs(data_dir, exist_ok=True)
        self._load()

    def _load(self):
        try:
            if os.path.exists(self.blocklist_file):
                with open(self.blocklist_file, "r") as f:
                    self.blocked = json.load(f)
                print(f"[blocklist] Loaded {len(self.blocked)} blocked IPs")
        except Exception as e:
            print(f"[blocklist] Could not load: {e}")

    def _persist(self):
        try:
            with open(self.blocklist_file, "w") as f:
                json.dump(self.blocked, f, indent=2)
        except Exception as e:
            print(f"[blocklist] Persist error: {e}")

    def block(self, ip: str, reason: str):
        """Add an IP to the blocklist."""
        with self.lock:
            if ip not in self.blocked:
                self.blocked[ip] = {
                    "blocked_at": datetime.now(timezone(timedelta(hours=5, minutes=30))).strftime("%Y-%m-%dT%H:%M:%S.%f+05:30"),
                    "reason": reason,
                }
                self._persist()
                print(f"[BLOCK] IP {ip} blocked — reason: {reason}")
                return True
            return False

    def unblock(self, ip: str):
        """Remove an IP from the blocklist."""
        with self.lock:
            if ip in self.blocked:
                del self.blocked[ip]
                self._persist()
                print(f"[UNBLOCK] IP {ip} removed from blocklist")
                return True
            return False

    def is_blocked(self, ip: str) -> bool:
        with self.lock:
            return ip in self.blocked

    def get_all(self) -> dict:
        with self.lock:
            return dict(self.blocked)
