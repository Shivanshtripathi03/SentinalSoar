"""
Brute Force Detection Rule

Trigger: A single source IP generates >= threshold LOGIN_FAIL events
         on the auth service within the sliding window.

Evidence: List of raw log lines from the window.
"""

import time
from collections import defaultdict, deque
from datetime import datetime


class BruteForceRule:
    name = "BRUTE_FORCE"

    def __init__(self, window_seconds=60, threshold=5, severity="high"):
        self.window_seconds = window_seconds
        self.threshold = threshold
        self.severity = severity
        self.cooldown_seconds = 15
        # src_ip -> deque of (timestamp_epoch, event)
        self.windows = defaultdict(deque)
        self.last_alert_time = {}

    def _parse_ts(self, ts_str):
        try:
            if ts_str.endswith("Z"):
                ts_str = ts_str[:-1] + "+00:00"
            return datetime.fromisoformat(ts_str).timestamp()
        except Exception:
            return time.time()

    def evaluate(self, event: dict):
        # Only look at auth service LOGIN_FAIL events
        if event.get("source_type") != "auth":
            return None
        action = event.get("action", "").upper()
        if "LOGIN_FAIL" not in action and "FAIL" not in action:
            return None

        src_ip = event.get("src_ip", "")
        ts = self._parse_ts(event.get("timestamp", ""))

        self.windows[src_ip].append((ts, event))

        # Prune old entries
        cutoff = ts - self.window_seconds
        while self.windows[src_ip] and self.windows[src_ip][0][0] < cutoff:
            self.windows[src_ip].popleft()

        # Cooldown
        last = self.last_alert_time.get(src_ip, 0)
        if ts - last < self.cooldown_seconds:
            return None

        count = len(self.windows[src_ip])
        if count >= self.threshold:
            self.last_alert_time[src_ip] = ts
            entries = list(self.windows[src_ip])
            evidence = [e[1]["raw"] for e in entries[-20:]]
            return {
                "rule": self.name,
                "severity": self.severity,
                "src_ip": src_ip,
                "trigger": f"{count} failed login attempts in {self.window_seconds}s (threshold: {self.threshold})",
                "window_seconds": self.window_seconds,
                "timestamp": event["timestamp"],
                "evidence": evidence,
            }

        return None
