"""
Flooding Detection Rule

Trigger: A single source IP sends >= threshold connections within
         a short time window (e.g. 50 connections in 10 seconds).

Indicates DoS or brute-force style attacks.
"""

import time
from collections import defaultdict, deque
from datetime import datetime


class FloodingRule:
    name = "FLOODING"

    def __init__(self, window_seconds=10, threshold=50, severity="critical"):
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
        src_ip = event.get("src_ip", "")
        ts = self._parse_ts(event.get("timestamp", ""))

        self.windows[src_ip].append((ts, event))

        # Prune
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
                "trigger": f"{count} connections in {self.window_seconds}s (threshold: {self.threshold})",
                "window_seconds": self.window_seconds,
                "timestamp": event["timestamp"],
                "evidence": evidence,
            }

        return None
