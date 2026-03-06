"""
Port Scan Detection Rule

Trigger: A single source IP sends >= threshold distinct endpoint probes
         (unique dst_ip:dst_port + path combos) within the sliding window.

Evidence: List of raw log lines from the window.
"""

import time
from collections import defaultdict, deque
from datetime import datetime


class PortScanRule:
    name = "PORT_SCAN"

    def __init__(self, window_seconds=60, threshold=10, severity="high"):
        self.window_seconds = window_seconds
        self.threshold = threshold
        self.severity = severity
        self.cooldown_seconds = 15
        # src_ip -> deque of (timestamp_epoch, probe_key, event)
        self.windows = defaultdict(deque)
        # Cooldown: don't re-alert for the same src_ip within the cooldown
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
        dst_ip = event.get("dst_ip", "")
        dst_port = event.get("dst_port", 0)
        detail = event.get("detail", "")
        ts = self._parse_ts(event.get("timestamp", ""))

        # A probe is a unique (dst_ip, dst_port, detail/path) combination
        probe_key = (dst_ip, dst_port, detail)

        # Add to window
        self.windows[src_ip].append((ts, probe_key, event))

        # Prune old entries
        cutoff = ts - self.window_seconds
        while self.windows[src_ip] and self.windows[src_ip][0][0] < cutoff:
            self.windows[src_ip].popleft()

        # Check cooldown
        last = self.last_alert_time.get(src_ip, 0)
        if ts - last < self.cooldown_seconds:
            return None

        # Count distinct endpoint probes
        window_entries = list(self.windows[src_ip])
        distinct_probes = set(e[1] for e in window_entries)

        if len(distinct_probes) >= self.threshold:
            self.last_alert_time[src_ip] = ts
            evidence = [e[2]["raw"] for e in window_entries]
            return {
                "rule": self.name,
                "severity": self.severity,
                "src_ip": src_ip,
                "trigger": f"{len(distinct_probes)} distinct endpoint probes in {self.window_seconds}s (threshold: {self.threshold})",
                "window_seconds": self.window_seconds,
                "timestamp": event["timestamp"],
                "evidence": evidence[-20:],
            }

        return None
