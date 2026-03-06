"""
Lateral Movement Detection Rule

Trigger: A single source IP contacts >= threshold distinct internal
         destination IPs within the time window.

Indicates an attacker probing multiple internal services after initial compromise.
"""

import time
from collections import defaultdict, deque
from datetime import datetime


class LateralMovementRule:
    name = "LATERAL_MOVEMENT"

    def __init__(self, window_seconds=120, threshold=3, severity="high"):
        self.window_seconds = window_seconds
        self.threshold = threshold
        self.severity = severity
        self.cooldown_seconds = 15
        # src_ip -> deque of (timestamp_epoch, dst_ip, event)
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
        dst_ip = event.get("dst_ip", "")
        ts = self._parse_ts(event.get("timestamp", ""))

        self.windows[src_ip].append((ts, dst_ip, event))

        # Prune
        cutoff = ts - self.window_seconds
        while self.windows[src_ip] and self.windows[src_ip][0][0] < cutoff:
            self.windows[src_ip].popleft()

        # Cooldown
        last = self.last_alert_time.get(src_ip, 0)
        if ts - last < self.cooldown_seconds:
            return None

        entries = list(self.windows[src_ip])
        distinct_dsts = set(e[1] for e in entries)

        if len(distinct_dsts) >= self.threshold:
            self.last_alert_time[src_ip] = ts
            evidence = [e[2]["raw"] for e in entries[-20:]]
            return {
                "rule": self.name,
                "severity": self.severity,
                "src_ip": src_ip,
                "trigger": (
                    f"{len(distinct_dsts)} distinct internal targets in {self.window_seconds}s "
                    f"(threshold: {self.threshold}) — targets: {', '.join(sorted(distinct_dsts))}"
                ),
                "window_seconds": self.window_seconds,
                "timestamp": event["timestamp"],
                "evidence": evidence,
            }

        return None
