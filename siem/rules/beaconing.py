"""
Beaconing Detection Rule

Trigger: A (src_ip, dst_ip, dst_port) tuple shows regular periodic connections
         — at least min_events within the window, with low standard deviation
         of inter-arrival times (< jitter_threshold seconds).

This detects C2-like behaviour: small, regular callouts.
"""

import time
import math
from collections import defaultdict, deque
from datetime import datetime


class BeaconingRule:
    name = "BEACONING"

    def __init__(self, window_seconds=300, min_events=5, jitter_threshold=3.0, severity="medium"):
        self.window_seconds = window_seconds
        self.min_events = min_events
        self.jitter_threshold = jitter_threshold
        self.severity = severity
        self.cooldown_seconds = 15
        # (src_ip, dst_ip, dst_port) -> deque of (timestamp_epoch, event)
        self.windows = defaultdict(deque)
        self.last_alert_time = {}

    def _parse_ts(self, ts_str):
        try:
            if ts_str.endswith("Z"):
                ts_str = ts_str[:-1] + "+00:00"
            return datetime.fromisoformat(ts_str).timestamp()
        except Exception:
            return time.time()

    def _stddev(self, values):
        if len(values) < 2:
            return float("inf")
        mean = sum(values) / len(values)
        variance = sum((v - mean) ** 2 for v in values) / (len(values) - 1)
        return math.sqrt(variance)

    def evaluate(self, event: dict):
        src_ip = event.get("src_ip", "")
        dst_ip = event.get("dst_ip", "")
        dst_port = event.get("dst_port", 0)
        ts = self._parse_ts(event.get("timestamp", ""))
        key = (src_ip, dst_ip, dst_port)

        self.windows[key].append((ts, event))

        # Prune
        cutoff = ts - self.window_seconds
        while self.windows[key] and self.windows[key][0][0] < cutoff:
            self.windows[key].popleft()

        # Cooldown
        last = self.last_alert_time.get(key, 0)
        if ts - last < self.cooldown_seconds:
            return None

        entries = list(self.windows[key])
        if len(entries) < self.min_events:
            return None

        # Calculate inter-arrival time std dev
        timestamps = [e[0] for e in entries]
        intervals = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]
        std = self._stddev(intervals)
        mean_interval = sum(intervals) / len(intervals) if intervals else 0

        # Reject burst traffic (port scans, floods) — beaconing has slower, periodic intervals
        if mean_interval < 2.0:
            return None

        if std < self.jitter_threshold:
            self.last_alert_time[key] = ts
            evidence = [e[1]["raw"] for e in entries]
            return {
                "rule": self.name,
                "severity": self.severity,
                "src_ip": src_ip,
                "trigger": (
                    f"{len(entries)} periodic connections to {dst_ip}:{dst_port} "
                    f"(mean interval: {mean_interval:.1f}s, jitter σ: {std:.2f}s < {self.jitter_threshold}s)"
                ),
                "window_seconds": self.window_seconds,
                "timestamp": event["timestamp"],
                "evidence": evidence[-15:],
            }

        return None
