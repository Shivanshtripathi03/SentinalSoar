"""
AI Anomaly Detection Rule (Statistical)

Trigger: A source IP's event rate deviates significantly (> z_threshold
         standard deviations) from its historical baseline.

Uses a rolling baseline of per-IP event counts per minute.
No external API required — pure statistical analysis.
"""

import time
import math
from collections import defaultdict, deque
from datetime import datetime


class AnomalyDetectionRule:
    name = "ANOMALY_DETECTION"

    def __init__(self, window_seconds=300, baseline_minutes=10,
                 z_threshold=3.0, min_baseline_points=5, severity="medium"):
        self.window_seconds = window_seconds
        self.baseline_minutes = baseline_minutes
        self.z_threshold = z_threshold
        self.min_baseline_points = min_baseline_points
        self.severity = severity
        self.cooldown_seconds = 60  # longer cooldown for anomalies

        # src_ip -> deque of (timestamp_epoch, event)
        self.windows = defaultdict(deque)
        # src_ip -> list of per-minute event counts (historical baseline)
        self.baselines = defaultdict(lambda: deque(maxlen=baseline_minutes))
        # src_ip -> current minute bucket
        self.current_minute = {}
        self.current_minute_count = defaultdict(int)
        self.last_alert_time = {}

    def _parse_ts(self, ts_str):
        try:
            if ts_str.endswith("Z"):
                ts_str = ts_str[:-1] + "+00:00"
            return datetime.fromisoformat(ts_str).timestamp()
        except Exception:
            return time.time()

    def _update_baseline(self, src_ip, ts):
        """Track per-minute event counts for baseline calculation."""
        current_min = int(ts // 60)

        if src_ip not in self.current_minute:
            self.current_minute[src_ip] = current_min
            self.current_minute_count[src_ip] = 0

        if current_min != self.current_minute[src_ip]:
            # New minute — save the previous minute's count as baseline
            self.baselines[src_ip].append(self.current_minute_count[src_ip])
            self.current_minute[src_ip] = current_min
            self.current_minute_count[src_ip] = 0

        self.current_minute_count[src_ip] += 1

    def _calculate_z_score(self, src_ip):
        """Calculate z-score of current minute's rate vs baseline."""
        baseline = list(self.baselines[src_ip])
        if len(baseline) < self.min_baseline_points:
            return 0.0  # Not enough data

        mean = sum(baseline) / len(baseline)
        if len(baseline) < 2:
            return 0.0

        variance = sum((x - mean) ** 2 for x in baseline) / (len(baseline) - 1)
        std = math.sqrt(variance) if variance > 0 else 0.0

        if std == 0:
            # If baseline is perfectly uniform, any deviation is anomalous
            current = self.current_minute_count[src_ip]
            return (current - mean) * 10 if current > mean * 2 else 0.0

        current = self.current_minute_count[src_ip]
        return (current - mean) / std

    def evaluate(self, event: dict):
        src_ip = event.get("src_ip", "")
        ts = self._parse_ts(event.get("timestamp", ""))

        # Add to window
        self.windows[src_ip].append((ts, event))

        # Prune old entries
        cutoff = ts - self.window_seconds
        while self.windows[src_ip] and self.windows[src_ip][0][0] < cutoff:
            self.windows[src_ip].popleft()

        # Update baseline tracking
        self._update_baseline(src_ip, ts)

        # Cooldown
        last = self.last_alert_time.get(src_ip, 0)
        if ts - last < self.cooldown_seconds:
            return None

        # Calculate anomaly score
        z_score = self._calculate_z_score(src_ip)

        if z_score >= self.z_threshold:
            self.last_alert_time[src_ip] = ts
            baseline = list(self.baselines[src_ip])
            mean = sum(baseline) / len(baseline) if baseline else 0
            current = self.current_minute_count[src_ip]
            entries = list(self.windows[src_ip])
            evidence = [e[1]["raw"] for e in entries[-15:]]

            return {
                "rule": self.name,
                "severity": self.severity,
                "src_ip": src_ip,
                "trigger": (
                    f"Anomalous activity: {current} events/min vs baseline avg "
                    f"{mean:.1f}/min (z-score: {z_score:.2f}, threshold: {self.z_threshold})"
                ),
                "window_seconds": self.window_seconds,
                "z_score": round(z_score, 2),
                "baseline_mean": round(mean, 1),
                "current_rate": current,
                "timestamp": event["timestamp"],
                "evidence": evidence,
            }

        return None
