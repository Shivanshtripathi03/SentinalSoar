"""
SentinelSOAR Main Loop — orchestrates ingestion, normalisation, rule evaluation,
alerting, containment, and SOAR playbook execution in a single-threaded
polling loop.
"""

import os
import time
import threading
from collections import deque

from sentinelsoar.ingestion import LogIngester
from sentinelsoar.normaliser import normalise
from sentinelsoar.rule_engine import RuleEngine
from sentinelsoar.alert_manager import AlertManager
from sentinelsoar.blocklist import BlocklistManager
from sentinelsoar.soar.playbook_engine import PlaybookEngine
from sentinelsoar.soar.notifier import NotificationManager
from sentinelsoar.intel.threat_intel import ThreatIntelManager
from sentinelsoar.incident.manager import IncidentManager
from sentinelsoar.ai.analyst import AIAnalyst
from sentinelsoar.audit import AuditLogger


class SentinelSOARCore:
    """Main SentinelSOAR processing pipeline with SOAR integration."""

    def __init__(
        self,
        log_dir="/logs",
        config_path="/app/config/rules.yaml",
        data_dir="/app/data",
    ):
        self.ingester = LogIngester(log_dir=log_dir)
        self.rule_engine = RuleEngine(config_path=config_path)
        self.alert_manager = AlertManager(data_dir=data_dir)
        self.blocklist = BlocklistManager(data_dir=data_dir)
        self.auto_block_severities = self.rule_engine.get_auto_block_severities()

        # ── New modules ──
        playbook_config = os.path.join(os.path.dirname(config_path), "playbooks.yaml")
        self.threat_intel = ThreatIntelManager()
        self.incident_manager = IncidentManager(data_dir=data_dir)
        self.notifier = NotificationManager()
        self.ai_analyst = AIAnalyst()
        self.audit = AuditLogger(data_dir=data_dir)
        self.playbook_engine = PlaybookEngine(config_path=playbook_config)

        # Register service providers for SOAR actions
        self.playbook_engine.register_providers(
            blocklist=self.blocklist,
            threat_intel=self.threat_intel,
            notifier=self.notifier,
            incident_manager=self.incident_manager,
        )

        # Recent normalised events for the dashboard
        self.recent_events = deque(maxlen=500)
        # Time-series tracking: (epoch, src_ip, source_type)
        self.ts_events = deque(maxlen=5000)
        self.lock = threading.Lock()

        self.running = False
        self.start_time = None
        self.stats = {"events_processed": 0, "alerts_generated": 0, "ips_blocked": 0}

    def process_cycle(self):
        """One polling cycle: ingest → normalise → evaluate → alert → SOAR."""
        raw_lines = self.ingester.poll()
        for source_type, raw_line in raw_lines:
            event = normalise(source_type, raw_line)
            if event is None:
                continue

            # Drop events from blocked IPs entirely (containment)
            if self.blocklist.is_blocked(event.get("src_ip", "")):
                continue

            # Store for dashboard
            with self.lock:
                self.recent_events.append(event)
                self.ts_events.append((time.time(), event.get("src_ip", ""), event.get("source_type", "")))
            self.stats["events_processed"] += 1

            # Run all rules
            alerts = self.rule_engine.evaluate(event)
            for alert in alerts:
                self.alert_manager.add_alert(alert)
                self.stats["alerts_generated"] += 1

                # Auto-block if severity is high enough
                severity = alert.get("severity", "")
                src_ip = alert.get("src_ip", "")
                if severity in self.auto_block_severities and src_ip:
                    blocked = self.blocklist.block(
                        src_ip, f"Auto-blocked by rule {alert.get('rule', '?')}"
                    )
                    if blocked:
                        self.stats["ips_blocked"] += 1

                # Execute SOAR playbooks
                try:
                    self.playbook_engine.execute_for_alert(alert)
                except Exception as e:
                    print(f"[sentinelsoar] SOAR playbook error: {e}")

    def get_recent_events(self, limit=200):
        with self.lock:
            return list(self.recent_events)[-limit:]

    def get_timeseries(self, window=60, last_n=0):
        """Return event counts bucketed by second, per src_ip.

        If last_n > 0, derive the window from the last N stored events
        instead of a fixed wall-clock window.
        """
        now = time.time()
        with self.lock:
            snapshot = list(self.ts_events)

        if last_n > 0 and snapshot:
            tail = snapshot[-last_n:]
            cutoff = tail[0][0]
        else:
            cutoff = now - window

        buckets = {}
        for ts, src_ip, _ in snapshot:
            if ts < cutoff:
                continue
            sec = int(ts)
            buckets.setdefault(src_ip, {}).setdefault(sec, 0)
            buckets[src_ip][sec] += 1

        seconds = list(range(int(cutoff), int(now) + 1))
        result = {"timestamps": seconds, "series": {}}
        for src_ip, secs in buckets.items():
            result["series"][src_ip] = [secs.get(s, 0) for s in seconds]
        return result

    def get_service_distribution(self):
        """Return event counts per source_type."""
        counts = {}
        with self.lock:
            for event in self.recent_events:
                st = event.get("source_type", "unknown")
                counts[st] = counts.get(st, 0) + 1
        return counts

    def run(self, poll_interval=1.0):
        """Start the main polling loop (blocking)."""
        self.running = True
        self.start_time = time.time()
        print(f"[sentinelsoar] SentinelSOAR Core started — polling every {poll_interval}s")
        print(f"[sentinelsoar] Active rules: {len(self.rule_engine.rules)}, "
              f"Playbooks: {len(self.playbook_engine.playbooks)}")
        while self.running:
            try:
                self.process_cycle()
            except Exception as e:
                print(f"[sentinelsoar] Error in processing cycle: {e}")
            time.sleep(poll_interval)

    def stop(self):
        self.running = False
