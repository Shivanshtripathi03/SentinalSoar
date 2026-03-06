"""
Rule Engine — manages sliding time windows and evaluates detection rules.
"""

import time
import yaml
from datetime import datetime, timedelta

from siem.rules.port_scan import PortScanRule
from siem.rules.beaconing import BeaconingRule
from siem.rules.flooding import FloodingRule
from siem.rules.lateral_movement import LateralMovementRule


class RuleEngine:
    """
    Maintains per-rule sliding windows and evaluates each incoming event
    against all registered rules.
    """

    def __init__(self, config_path="/app/config/rules.yaml"):
        self.config = self._load_config(config_path)
        self.rules = self._init_rules()

    def _load_config(self, path):
        try:
            with open(path, "r") as f:
                return yaml.safe_load(f)
        except Exception as e:
            print(f"[rule_engine] Failed to load config: {e}, using defaults")
            return {"rules": {}, "containment": {"auto_block_severity": ["high", "critical"]}}

    def _init_rules(self):
        """Instantiate all enabled rules from config."""
        rules = []
        rc = self.config.get("rules", {})

        if rc.get("port_scan", {}).get("enabled", True):
            cfg = rc.get("port_scan", {})
            rules.append(PortScanRule(
                window_seconds=cfg.get("window_seconds", 60),
                threshold=cfg.get("threshold", 10),
                severity=cfg.get("severity", "high"),
            ))

        if rc.get("beaconing", {}).get("enabled", True):
            cfg = rc.get("beaconing", {})
            rules.append(BeaconingRule(
                window_seconds=cfg.get("window_seconds", 300),
                min_events=cfg.get("min_events", 5),
                jitter_threshold=cfg.get("jitter_threshold", 3.0),
                severity=cfg.get("severity", "medium"),
            ))

        if rc.get("flooding", {}).get("enabled", True):
            cfg = rc.get("flooding", {})
            rules.append(FloodingRule(
                window_seconds=cfg.get("window_seconds", 10),
                threshold=cfg.get("threshold", 50),
                severity=cfg.get("severity", "critical"),
            ))

        if rc.get("lateral_movement", {}).get("enabled", True):
            cfg = rc.get("lateral_movement", {})
            rules.append(LateralMovementRule(
                window_seconds=cfg.get("window_seconds", 120),
                threshold=cfg.get("threshold", 3),
                severity=cfg.get("severity", "high"),
            ))

        print(f"[rule_engine] Loaded {len(rules)} rules: {[r.name for r in rules]}")
        return rules

    def evaluate(self, event: dict) -> list:
        """
        Evaluate a normalised event against all rules.
        Returns a list of alert dicts (may be empty).
        """
        alerts = []
        for rule in self.rules:
            alert = rule.evaluate(event)
            if alert:
                alerts.append(alert)
        return alerts

    def get_auto_block_severities(self):
        return self.config.get("containment", {}).get("auto_block_severity", ["high", "critical"])
