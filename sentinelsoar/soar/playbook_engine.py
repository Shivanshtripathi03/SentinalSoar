"""
SOAR Playbook Engine — matches alerts to playbooks and executes
ordered response actions automatically.

Playbooks are defined in config/playbooks.yaml and executed when
alerts are created. Each playbook has:
  - name: human-readable name
  - trigger_rules: list of rule names that activate this playbook
  - severity_filter: minimum severity to activate (optional)
  - actions: ordered list of action names with optional parameters
"""

import os
import time
import yaml
import threading
from datetime import datetime, timezone, timedelta
from collections import deque

from sentinelsoar.soar.actions import ACTION_REGISTRY

IST = timezone(timedelta(hours=5, minutes=30))


class PlaybookEngine:
    """Loads and executes SOAR playbooks based on alert rules."""

    def __init__(self, config_path="/app/config/playbooks.yaml"):
        self.playbooks = self._load_playbooks(config_path)
        self.execution_log = deque(maxlen=200)
        self.lock = threading.Lock()
        self._context_providers = {}  # injectable dependencies

    def _load_playbooks(self, path):
        """Load playbook definitions from YAML."""
        try:
            with open(path, "r") as f:
                data = yaml.safe_load(f) or {}
                playbooks = data.get("playbooks", [])
                print(f"[soar] Loaded {len(playbooks)} playbooks")
                return playbooks
        except FileNotFoundError:
            print(f"[soar] No playbook config at {path}, using defaults")
            return self._default_playbooks()
        except Exception as e:
            print(f"[soar] Error loading playbooks: {e}, using defaults")
            return self._default_playbooks()

    def _default_playbooks(self):
        """Built-in default playbooks if no config file exists."""
        return [
            {
                "name": "Flooding Response",
                "trigger_rules": ["FLOODING"],
                "actions": [
                    {"action": "block_ip"},
                    {"action": "enrich_ip"},
                    {"action": "notify", "params": {"channel": "log"}},
                    {"action": "log_incident"},
                ],
            },
            {
                "name": "Port Scan Response",
                "trigger_rules": ["PORT_SCAN"],
                "actions": [
                    {"action": "block_ip"},
                    {"action": "enrich_ip"},
                    {"action": "log_incident"},
                ],
            },
            {
                "name": "Brute Force Response",
                "trigger_rules": ["BRUTE_FORCE"],
                "actions": [
                    {"action": "block_ip"},
                    {"action": "enrich_ip"},
                    {"action": "notify", "params": {"channel": "log"}},
                    {"action": "log_incident"},
                ],
            },
            {
                "name": "Beaconing Investigation",
                "trigger_rules": ["BEACONING"],
                "actions": [
                    {"action": "enrich_ip"},
                    {"action": "add_to_watchlist", "params": {"duration": "48h"}},
                    {"action": "notify", "params": {"channel": "log"}},
                    {"action": "log_incident"},
                ],
            },
            {
                "name": "Lateral Movement Response",
                "trigger_rules": ["LATERAL_MOVEMENT"],
                "actions": [
                    {"action": "block_ip"},
                    {"action": "enrich_ip"},
                    {"action": "escalate"},
                    {"action": "notify", "params": {"channel": "log"}},
                    {"action": "log_incident"},
                ],
            },
            {
                "name": "Anomaly Investigation",
                "trigger_rules": ["ANOMALY_DETECTION"],
                "actions": [
                    {"action": "enrich_ip"},
                    {"action": "add_to_watchlist", "params": {"duration": "24h"}},
                    {"action": "log_incident"},
                ],
            },
        ]

    def register_providers(self, **providers):
        """Register service providers for action context injection."""
        self._context_providers.update(providers)

    def execute_for_alert(self, alert: dict) -> list:
        """
        Find and execute all matching playbooks for an alert.
        Returns list of execution results.
        """
        rule = alert.get("rule", "")
        results = []

        for playbook in self.playbooks:
            triggers = playbook.get("trigger_rules", [])
            if rule in triggers:
                result = self._execute_playbook(playbook, alert)
                results.append(result)

        return results

    def _execute_playbook(self, playbook: dict, alert: dict) -> dict:
        """Execute a single playbook for an alert."""
        playbook_name = playbook.get("name", "Unnamed")
        start_time = time.time()

        # Build context from alert + injected providers
        context = {
            "rule": alert.get("rule", ""),
            "severity": alert.get("severity", ""),
            "src_ip": alert.get("src_ip", ""),
            "trigger": alert.get("trigger", ""),
            "timestamp": alert.get("timestamp", alert.get("created_at", "")),
            "alert_id": alert.get("id", 0),
            "evidence": alert.get("evidence", []),
        }
        # Inject service providers (prefixed with _)
        for key, provider in self._context_providers.items():
            context[f"_{key}"] = provider

        action_results = []
        for step in playbook.get("actions", []):
            action_name = step.get("action", "")
            params = step.get("params", {})

            action_fn = ACTION_REGISTRY.get(action_name)
            if not action_fn:
                action_results.append({
                    "action": action_name,
                    "status": "error",
                    "reason": f"Unknown action: {action_name}",
                })
                continue

            try:
                result = action_fn(context, **params)
                result["action"] = action_name
                action_results.append(result)
            except Exception as e:
                action_results.append({
                    "action": action_name,
                    "status": "error",
                    "reason": str(e),
                })

        execution = {
            "playbook": playbook_name,
            "alert_id": alert.get("id", 0),
            "rule": alert.get("rule", ""),
            "src_ip": alert.get("src_ip", ""),
            "executed_at": datetime.now(IST).strftime("%Y-%m-%dT%H:%M:%S+05:30"),
            "duration_ms": round((time.time() - start_time) * 1000, 1),
            "actions": action_results,
        }

        with self.lock:
            self.execution_log.append(execution)

        print(
            f"[SOAR] Playbook '{playbook_name}' executed for {alert.get('rule', '?')} "
            f"from {alert.get('src_ip', '?')} — {len(action_results)} actions in {execution['duration_ms']}ms"
        )

        return execution

    def get_execution_log(self, limit=50) -> list:
        """Return recent playbook executions."""
        with self.lock:
            return list(self.execution_log)[-limit:]
