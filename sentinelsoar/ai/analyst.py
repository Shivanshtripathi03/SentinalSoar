"""
AI-Powered Threat Analyst — uses Google Gemini to analyze alerts
and generate human-readable threat intelligence reports.

Set the GEMINI_API_KEY environment variable to enable.
Falls back to a structured static analysis if no key is configured.
"""

import os
import json
import time
import threading

try:
    import google.generativeai as genai
    GENAI_AVAILABLE = True
except ImportError:
    GENAI_AVAILABLE = False


# MITRE ATT&CK mapping for known rule types
MITRE_MAPPING = {
    "PORT_SCAN": {
        "tactic": "Discovery",
        "technique": "T1046 — Network Service Discovery",
        "description": "Adversary is scanning network services to identify potential targets.",
    },
    "FLOODING": {
        "tactic": "Impact",
        "technique": "T1498 — Network Denial of Service",
        "description": "Adversary is attempting to overwhelm a service with high-volume traffic.",
    },
    "BEACONING": {
        "tactic": "Command and Control",
        "technique": "T1071 — Application Layer Protocol",
        "description": "Periodic callbacks suggesting C2 communication channel.",
    },
    "LATERAL_MOVEMENT": {
        "tactic": "Lateral Movement",
        "technique": "T1021 — Remote Services",
        "description": "Adversary is pivoting across multiple internal hosts.",
    },
    "BRUTE_FORCE": {
        "tactic": "Credential Access",
        "technique": "T1110 — Brute Force",
        "description": "Adversary is attempting to gain access by trying many passwords.",
    },
    "ANOMALY_DETECTION": {
        "tactic": "Multiple",
        "technique": "N/A — Statistical Anomaly",
        "description": "Unusual traffic pattern detected that deviates from baseline behaviour.",
    },
}


class AIAnalyst:
    """AI-powered alert analysis engine."""

    def __init__(self):
        self.api_key = os.environ.get("GEMINI_API_KEY", "")
        self.model = None
        self.lock = threading.Lock()
        self._cache = {}  # alert_id -> analysis result
        self._cache_ttl = 300  # 5 minute cache

        if self.api_key and GENAI_AVAILABLE:
            try:
                genai.configure(api_key=self.api_key)
                self.model = genai.GenerativeModel("gemini-2.0-flash")
                print("[ai_analyst] Gemini AI analyst initialised")
            except Exception as e:
                print(f"[ai_analyst] Failed to initialise Gemini: {e}")
        else:
            reason = "no API key" if not self.api_key else "google-generativeai not installed"
            print(f"[ai_analyst] Running in offline mode ({reason})")

    def _build_prompt(self, alert, recent_events=None):
        """Build a structured prompt for the AI model."""
        evidence_text = "\n".join(alert.get("evidence", [])[:10])

        prompt = f"""You are a senior SOC (Security Operations Center) analyst reviewing a SentinelSOAR alert.
Analyze the following alert and provide a structured threat assessment.

ALERT DETAILS:
- Rule: {alert.get('rule', 'unknown')}
- Severity: {alert.get('severity', 'unknown')}
- Source IP: {alert.get('src_ip', 'unknown')}
- Trigger: {alert.get('trigger', 'unknown')}
- Timestamp: {alert.get('created_at', alert.get('timestamp', 'unknown'))}

RAW EVIDENCE (log lines):
{evidence_text}

"""
        if recent_events:
            event_summary = f"Recent activity from this IP: {len(recent_events)} events in the last 5 minutes."
            prompt += f"\nCONTEXT:\n{event_summary}\n"

        prompt += """
Respond ONLY with a valid JSON object (no markdown, no code fences) with these exact keys:
{
  "summary": "2-3 sentence plain English summary of the threat",
  "risk_level": "critical|high|medium|low",
  "attack_stage": "reconnaissance|weaponization|delivery|exploitation|installation|command_and_control|actions_on_objectives",
  "recommended_actions": ["action 1", "action 2", "action 3"],
  "false_positive_likelihood": "high|medium|low",
  "investigation_queries": ["what to search for in logs to investigate further"],
  "mitre_attack": {"tactic": "...", "technique": "T____", "description": "..."}
}"""
        return prompt

    def explain_alert(self, alert, recent_events=None):
        """
        Analyze an alert and return a threat intelligence report.
        Uses Gemini if available, otherwise returns a static analysis.
        """
        alert_id = alert.get("id", 0)

        # Check cache
        with self.lock:
            if alert_id in self._cache:
                cached = self._cache[alert_id]
                if time.time() - cached["_cached_at"] < self._cache_ttl:
                    return cached

        if self.model:
            result = self._ai_analysis(alert, recent_events)
        else:
            result = self._static_analysis(alert)

        # Cache result
        result["_cached_at"] = time.time()
        with self.lock:
            self._cache[alert_id] = result

        return result

    def _ai_analysis(self, alert, recent_events=None):
        """Query Gemini for AI-powered analysis."""
        try:
            prompt = self._build_prompt(alert, recent_events)
            response = self.model.generate_content(prompt)
            text = response.text.strip()

            # Strip markdown code fences if present
            if text.startswith("```"):
                text = text.split("\n", 1)[1] if "\n" in text else text[3:]
            if text.endswith("```"):
                text = text[:-3].strip()
            if text.startswith("json"):
                text = text[4:].strip()

            result = json.loads(text)
            result["source"] = "gemini-ai"
            result["alert_id"] = alert.get("id", 0)
            return result

        except Exception as e:
            print(f"[ai_analyst] Gemini error: {e}, falling back to static analysis")
            return self._static_analysis(alert)

    def _static_analysis(self, alert):
        """Provide a structured analysis without AI (offline mode)."""
        rule = alert.get("rule", "UNKNOWN")
        severity = alert.get("severity", "medium")
        src_ip = alert.get("src_ip", "unknown")
        mitre = MITRE_MAPPING.get(rule, {
            "tactic": "Unknown",
            "technique": "N/A",
            "description": "No MITRE mapping available for this rule.",
        })

        severity_actions = {
            "critical": [
                f"Immediately isolate {src_ip} from the network",
                "Escalate to incident response team",
                "Preserve all logs and evidence for forensic analysis",
                "Check for data exfiltration indicators",
            ],
            "high": [
                f"Block {src_ip} at the network perimeter",
                "Investigate all recent activity from this IP",
                "Check if any credentials were compromised",
                "Review access logs on targeted services",
            ],
            "medium": [
                f"Monitor {src_ip} for additional suspicious activity",
                "Cross-reference with threat intelligence feeds",
                "Review related alerts for correlation",
                "Consider adding to watchlist",
            ],
            "low": [
                "Log for baseline analysis",
                "No immediate action required",
                "Review during next threat hunting session",
            ],
        }

        return {
            "source": "static-analysis",
            "alert_id": alert.get("id", 0),
            "summary": (
                f"A {rule.replace('_', ' ').title()} event was detected from {src_ip}. "
                f"Severity is {severity}. {mitre['description']} "
                f"The alert was triggered by: {alert.get('trigger', 'unknown condition')}."
            ),
            "risk_level": severity,
            "attack_stage": _map_rule_to_stage(rule),
            "recommended_actions": severity_actions.get(severity, severity_actions["medium"]),
            "false_positive_likelihood": "low" if severity in ("critical", "high") else "medium",
            "investigation_queries": [
                f"Search for all events from src_ip={src_ip} in the last 24 hours",
                f"Check if {src_ip} has triggered other rules recently",
                f"Review {rule.lower()} pattern across all source IPs",
            ],
            "mitre_attack": mitre,
        }

    def summarize_logs(self, events, window_minutes=5):
        """Generate a natural language summary of recent log activity."""
        if not events:
            return {"summary": "No events in the specified window.", "source": "static"}

        # Aggregate stats
        ip_counts = {}
        source_counts = {}
        action_counts = {}
        for e in events:
            ip = e.get("src_ip", "unknown")
            ip_counts[ip] = ip_counts.get(ip, 0) + 1
            st = e.get("source_type", "unknown")
            source_counts[st] = source_counts.get(st, 0) + 1
            act = e.get("action", "unknown")
            action_counts[act] = action_counts.get(act, 0) + 1

        top_ips = sorted(ip_counts.items(), key=lambda x: -x[1])[:5]
        total = len(events)

        if self.model:
            return self._ai_log_summary(events, top_ips, source_counts, total, window_minutes)

        # Static summary
        ip_breakdown = ", ".join(f"{ip} ({cnt} events)" for ip, cnt in top_ips)
        svc_breakdown = ", ".join(f"{svc}: {cnt}" for svc, cnt in source_counts.items())

        return {
            "source": "static-analysis",
            "summary": (
                f"In the last {window_minutes} minutes: {total} total events. "
                f"Top source IPs: {ip_breakdown}. "
                f"Service breakdown: {svc_breakdown}."
            ),
            "total_events": total,
            "top_source_ips": dict(top_ips),
            "service_distribution": source_counts,
            "top_actions": dict(sorted(action_counts.items(), key=lambda x: -x[1])[:5]),
        }

    def _ai_log_summary(self, events, top_ips, source_counts, total, window_minutes):
        """Generate an AI-powered summary of recent log activity."""
        try:
            ip_data = ", ".join(f"{ip}: {cnt} events" for ip, cnt in top_ips)
            svc_data = ", ".join(f"{svc}: {cnt}" for svc, cnt in source_counts.items())
            sample_logs = "\n".join(e.get("raw", str(e)) for e in events[-10:])

            prompt = f"""You are a SOC analyst. Summarize the following SentinelSOAR activity in 3-4 concise sentences.

TIME WINDOW: Last {window_minutes} minutes
TOTAL EVENTS: {total}
TOP SOURCE IPs: {ip_data}
SERVICE DISTRIBUTION: {svc_data}

SAMPLE LOG LINES (last 10):
{sample_logs}

Be specific about what's happening. Mention any suspicious patterns.
Respond with a JSON object: {{"summary": "...", "threat_level": "none|low|medium|high|critical"}}"""

            response = self.model.generate_content(prompt)
            text = response.text.strip()
            if text.startswith("```"):
                text = text.split("\n", 1)[1] if "\n" in text else text[3:]
            if text.endswith("```"):
                text = text[:-3].strip()
            if text.startswith("json"):
                text = text[4:].strip()

            result = json.loads(text)
            result["source"] = "gemini-ai"
            result["total_events"] = total
            result["top_source_ips"] = dict(top_ips)
            result["service_distribution"] = source_counts
            return result

        except Exception as e:
            print(f"[ai_analyst] Log summary error: {e}")
            return self.summarize_logs.__wrapped__(self, events, window_minutes) if hasattr(self.summarize_logs, '__wrapped__') else {
                "source": "static-fallback",
                "summary": f"{total} events in {window_minutes}min from {len(top_ips)} IPs.",
                "total_events": total,
            }


def _map_rule_to_stage(rule):
    """Map a rule name to the cyber kill chain stage."""
    mapping = {
        "PORT_SCAN": "reconnaissance",
        "FLOODING": "actions_on_objectives",
        "BEACONING": "command_and_control",
        "LATERAL_MOVEMENT": "exploitation",
        "BRUTE_FORCE": "exploitation",
        "ANOMALY_DETECTION": "reconnaissance",
    }
    return mapping.get(rule, "reconnaissance")
