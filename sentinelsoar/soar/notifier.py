"""
Notification System — sends alerts via email (SMTP) or webhooks.

Configuration via environment variables:
  SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, SMTP_TO
  WEBHOOK_URL (Slack / Discord incoming webhook)
"""

import os
import json
import threading

try:
    import smtplib
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart
    SMTP_AVAILABLE = True
except ImportError:
    SMTP_AVAILABLE = False

try:
    import requests as req_lib
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


class NotificationManager:
    """Multi-channel notification sender."""

    def __init__(self):
        self.smtp_config = {
            "host": os.environ.get("SMTP_HOST", ""),
            "port": int(os.environ.get("SMTP_PORT", "587")),
            "user": os.environ.get("SMTP_USER", ""),
            "password": os.environ.get("SMTP_PASSWORD", ""),
            "to": os.environ.get("SMTP_TO", ""),
        }
        self.webhook_url = os.environ.get("WEBHOOK_URL", "")
        self.lock = threading.Lock()

        channels = []
        if self.smtp_config["host"]:
            channels.append("email")
        if self.webhook_url:
            channels.append("webhook")
        channels.append("log")  # always available

        print(f"[notifier] Available channels: {', '.join(channels)}")

    def send(self, channel="log", subject="", body=""):
        """Send a notification via the specified channel."""
        if channel == "email":
            return self._send_email(subject, body)
        elif channel == "webhook":
            return self._send_webhook(subject, body)
        else:
            return self._send_log(subject, body)

    def _send_email(self, subject, body):
        """Send notification via SMTP email."""
        cfg = self.smtp_config
        if not cfg["host"] or not SMTP_AVAILABLE:
            return {"status": "skipped", "reason": "SMTP not configured"}

        try:
            msg = MIMEMultipart()
            msg["From"] = cfg["user"]
            msg["To"] = cfg["to"]
            msg["Subject"] = f"🚨 {subject}"
            msg.attach(MIMEText(body, "plain"))

            with smtplib.SMTP(cfg["host"], cfg["port"]) as server:
                server.starttls()
                server.login(cfg["user"], cfg["password"])
                server.send_message(msg)

            return {"status": "sent", "channel": "email", "to": cfg["to"]}
        except Exception as e:
            print(f"[notifier] Email error: {e}")
            return {"status": "error", "channel": "email", "error": str(e)}

    def _send_webhook(self, subject, body):
        """Send notification via webhook (Slack/Discord compatible)."""
        if not self.webhook_url or not REQUESTS_AVAILABLE:
            return {"status": "skipped", "reason": "Webhook not configured"}

        try:
            payload = {
                "text": f"🚨 *{subject}*\n{body}",
                # Discord compatibility
                "content": f"🚨 **{subject}**\n{body}",
            }
            resp = req_lib.post(
                self.webhook_url,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=10,
            )
            return {
                "status": "sent" if resp.status_code < 300 else "error",
                "channel": "webhook",
                "http_status": resp.status_code,
            }
        except Exception as e:
            print(f"[notifier] Webhook error: {e}")
            return {"status": "error", "channel": "webhook", "error": str(e)}

    def _send_log(self, subject, body):
        """Log notification to stdout (always available)."""
        print(f"[NOTIFICATION] {subject}: {body}")
        return {"status": "logged", "channel": "log"}
