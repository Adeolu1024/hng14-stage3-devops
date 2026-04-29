import json
import time
import logging
import requests

logger = logging.getLogger("detector.notifier")

class Notifier:
    """Sends alerts to Slack via webhook."""

    def __init__(self, config):
        self.webhook_url = config.get("slack.webhook_url", "")
        self.channel = config.get("slack.channel", "#security-alerts")

    def send_ip_ban_alert(self, ip, reason, rate, baseline_mean, baseline_stddev, ban_duration=0):
        """Send Slack alert for a per-IP ban."""
        duration_str = f"{ban_duration:.1f} minutes" if ban_duration > 0 else "Per backoff schedule (10m, 30m, 2h, permanent)"
        payload = {
            "channel": self.channel,
            "username": "AnomalyDetector",
            "icon_emoji": ":rotating_light:",
            "blocks": [
                {
                    "type": "header",
                    "text": {"type": "plain_text", "text": "IP BLOCKED"}
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*IP:*\n{ip}"},
                        {"type": "mrkdwn", "text": f"*Condition:*\n{reason}"},
                        {"type": "mrkdwn", "text": f"*Current Rate:*\n{rate:.2f} req/s"},
                        {"type": "mrkdwn", "text": f"*Baseline:*\nmean={baseline_mean:.2f}, stddev={baseline_stddev:.2f}"},
                        {"type": "mrkdwn", "text": f"*Timestamp:*\n{time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}"},
                        {"type": "mrkdwn", "text": f"*Ban Duration:*\n{duration_str}"}
                    ]
                }
            ]
        }
        self._send(payload)

    def send_global_alert(self, reason, rate, baseline_mean, baseline_stddev):
        """Send Slack alert for a global anomaly."""
        payload = {
            "channel": self.channel,
            "username": "AnomalyDetector",
            "icon_emoji": ":globe_with_meridians:",
            "blocks": [
                {
                    "type": "header",
                    "text": {"type": "plain_text", "text": "GLOBAL ANOMALY DETECTED"}
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Condition:*\n{reason}"},
                        {"type": "mrkdwn", "text": f"*Global Rate:*\n{rate:.2f} req/s"},
                        {"type": "mrkdwn", "text": f"*Baseline:*\nmean={baseline_mean:.2f}, stddev={baseline_stddev:.2f}"},
                        {"type": "mrkdwn", "text": f"*Timestamp:*\n{time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}"}
                    ]
                }
            ]
        }
        self._send(payload)

    def send_unban_alert(self, ip, duration_minutes, ban_count):
        """Send Slack alert for an auto-unban."""
        payload = {
            "channel": self.channel,
            "username": "AnomalyDetector",
            "icon_emoji": ":unlock:",
            "blocks": [
                {
                    "type": "header",
                    "text": {"type": "plain_text", "text": "IP UNBANNED"}
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*IP:*\n{ip}"},
                        {"type": "mrkdwn", "text": f"*Ban Duration:*\n{duration_minutes:.1f} minutes"},
                        {"type": "mrkdwn", "text": f"*Ban Count:*\n#{ban_count}"},
                        {"type": "mrkdwn", "text": f"*Timestamp:*\n{time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}"}
                    ]
                }
            ]
        }
        self._send(payload)

    def _send(self, payload):
        if not self.webhook_url or "YOUR/WEBHOOK/URL" in self.webhook_url:
            logger.warning("Slack webhook not configured, skipping alert")
            return

        try:
            resp = requests.post(
                self.webhook_url,
                json=payload,
                timeout=10
            )
            if resp.status_code == 200:
                logger.info("Slack alert sent successfully")
            else:
                logger.error("Slack alert failed: %d %s", resp.status_code, resp.text)
        except Exception as e:
            logger.error("Slack alert error: %s", e)
