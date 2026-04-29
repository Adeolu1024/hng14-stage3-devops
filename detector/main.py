#!/usr/bin/env python3
"""
HNG Anomaly Detection Engine
Main daemon that ties together log monitoring, baseline learning,
anomaly detection, IP blocking, auto-unbanning, Slack alerts, and live dashboard.
"""

import os
import sys
import time
import json
import signal
import logging
from logging.handlers import RotatingFileHandler

# Ensure the detector directory is in path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import load_config, get
from monitor import LogMonitor
from baseline import RollingBaseline
from detector import AnomalyDetector
from blocker import IPBlocker
from unbanner import Unbanner
from notifier import Notifier
from dashboard import Dashboard

# Setup logging
def setup_logging():
    log_level = get("logging.log_level", "INFO")
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)

    logging.basicConfig(
        level=numeric_level,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout),
            RotatingFileHandler(
                "/var/log/detector/detector.log",
                maxBytes=10*1024*1024,
                backupCount=5
            )
        ]
    )

# Audit logger - writes structured entries for bans, unbans, baseline recalcs
audit_logger = None

def setup_audit_logger():
    global audit_logger
    audit_path = get("logging.audit_log_path", "/var/log/detector/audit.log")
    audit_logger = logging.getLogger("audit")
    audit_logger.setLevel(logging.INFO)
    audit_handler = RotatingFileHandler(audit_path, maxBytes=10*1024*1024, backupCount=10)
    audit_handler.setFormatter(logging.Formatter("%(message)s"))
    audit_logger.addHandler(audit_handler)

def write_audit(action, ip="", condition="", rate="", baseline="", duration=""):
    """Write a structured audit log entry.
    Format: [timestamp] ACTION ip | condition | rate | baseline | duration
    """
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    audit_logger.info("[%s] %s %s | %s | %s | %s | %s",
                      ts, action, ip, condition, rate, baseline, duration)

# Global state
running = True
detector_state = {}

def signal_handler(sig, frame):
    global running
    running = False
    logging.getLogger("detector.main").info("Shutdown signal received")

def process_entry(entry, det, baseline, blocker, notifier):
    """Process a single log entry from the monitor."""
    ip = entry.get("source_ip", entry.get("remote_addr", "unknown"))
    timestamp = entry.get("_unix_ts", time.time())
    status = int(entry.get("status", 0))
    is_error = status >= 400

    # Add to sliding windows
    det.add_request(ip, timestamp, status)
    baseline.add_request(timestamp, is_error)

def detection_loop(det, baseline, blocker, notifier, config):
    """Main detection loop - runs every 5 seconds."""
    global running
    last_baseline_recalc = 0
    recalc_interval = get("detection.baseline_recalc_interval_seconds", 60)

    while running:
        now = time.time()

        # Recalculate baseline on schedule
        if now - last_baseline_recalc >= recalc_interval:
            stats = baseline.recalculate(now)
            write_audit(
                "BASELINE_RECALC",
                condition="scheduled",
                rate=f"mean={stats['mean']:.2f}",
                baseline=f"stddev={stats['stddev']:.2f}"
            )
            last_baseline_recalc = now

        stats = baseline.get_stats()
        mean = stats["mean"]
        stddev = stats["stddev"]
        error_mean = stats["error_rate_mean"]

        # Check per-IP anomalies
        for ip in list(det.ip_windows.keys()):
            if blocker.is_blocked(ip):
                continue

            is_anomaly, reason, rate, z_score = det.check_ip_anomaly(ip, mean, stddev, error_mean)
            if is_anomaly:
                blocker.block_ip(ip, reason)
                blocker.increment_ban_count(ip)
                ban_count = blocker.get_blocked_ips()[ip]["ban_count"]
                schedule = get("blocking.unban_schedule_minutes", [10, 30, 120])
                if ban_count <= len(schedule):
                    scheduled_minutes = schedule[ban_count - 1]
                    duration_str = f"{scheduled_minutes}m"
                    notifier.send_ip_ban_alert(ip, reason, rate, mean, stddev, ban_duration=scheduled_minutes)
                else:
                    duration_str = "permanent"
                    notifier.send_ip_ban_alert(ip, reason, rate, mean, stddev, ban_duration=0)
                write_audit(
                    "BAN",
                    ip=ip,
                    condition=reason,
                    rate=f"{rate:.2f} req/s",
                    baseline=f"mean={mean:.2f}, stddev={stddev:.2f}",
                    duration=duration_str
                )

        # Check global anomaly
        is_global, g_reason, g_rate, g_z = det.check_global_anomaly(mean, stddev)
        if is_global:
            notifier.send_global_alert(g_reason, g_rate, mean, stddev)
            write_audit(
                "GLOBAL_ANOMALY",
                condition=g_reason,
                rate=f"{g_rate:.2f} req/s",
                baseline=f"mean={mean:.2f}, stddev={stddev:.2f}"
            )

        time.sleep(5)

def main():
    global running

    # Ensure log directories exist
    os.makedirs("/var/log/detector", exist_ok=True)
    os.makedirs("/var/log/nginx", exist_ok=True)
    os.makedirs("/var/lib/detector", exist_ok=True)

    setup_logging()
    setup_audit_logger()
    logger = logging.getLogger("detector.main")

    logger.info("=" * 60)
    logger.info("HNG Anomaly Detection Engine starting...")
    logger.info("=" * 60)

    config = load_config()

    # Initialize components
    baseline = RollingBaseline(
        window_minutes=get("detection.baseline_window_minutes", 30),
        recalc_interval=get("detection.baseline_recalc_interval_seconds", 60)
    )

    det = AnomalyDetector(config)
    blocker = IPBlocker()
    notifier = Notifier(config)
    unbanner = Unbanner(
        blocker,
        notifier,
        audit_callback=write_audit,
        schedule_minutes=get("blocking.unban_schedule_minutes", [10, 30, 120])
    )

    # Start dashboard
    dash = Dashboard(config, det, baseline, blocker)
    dash.start()

    # Start unbanner
    unbanner.start()

    # Start log monitor
    log_path = get("nginx.log_path", "/var/lib/docker/volumes/HNG-nginx-logs/_data/hng-access.log")
    monitor = LogMonitor(log_path, lambda entry: process_entry(entry, det, baseline, blocker, notifier))
    monitor.start()

    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    logger.info("All components started. Monitoring %s", log_path)

    # Run detection loop
    try:
        detection_loop(det, baseline, blocker, notifier, config)
    except KeyboardInterrupt:
        pass
    finally:
        logger.info("Shutting down...")
        monitor.stop()
        unbanner.stop()
        logger.info("Shutdown complete.")

if __name__ == "__main__":
    main()
