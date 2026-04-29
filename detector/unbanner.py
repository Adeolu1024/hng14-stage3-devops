import time
import logging
import threading

logger = logging.getLogger("detector.unbanner")

class Unbanner:
    """
    Manages the auto-unban backoff schedule:
    10 min -> 30 min -> 2 hours -> permanent
    """

    def __init__(self, blocker, notifier, audit_callback=None, schedule_minutes=None):
        self.blocker = blocker
        self.notifier = notifier
        self.audit_callback = audit_callback
        self.schedule = schedule_minutes or [10, 30, 120]
        self._running = False
        self._thread = None

    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        logger.info("Unbanner started with schedule: %s minutes", self.schedule)

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)

    def _loop(self):
        while self._running:
            self._check_unbans()
            time.sleep(10)

    def _check_unbans(self):
        """Check if any blocked IPs should be unbanned based on schedule."""
        blocked = self.blocker.get_blocked_ips()
        now = time.time()

        for ip, info in list(blocked.items()):
            ban_count = info.get("ban_count", 1)
            ban_duration_sec = now - info["timestamp"]

            # Determine expected duration for this ban count
            if ban_count <= len(self.schedule):
                expected_duration = self.schedule[ban_count - 1] * 60  # convert to seconds
            else:
                # Permanent ban after all schedule steps exhausted
                continue

            if ban_duration_sec >= expected_duration:
                self._unban(ip, ban_count, ban_duration_sec)

    def _unban(self, ip, ban_count, ban_duration_sec):
        """Unban an IP and notify."""
        duration_minutes = ban_duration_sec / 60.0

        if self.blocker.unblock_ip(ip):
            logger.info("Auto-unbanned IP %s after %.1f minutes (ban #%d)", ip, duration_minutes, ban_count)
            self.notifier.send_unban_alert(ip, duration_minutes, ban_count)
            if self.audit_callback:
                self.audit_callback(
                    "UNBAN",
                    ip=ip,
                    condition=f"ban #{ban_count} expired",
                    rate="",
                    baseline="",
                    duration=f"{duration_minutes:.1f}m"
                )
