import subprocess
import logging
import time

logger = logging.getLogger("detector.blocker")

class IPBlocker:
    """Manages iptables DROP rules for blocking malicious IPs."""

    def __init__(self):
        self._blocked = {}  # ip -> {timestamp, ban_count}

    def block_ip(self, ip, reason=""):
        """Add an iptables DROP rule for the given IP."""
        if ip in self._blocked:
            logger.info("IP %s already blocked, skipping", ip)
            return False

        try:
            cmd = ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
            subprocess.run(cmd, check=True, timeout=10)
            self._blocked[ip] = {
                "timestamp": time.time(),
                "ban_count": 1
            }
            logger.info("Blocked IP %s: %s", ip, reason)
            return True
        except subprocess.CalledProcessError as e:
            logger.error("Failed to block IP %s: %s", ip, e)
            return False
        except Exception as e:
            logger.error("Unexpected error blocking IP %s: %s", ip, e)
            return False

    def unblock_ip(self, ip):
        """Remove the iptables DROP rule for the given IP."""
        if ip not in self._blocked:
            return False

        try:
            cmd = ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
            subprocess.run(cmd, check=True, timeout=10)
            del self._blocked[ip]
            logger.info("Unblocked IP %s", ip)
            return True
        except subprocess.CalledProcessError as e:
            logger.error("Failed to unblock IP %s: %s", ip, e)
            return False
        except Exception as e:
            logger.error("Unexpected error unblocking IP %s: %s", ip, e)
            return False

    def is_blocked(self, ip):
        return ip in self._blocked

    def get_blocked_ips(self):
        return dict(self._blocked)

    def get_ban_duration(self, ip):
        if ip not in self._blocked:
            return 0
        return time.time() - self._blocked[ip]["timestamp"]

    def increment_ban_count(self, ip):
        if ip in self._blocked:
            self._blocked[ip]["ban_count"] += 1
