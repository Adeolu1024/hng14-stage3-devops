import time
import logging
from collections import deque

logger = logging.getLogger("detector.detector")

class AnomalyDetector:
    """
    Tracks per-IP and global request rates using deque-based sliding windows.
    Flags anomalies using z-score and rate multiplier thresholds.
    """

    def __init__(self, config):
        detection_cfg = config.get("detection", {})
        self.z_threshold = detection_cfg.get("z_score_threshold", 3.0)
        self.rate_multiplier = detection_cfg.get("rate_multiplier_threshold", 5.0)
        self.error_multiplier = detection_cfg.get("error_rate_multiplier", 3.0)
        self.window_seconds = detection_cfg.get("sliding_window_seconds", 60)

        # per-IP sliding windows: {ip: deque of timestamps}
        self.ip_windows = {}
        # per-IP error windows: {ip: deque of timestamps}
        self.ip_error_windows = {}
        # global sliding window
        self.global_window = deque()
        # global error window
        self.global_error_window = deque()
        # IPs with tightened thresholds due to error surge
        self.tightened_ips = set()

    def add_request(self, ip, timestamp, status_code):
        """Record a request in the appropriate sliding windows."""
        now = timestamp or time.time()

        # Per-IP window
        if ip not in self.ip_windows:
            self.ip_windows[ip] = deque()
            self.ip_error_windows[ip] = deque()
        self.ip_windows[ip].append(now)
        if status_code >= 400:
            self.ip_error_windows[ip].append(now)

        # Global window
        self.global_window.append(now)
        if status_code >= 400:
            self.global_error_window.append(now)

        # Evict old entries
        cutoff = now - self.window_seconds
        self._evict(self.ip_windows[ip], cutoff)
        self._evict(self.ip_error_windows[ip], cutoff)
        self._evict(self.global_window, cutoff)
        self._evict(self.global_error_window, cutoff)

    def _evict(self, dq, cutoff):
        while dq and dq[0] < cutoff:
            dq.popleft()

    def get_ip_rate(self, ip):
        """Get current request rate (req/s) for an IP."""
        if ip not in self.ip_windows:
            return 0.0
        count = len(self.ip_windows[ip])
        return count / self.window_seconds

    def get_ip_error_rate(self, ip):
        """Get current error rate (errors/s) for an IP."""
        if ip not in self.ip_error_windows:
            return 0.0
        count = len(self.ip_error_windows[ip])
        return count / self.window_seconds

    def get_global_rate(self):
        """Get current global request rate (req/s)."""
        count = len(self.global_window)
        return count / self.window_seconds

    def check_ip_anomaly(self, ip, baseline_mean, baseline_stddev, error_baseline):
        """
        Check if an IP's rate is anomalous.
        Returns (is_anomaly, reason, rate, z_score)
        """
        rate = self.get_ip_rate(ip)
        if baseline_mean <= 0:
            return False, None, rate, 0

        # Z-score check
        z_score = (rate - baseline_mean) / baseline_stddev if baseline_stddev > 0 else 0

        # Rate multiplier check
        rate_ratio = rate / baseline_mean if baseline_mean > 0 else 0

        is_anomaly = False
        reason = None

        if z_score > self.z_threshold:
            is_anomaly = True
            reason = f"z_score={z_score:.2f} > {self.z_threshold}"
        elif rate_ratio > self.rate_multiplier:
            is_anomaly = True
            reason = f"rate_ratio={rate_ratio:.2f}x > {self.rate_multiplier}x"

        # Check error surge for threshold tightening
        err_rate = self.get_ip_error_rate(ip)
        if error_baseline > 0 and err_rate > (error_baseline * self.error_multiplier):
            self.tightened_ips.add(ip)
            logger.info("Error surge for %s: tightening thresholds", ip)

        # If this IP has tightened thresholds, use lower z-score
        if ip in self.tightened_ips:
            tight_z = self.z_threshold * 0.6  # 40% lower threshold
            if z_score > tight_z and not is_anomaly:
                is_anomaly = True
                reason = f"z_score={z_score:.2f} > {tight_z:.2f} (tightened)"

        return is_anomaly, reason, rate, z_score

    def check_global_anomaly(self, baseline_mean, baseline_stddev):
        """
        Check if global traffic is anomalous.
        Returns (is_anomaly, reason, rate, z_score)
        """
        rate = self.get_global_rate()
        if baseline_mean <= 0:
            return False, None, rate, 0

        z_score = (rate - baseline_mean) / baseline_stddev if baseline_stddev > 0 else 0
        rate_ratio = rate / baseline_mean if baseline_mean > 0 else 0

        is_anomaly = False
        reason = None

        if z_score > self.z_threshold:
            is_anomaly = True
            reason = f"global z_score={z_score:.2f} > {self.z_threshold}"
        elif rate_ratio > self.rate_multiplier:
            is_anomaly = True
            reason = f"global rate_ratio={rate_ratio:.2f}x > {self.rate_multiplier}x"

        return is_anomaly, reason, rate, z_score

    def get_top_ips(self, n=10):
        """Get top N IPs by request count in the current window."""
        ip_counts = {}
        for ip, dq in self.ip_windows.items():
            ip_counts[ip] = len(dq)
        sorted_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)
        return sorted_ips[:n]
