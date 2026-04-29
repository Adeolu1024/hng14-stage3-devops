import math
import time
import logging
from collections import deque

logger = logging.getLogger("detector.baseline")

class RollingBaseline:
    """
    Maintains a rolling 30-minute window of per-second request counts.
    Recalculates mean/stddev every 60 seconds.
    Prefers current hour's baseline when it has enough data.
    """

    def __init__(self, window_minutes=30, recalc_interval=60):
        self.window_minutes = window_minutes
        self.recalc_interval = recalc_interval
        # per-second counts: deque of (timestamp_second, count)
        self.second_counts = deque()
        # per-hour slots: {hour_key: [per-second counts list]}
        self.hour_slots = {}
        # current effective stats
        self.effective_mean = 0.0
        self.effective_stddev = 0.0
        self.last_recalc = 0
        self.error_rate_mean = 0.0
        self.error_second_counts = deque()

    def add_request(self, timestamp, is_error=False):
        """Record a request at the given unix timestamp."""
        sec = int(timestamp)
        self.second_counts.append(sec)
        if is_error:
            self.error_second_counts.append(sec)

    def recalculate(self, current_time=None):
        """Recalculate mean/stddev from the rolling window."""
        now = current_time or time.time()
        cutoff = now - (self.window_minutes * 60)

        # Evict old entries
        while self.second_counts and self.second_counts[0] < cutoff:
            self.second_counts.popleft()
        while self.error_second_counts and self.error_second_counts[0] < cutoff:
            self.error_second_counts.popleft()

        # Build per-second counts from the window
        if not self.second_counts:
            self.effective_mean = 0.0
            self.effective_stddev = 0.0
            self.error_rate_mean = 0.0
            self.last_recalc = now
            return

        # Group by second
        sec_map = {}
        for sec in self.second_counts:
            sec_map[sec] = sec_map.get(sec, 0) + 1

        # Fill in zeros for missing seconds to get true distribution
        total_seconds = int(now - cutoff)
        if total_seconds <= 0:
            total_seconds = 1

        counts = [sec_map.get(int(cutoff) + i, 0) for i in range(total_seconds)]

        # Calculate mean and stddev
        n = len(counts)
        mean = sum(counts) / n if n > 0 else 0
        variance = sum((c - mean) ** 2 for c in counts) / n if n > 0 else 0
        stddev = math.sqrt(variance)

        # Floor stddev to avoid division by zero
        if stddev < 0.1:
            stddev = 0.1

        # Check current hour slot
        current_hour_key = time.strftime("%Y-%m-%d-%H", time.gmtime(now))
        hour_cutoff = now - 3600  # last hour

        hour_counts = [sec_map.get(s, 0) for s in sec_map if s >= hour_cutoff]
        if len(hour_counts) >= 60:  # enough data in current hour
            hour_mean = sum(hour_counts) / len(hour_counts)
            hour_var = sum((c - hour_mean) ** 2 for c in hour_counts) / len(hour_counts)
            hour_stddev = math.sqrt(hour_var)
            if hour_stddev < 0.1:
                hour_stddev = 0.1
            self.effective_mean = hour_mean
            self.effective_stddev = hour_stddev
            logger.info(
                "Baseline recalculated (current hour): mean=%.2f, stddev=%.2f, samples=%d",
                hour_mean, hour_stddev, len(hour_counts)
            )
        else:
            self.effective_mean = mean
            self.effective_stddev = stddev
            logger.info(
                "Baseline recalculated (full window): mean=%.2f, stddev=%.2f, seconds=%d",
                mean, stddev, n
            )

        # Store hourly slot
        self.hour_slots[current_hour_key] = {
            "mean": self.effective_mean,
            "stddev": self.effective_stddev,
            "timestamp": now
        }

        # Error rate baseline
        if self.error_second_counts:
            err_sec_map = {}
            for sec in self.error_second_counts:
                err_sec_map[sec] = err_sec_map.get(sec, 0) + 1
            err_counts = [err_sec_map.get(int(cutoff) + i, 0) for i in range(total_seconds)]
            err_mean = sum(err_counts) / len(err_counts) if err_counts else 0
            self.error_rate_mean = err_mean
        else:
            self.error_rate_mean = 0.0

        self.last_recalc = now
        return {
            "mean": self.effective_mean,
            "stddev": self.effective_stddev,
            "error_rate_mean": self.error_rate_mean,
            "hour_slots": dict(self.hour_slots)
        }

    def get_stats(self):
        return {
            "mean": self.effective_mean,
            "stddev": self.effective_stddev,
            "error_rate_mean": self.error_rate_mean,
            "hour_slots": {k: v for k, v in self.hour_slots.items()}
        }
