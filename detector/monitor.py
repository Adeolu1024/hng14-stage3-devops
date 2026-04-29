import json
import time
import logging
from datetime import datetime, timezone
from collections import deque
from threading import Thread, Lock

logger = logging.getLogger("detector.monitor")

def parse_iso8601(ts_str):
    """Convert ISO 8601 timestamp string to unix epoch float."""
    try:
        # Handle formats like "2024-01-15T10:30:00+00:00" or "2024-01-15T10:30:00Z"
        ts_str = ts_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(ts_str)
        return dt.timestamp()
    except (ValueError, AttributeError):
        return time.time()

class LogMonitor:
    """Continuously tails the Nginx JSON access log and feeds parsed entries to callbacks."""

    def __init__(self, log_path, on_entry):
        self.log_path = log_path
        self.on_entry = on_entry
        self._stop = False
        self._thread = None

    def start(self):
        self._thread = Thread(target=self._tail, daemon=True)
        self._thread.start()
        logger.info("LogMonitor started on %s", self.log_path)

    def stop(self):
        self._stop = True
        if self._thread:
            self._thread.join(timeout=5)

    def _tail(self):
        """Tail the log file, reopening on rotation."""
        while not self._stop:
            try:
                with open(self.log_path, "r") as f:
                    f.seek(0, 2)  # seek to end
                    while not self._stop:
                        line = f.readline()
                        if not line:
                            time.sleep(0.1)
                            continue
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            entry = json.loads(line)
                            # Convert ISO 8601 timestamp to unix epoch
                            raw_ts = entry.get("timestamp")
                            if raw_ts:
                                entry["_unix_ts"] = parse_iso8601(raw_ts)
                            else:
                                entry["_unix_ts"] = time.time()
                            self.on_entry(entry)
                        except json.JSONDecodeError:
                            logger.debug("Skipping non-JSON line: %s", line[:80])
            except FileNotFoundError:
                time.sleep(1)
            except Exception as e:
                logger.error("Monitor error: %s", e)
                time.sleep(1)
