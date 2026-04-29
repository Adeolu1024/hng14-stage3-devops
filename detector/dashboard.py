import time
import psutil
import logging
from flask import Flask, jsonify, render_template_string

logger = logging.getLogger("detector.dashboard")

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>HNG Anomaly Detector - Live Metrics</title>
    <meta http-equiv="refresh" content="{{ refresh_interval }}">
    <style>
        body { font-family: monospace; background: #1a1a2e; color: #e0e0e0; margin: 20px; }
        h1 { color: #00ff88; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
        .card { background: #16213e; border: 1px solid #0f3460; border-radius: 8px; padding: 15px; }
        .card h2 { color: #e94560; margin-top: 0; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 8px; text-align: left; border-bottom: 1px solid #0f3460; }
        th { color: #00ff88; }
        .metric { font-size: 2em; color: #00ff88; }
        .banned { color: #e94560; }
    </style>
</head>
<body>
    <h1>HNG Anomaly Detector - Live Dashboard</h1>
    <p>Last updated: {{ timestamp }} | Uptime: {{ uptime }}</p>

    <div class="grid">
        <div class="card">
            <h2>Global Traffic</h2>
            <div class="metric">{{ global_rate }} req/s</div>
            <p>Baseline mean: {{ baseline_mean }} | stddev: {{ baseline_stddev }}</p>
        </div>

        <div class="card">
            <h2>System Resources</h2>
            <p>CPU: {{ cpu_percent }}%</p>
            <p>Memory: {{ memory_percent }}% ({{ memory_used }} / {{ memory_total }} MB)</p>
        </div>

        <div class="card">
            <h2>Banned IPs ({{ banned_count }})</h2>
            {% if banned_ips %}
            <table>
                <tr><th>IP</th><th>Since</th><th>Duration</th></tr>
                {% for ip, info in banned_ips.items() %}
                <tr class="banned">
                    <td>{{ ip }}</td>
                    <td>{{ info.time_str }}</td>
                    <td>{{ info.duration_str }}</td>
                </tr>
                {% endfor %}
            </table>
            {% else %}
            <p>No IPs currently banned.</p>
            {% endif %}
        </div>

        <div class="card">
            <h2>Top 10 Source IPs</h2>
            <table>
                <tr><th>Rank</th><th>IP</th><th>Requests (last 60s)</th></tr>
                {% for rank, ip, count in top_ips %}
                <tr><td>{{ rank }}</td><td>{{ ip }}</td><td>{{ count }}</td></tr>
                {% endfor %}
            </table>
        </div>

        <div class="card">
            <h2>Baseline Stats</h2>
            <p>Effective Mean: {{ baseline_mean }}</p>
            <p>Effective StdDev: {{ baseline_stddev }}</p>
            <p>Error Rate Mean: {{ error_rate_mean }}</p>
            <p>Hourly Slots:</p>
            <table>
                <tr><th>Hour</th><th>Mean</th><th>StdDev</th></tr>
                {% for hour, stats in hour_slots.items() %}
                <tr><td>{{ hour }}</td><td>{{ stats.mean }}</td><td>{{ stats.stddev }}</td></tr>
                {% endfor %}
            </table>
        </div>
    </div>
</body>
</html>
"""

class Dashboard:
    """Flask-based live metrics dashboard."""

    def __init__(self, config, detector, baseline, blocker):
        self.host = config.get("dashboard.host", "0.0.0.0")
        self.port = config.get("dashboard.port", 8080)
        self.refresh = config.get("dashboard.refresh_interval_seconds", 3)
        self.detector = detector
        self.baseline = baseline
        self.blocker = blocker
        self.start_time = time.time()
        self.app = Flask(__name__)
        self._setup_routes()

    def _setup_routes(self):
        @self.app.route("/")
        def index():
            now = time.time()
            uptime = now - self.start_time
            hours = int(uptime // 3600)
            mins = int((uptime % 3600) // 60)
            secs = int(uptime % 60)

            banned = self.blocker.get_blocked_ips()
            banned_formatted = {}
            for ip, info in banned.items():
                dur = now - info["timestamp"]
                banned_formatted[ip] = {
                    "time_str": time.strftime("%H:%M:%S", time.gmtime(info["timestamp"])),
                    "duration_str": f"{dur/60:.1f}m"
                }

            top = self.detector.get_top_ips(10)
            top_formatted = [(i+1, ip, count) for i, (ip, count) in enumerate(top)]

            stats = self.baseline.get_stats()
            hour_slots = stats.get("hour_slots", {})

            mem = psutil.virtual_memory()

            return render_template_string(
                HTML_TEMPLATE,
                refresh_interval=self.refresh,
                timestamp=time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
                uptime=f"{hours}h {mins}m {secs}s",
                global_rate=f"{self.detector.get_global_rate():.2f}",
                baseline_mean=f"{stats['mean']:.2f}",
                baseline_stddev=f"{stats['stddev']:.2f}",
                error_rate_mean=f"{stats['error_rate_mean']:.2f}",
                cpu_percent=psutil.cpu_percent(interval=0),
                memory_percent=mem.percent,
                memory_used=mem.used // (1024*1024),
                memory_total=mem.total // (1024*1024),
                banned_count=len(banned),
                banned_ips=banned_formatted,
                top_ips=top_formatted,
                hour_slots=hour_slots
            )

        @self.app.route("/api/metrics")
        def api_metrics():
            stats = self.baseline.get_stats()
            return jsonify({
                "global_rate": self.detector.get_global_rate(),
                "baseline": stats,
                "banned_ips": self.blocker.get_blocked_ips(),
                "top_ips": self.detector.get_top_ips(10),
                "uptime": time.time() - self.start_time,
                "cpu": psutil.cpu_percent(interval=0),
                "memory": psutil.virtual_memory().percent
            })

    def start(self):
        """Start dashboard in a background thread."""
        import threading
        t = threading.Thread(
            target=self.app.run,
            kwargs={"host": self.host, "port": self.port, "debug": False, "use_reloader": False},
            daemon=True
        )
        t.start()
        logger.info("Dashboard started on %s:%d", self.host, self.port)
