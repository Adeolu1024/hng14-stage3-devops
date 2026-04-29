# HNG Anomaly Detection Engine

A real-time anomaly detection system that monitors HTTP traffic to a Nextcloud instance, learns normal traffic patterns, and automatically responds to suspicious activity.

## Live URLs

- **Server IP**: `98.89.178.68`
- **Metrics Dashboard**: `http://abimbola-project1.xyz`
- **Nextcloud**: `http://98.89.178.68` (IP only, as required)

## Language Choice

**Python 3.11** was chosen for its readability, excellent ecosystem for data processing (`collections.deque`, `math`, `psutil`), and ease of explaining concepts in the blog post. Python's standard library provides all the data structures needed (deques for sliding windows, dictionaries for IP tracking) without external dependencies for core logic.

## Architecture

```
                                    ┌─────────────────┐
                                    │   Nginx Proxy   │
                                    │  (JSON logs)    │
                                    └────────┬────────┘
                                             │
                          ┌──────────────────┼──────────────────┐
                          │                  │                  │
                          ▼                  ▼                  ▼
                   ┌────────────┐    ┌────────────┐    ┌──────────────┐
                   │ Nextcloud  │    │  Detector  │    │  Dashboard   │
                   │   (Docker) │    │  (Host)    │    │  (Flask :8080)
                   └────────────┘    └─────┬──────┘    └──────────────┘
                                           │
                          ┌────────────────┼────────────────┐
                          │                │                │
                          ▼                ▼                ▼
                   ┌────────────┐    ┌────────────┐    ┌──────────────┐
                   │  Baseline  │    │  Blocker   │    │  Notifier    │
                   │  (Rolling) │    │ (iptables) │    │   (Slack)    │
                   └────────────┘    └────────────┘    └──────────────┘

  Volume: HNG-nginx-logs (Docker named volume)
  └── Nginx writes JSON logs → Detector reads read-only from host path
```

## How the Sliding Window Works

The sliding window uses Python's `collections.deque` for O(1) append and popleft operations:

1. **Per-IP Window**: Each source IP has its own `deque` storing unix timestamps of requests.
2. **Global Window**: A single `deque` stores all request timestamps.
3. **Eviction Logic**: Every time a request is added, we calculate `cutoff = now - 60 seconds`. All timestamps older than the cutoff are removed from the front of the deque using `popleft()`. This ensures the window always contains only the last 60 seconds of data.
4. **Rate Calculation**: `rate = len(deque) / 60` gives requests per second.

```python
def _evict(self, dq, cutoff):
    while dq and dq[0] < cutoff:
        dq.popleft()
```

## How the Baseline Learns

1. **Window Size**: 30-minute rolling window of per-second request counts.
2. **Recalculation Interval**: Every 60 seconds, the baseline recalculates mean and standard deviation.
3. **Per-Second Counts**: All request timestamps in the window are grouped by second. Missing seconds are filled with zeros to get a true distribution.
4. **Current Hour Preference**: If the current hour slot has 60+ samples, its stats are used as the effective baseline instead of the full 30-minute window.
5. **Floor Values**: Standard deviation is floored at 0.1 to prevent division by zero in z-score calculations.
6. **Hourly Slots**: Each hour's baseline is stored in a dictionary for historical tracking and visualization.

```python
# Floor stddev to avoid division by zero
if stddev < 0.1:
    stddev = 0.1
```

## How Detection Makes Decisions

An IP or global rate is flagged as anomalous if **either** condition fires first:

1. **Z-Score > 3.0**: `(rate - mean) / stddev > 3.0` — statistically significant deviation
2. **Rate > 5x Baseline**: `rate / mean > 5.0` — absolute spike regardless of variance

**Error Surge Handling**: If an IP's 4xx/5xx error rate exceeds 3x the baseline error rate, its z-score threshold is tightened to 60% of normal (1.8 instead of 3.0), making it easier to catch repeat offenders.

## Setup Instructions

### 1. Provision a VPS

Create a Linux VPS (Ubuntu 22.04 recommended) with at least 2 vCPU and 2 GB RAM on any provider (AWS, DigitalOcean, Hetzner, etc.).

### 2. Point a Domain/Subdomain

Create a DNS A record: `abimbola-project1.xyz` → `98.89.178.68`

### 3. Clone and Run Setup

```bash
git clone https://github.com/Adeolu1024/hng14-stage3-devops.git
cd hng14-stage3-devops
chmod +x setup.sh
sudo ./setup.sh
```

### 4. Generate Architecture Diagram

```bash
pip install matplotlib
python generate_diagram.py
```

### 5. Update Dashboard Domain

Edit `nginx/nginx.conf` and replace `monitor.yourdomain.com` with your actual domain:

```bash
sed -i 's/monitor.yourdomain.com/abimbola-project1.xyz/g' nginx/nginx.conf
docker compose down && docker compose up -d
```

### 6. Verify

```bash
# Check Docker containers
sudo docker compose ps

# Check detector service
sudo systemctl status hng-detector

# View detector logs
sudo journalctl -u hng-detector -f

# View audit log
sudo tail -f /var/log/detector/audit.log

# Access dashboard
curl http://localhost:8080
```

## Repository Structure

```
detector/
  main.py          # Entry point, orchestrates all components
  monitor.py       # Log tailing and JSON parsing
  baseline.py      # Rolling baseline calculation
  detector.py      # Anomaly detection logic
  blocker.py       # iptables IP blocking
  unbanner.py      # Auto-unban with backoff schedule
  notifier.py      # Slack webhook alerts
  dashboard.py     # Flask live metrics UI
  config.yaml      # All thresholds and settings
  requirements.txt # Python dependencies
  hng-detector.service  # systemd service file
nginx/
  nginx.conf       # Reverse proxy with JSON logging + dashboard proxy
docs/
  architecture.png # System architecture diagram
screenshots/       # Required submission screenshots
docker-compose.yml # Nextcloud + Nginx stack
setup.sh           # One-command VPS setup
README.md
```

## Screenshots

| # | Screenshot | Description |
|---|-----------|-------------|
| 1 | `tool-running.png` | Daemon processing log lines |
| 2 | `ban-slack.png` | Slack ban notification |
| 3 | `unban-slack.png` | Slack unban notification |
| 4 | `global-alert-slack.png` | Slack global anomaly alert |
| 5 | `iptables-banned.png` | `sudo iptables -L -n` showing blocked IP |
| 6 | `audit-log.png` | Structured audit log entries |
| 7 | `baseline-graph.png` | Baseline over time with hourly slots |

## Blog Post

[Read the beginner-friendly blog post here](https://dev.to/adeolu1024/building-a-real-time-http-anomaly-detection-engine-xxx)

## License

MIT
