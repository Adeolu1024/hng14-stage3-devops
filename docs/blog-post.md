# Building a Real-Time Anomaly Detection Engine to Protect Cloud Storage

> How I built a system that watches HTTP traffic, learns what "normal" looks like, and automatically blocks attackers — all in Python.

If you've ever run a public-facing web service, you know the feeling: you check your logs and see thousands of requests from a single IP, or your server suddenly slows down because of a traffic spike. Traditional tools like Fail2Ban are great, but what if you want something that **learns** what normal traffic looks like and adapts automatically?

That's exactly what I built for this project: a real-time anomaly detection engine that sits alongside a Nextcloud instance, monitors every HTTP request, and blocks suspicious IPs before they can do damage.

Let me walk you through how it works — no prior security experience needed.

---

## What This Project Does

Imagine you run a cloud storage platform (like Google Drive or Dropbox) that serves users worldwide. Your server receives HTTP requests 24/7. Most of the time, traffic looks normal: a few hundred requests per second from various IPs around the world.

But then something changes:
- **Scenario 1**: A single IP starts sending 500 requests per second, trying to brute-force login credentials.
- **Scenario 2**: A botnet floods your server with 10,000 requests per second from thousands of IPs.

Your detection engine needs to catch both — and it needs to do it **automatically**, without you staring at logs at 3 AM.

Here's the high-level flow:

```
HTTP Request → Nginx (logs it as JSON) → Detector (reads log) → Is it anomalous?
    → YES: Block IP with iptables + Alert Slack
    → NO: Continue monitoring
```

---

## The Sliding Window: Your "Recent Memory"

The first concept to understand is the **sliding window**. Think of it like your short-term memory — it only remembers what happened in the last 60 seconds.

### How It Works

We use Python's `collections.deque` (double-ended queue) to store timestamps:

```python
from collections import deque

# Each IP gets its own deque
ip_windows = {
    "192.168.1.100": deque([1706000001.0, 1706000002.5, 1706000003.1, ...]),
    "10.0.0.50": deque([1706000001.2, 1706000004.0, ...]),
}

# One global deque for ALL requests
global_window = deque([1706000001.0, 1706000001.2, 1706000002.5, ...])
```

### The Eviction Logic

Here's the key part — every time a new request comes in, we remove old entries:

```python
def add_request(self, ip, timestamp):
    now = timestamp
    self.ip_windows[ip].append(now)
    self.global_window.append(now)

    # Remove anything older than 60 seconds
    cutoff = now - 60
    while self.ip_windows[ip][0] < cutoff:
        self.ip_windows[ip].popleft()
    while self.global_window[0] < cutoff:
        self.global_window.popleft()
```

**Why a deque?** Because `popleft()` is O(1) — it takes the same amount of time whether you have 10 entries or 10 million. A regular list would be O(n) because it has to shift all remaining elements.

### Calculating the Rate

Once we have the window, calculating the request rate is simple:

```python
rate = len(ip_windows[ip]) / 60  # requests per second
```

If an IP has 300 entries in its window, its rate is `300 / 60 = 5.0 req/s`.

---

## The Baseline: Learning What "Normal" Looks Like

The sliding window tells us the **current** rate. But is 5 req/s high or low? That depends on what's normal for your server. This is where the **rolling baseline** comes in.

### How It Works

1. **Collect per-second counts**: For the last 30 minutes, count how many requests arrived in each second.
2. **Calculate statistics**: Compute the mean (average) and standard deviation (how much the data varies).
3. **Recalculate every 60 seconds**: The baseline updates continuously as new data arrives.

```python
import math

# Example: per-second counts over 30 minutes
counts = [2, 3, 1, 5, 2, 4, 3, 2, ...]  # 1800 values (30 min × 60 sec)

mean = sum(counts) / len(counts)          # e.g., 2.5 req/s
variance = sum((c - mean)**2 for c in counts) / len(counts)
stddev = math.sqrt(variance)               # e.g., 1.2
```

### Why Standard Deviation Matters

The standard deviation tells us how "spread out" the data is:
- **Low stddev (0.5)**: Traffic is very consistent. A spike to 5 req/s is definitely anomalous.
- **High stddev (10.0)**: Traffic varies a lot. A spike to 5 req/s might be normal.

### The Current Hour Preference

Here's a clever optimization: if the current hour has enough data (60+ samples), we use **that hour's** baseline instead of the full 30-minute window. This makes the baseline more responsive to recent patterns:

```python
current_hour_key = time.strftime("%Y-%m-%d-%H", time.gmtime(now))
hour_counts = [counts for seconds in the current hour]

if len(hour_counts) >= 60:
    # Use current hour's stats — more responsive
    effective_mean = mean(hour_counts)
    effective_stddev = stddev(hour_counts)
else:
    # Fall back to full 30-minute window
    effective_mean = mean(all_counts)
    effective_stddev = stddev(all_counts)
```

### Preventing Division by Zero

What if traffic is perfectly flat (every second has exactly 2 requests)? The stddev would be 0, and dividing by zero crashes the program. So we floor it:

```python
if stddev < 0.1:
    stddev = 0.1  # Minimum value to prevent division by zero
```

---

## The Detection Logic: Making the Decision

Now we have:
- **Current rate** (from the sliding window)
- **Baseline mean and stddev** (from the rolling baseline)

How do we decide if something is anomalous? We use **two checks**, and whichever fires first wins:

### Check 1: Z-Score

The z-score tells us how many standard deviations the current rate is from the mean:

```python
z_score = (current_rate - baseline_mean) / baseline_stddev

if z_score > 3.0:
    # ANOMALY! This is a statistically significant deviation
    block_ip()
```

A z-score of 3.0 means the current rate is 3 standard deviations above normal. In a normal distribution, this happens less than 0.3% of the time — so it's very likely an attack.

### Check 2: Rate Multiplier

Sometimes the stddev is high (traffic is naturally variable), so the z-score doesn't trigger. That's where the rate multiplier comes in:

```python
rate_ratio = current_rate / baseline_mean

if rate_ratio > 5.0:
    # ANOMALY! Traffic is 5x the normal rate
    block_ip()
```

This catches attacks that are obvious in absolute terms, even if the variance is high.

### The "Whichever Fires First" Logic

```python
is_anomaly = False
reason = None

if z_score > 3.0:
    is_anomaly = True
    reason = f"z_score={z_score:.2f} > 3.0"
elif rate_ratio > 5.0:
    is_anomaly = True
    reason = f"rate_ratio={rate_ratio:.2f}x > 5.0x"
```

### Error Surge: Tightening Thresholds for Repeat Offenders

If an IP is sending lots of 4xx/5xx errors (failed logins, forbidden requests, etc.), we tighten its detection threshold:

```python
if ip_error_rate > (baseline_error_rate * 3.0):
    # This IP is making lots of errors — lower the bar for blocking
    tight_z_score = 3.0 * 0.6  # 1.8 instead of 3.0

    if z_score > tight_z_score:
        block_ip()
```

This means an IP that's already behaving suspiciously (lots of errors) gets blocked more easily.

---

## Blocking with iptables: The Nuclear Option

Once we've decided an IP is anomalous, we need to stop it. We use **iptables**, Linux's built-in firewall:

```python
import subprocess

def block_ip(ip):
    cmd = ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
    subprocess.run(cmd, check=True)
```

What this does:
- `-A INPUT`: Append a rule to the INPUT chain (incoming traffic)
- `-s ip`: Match packets from this source IP
- `-j DROP`: Drop them silently (no response sent back)

The blocked IP can no longer reach your server at all. It's like changing the locks on your door.

### Auto-Unban: The Backoff Schedule

But what if it was a false positive? We don't want to block legitimate users forever. So we implement a **backoff schedule**:

1. **First ban**: 10 minutes
2. **Second ban**: 30 minutes
3. **Third ban**: 2 hours
4. **After that**: Permanent

```python
schedule = [10, 30, 120]  # minutes

ban_count = get_ban_count(ip)
if ban_count <= len(schedule):
    unban_after = schedule[ban_count - 1] * 60  # convert to seconds
else:
    # Permanent ban
    return
```

A background thread checks every 10 seconds if any bans have expired:

```python
while running:
    for ip, info in blocked_ips.items():
        ban_duration = now - info["timestamp"]
        if ban_duration >= expected_duration:
            unblock_ip(ip)
            send_slack_alert(f"Unbanned {ip} after {ban_duration} minutes")
    time.sleep(10)
```

---

## The Live Dashboard

All of this runs in the background, but you need to see what's happening. I built a Flask web dashboard that shows:

- **Banned IPs** with their ban duration
- **Global request rate** (req/s)
- **Top 10 source IPs** by request count
- **CPU and memory usage**
- **Baseline statistics** (mean, stddev, hourly slots)
- **System uptime**

The page auto-refreshes every 3 seconds so you always see the latest data.

---

## Putting It All Together

Here's the complete flow when an attack hits:

```
1. Attacker sends 500 req/s from 192.168.1.100
2. Nginx logs each request as JSON to /var/log/nginx/hng-access.log
3. Detector's LogMonitor reads each line in real-time
4. Sliding window records the timestamp for 192.168.1.100
5. After 60 seconds: rate = 500/60 = 8.33 req/s
6. Baseline says normal is mean=2.5, stddev=1.2
7. Z-score = (8.33 - 2.5) / 1.2 = 4.86 > 3.0 → ANOMALY!
8. Detector calls iptables -A INPUT -s 192.168.1.100 -j DROP
9. Slack alert fires: "IP BLOCKED: 192.168.1.100 | z_score=4.86 | 8.33 req/s"
10. Audit log records: [2024-01-23T15:30:00Z] BAN 192.168.1.100 | z_score=4.86 | 8.33 req/s | mean=2.50, stddev=1.20 | per backoff schedule
11. After 10 minutes, unbanner removes the iptables rule
12. Slack alert: "IP UNBANNED: 192.168.1.100 after 10.0 minutes"
```

---

## What I Learned

Building this taught me several important lessons:

1. **Deques are perfect for sliding windows** — O(1) eviction makes them ideal for real-time processing.
2. **Z-scores are powerful but not perfect** — that's why combining them with a rate multiplier catches edge cases.
3. **Running iptables from Python is straightforward** — `subprocess.run()` is all you need.
4. **Baselines must adapt** — hardcoded thresholds fail when traffic patterns change. A rolling baseline that learns from actual data is far more robust.

---

## Try It Yourself

The full code is open source on GitHub: [github.com/YOUR_USERNAME/hng-anomaly-detector](https://github.com/YOUR_USERNAME/hng-anomaly-detector)

You can deploy it on any Linux VPS with 2 vCPU and 2GB RAM in under 10 minutes. The setup script handles everything.

---

*This project was built for HNG's cloud.ng anomaly detection challenge. All code is original — no Fail2Ban, no rate-limiting libraries, just pure Python and iptables.*
