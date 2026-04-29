# I Built an Anomaly Detector in Python and It Actually Caught Real Hackers

> No Fail2Ban. No fancy libraries. Just Python, iptables, and a lot of trial and error.

**Live URLs**
- **Dashboard**: [http://abimbola-project1.xyz](http://abimbola-project1.xyz)
- **Nextcloud**: [http://98.89.178.68](http://98.89.178.68) (IP only, as required)
- **GitHub**: [github.com/Adeolu1024/hng14-stage3-devops](https://github.com/Adeolu1024/hng14-stage3-devops)

---

Okay so picture this: it's 2 AM, I'm supposed to be sleeping, but instead I'm staring at my server logs. And I see it. Some IP from who-knows-where is absolutely hammering my Nextcloud instance. Like, hundreds of requests per minute. My first thought? "Oh great, here we go."

I could've just installed Fail2Ban and called it a day. But where's the fun in that? Plus, I wanted something that actually *learns* what normal traffic looks like instead of using hardcoded rules that break the moment your traffic pattern changes.

So I built my own real-time anomaly detector. And honestly? It actually works. Let me show you how.

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

## The Setup (Or: How I Stopped Worrying and Learned to Love Docker)

I'm running a Nextcloud instance on an AWS EC2 `t3.small` (Ubuntu 24.04, because I'm fancy like that). Nextcloud sits behind Nginx, which logs every request as JSON. Here's the cool part — those logs get written to a Docker named volume called `HNG-nginx-logs`, and my Python detector reads them directly from the host.

The detector runs as a systemd service on the host (not in Docker — I learned the hard way that `network_mode: host` and iptables inside containers do *not* play nice). So it's:

- **Docker**: Nextcloud + Nginx + MariaDB
- **Host**: Python detector + iptables + Flask dashboard on port 8080

Simple enough, right? Haha. We'll get to the part where I spent 3 hours debugging why iptables rules weren't showing up. Spoiler: it was because systemd runs things with a different PATH and `iptables` wasn't in it. Had to use the full path `/usr/sbin/iptables`. Classic.

---

## The Sliding Window: Your "Recent Memory"

Alright, let's talk about the actual detection. The first thing you need is a way to track "how many requests did this IP make in the last 60 seconds?"

I started with a regular Python list. Bad idea. Every time you remove old entries from the front, Python has to shift everything else. With thousands of requests, that's O(n) and your CPU cries.

Enter `collections.deque`. Double-ended queue. `append()` on the right, `popleft()` on the left, both O(1). Doesn't matter if you have 10 entries or 10 million — same speed.

```python
from collections import deque

class SlidingWindow:
    def __init__(self, window_sec=60):
        self.window_sec = window_sec
        self.global_window = deque()
        self.ip_windows = {}

    def add(self, ip, timestamp):
        if ip not in self.ip_windows:
            self.ip_windows[ip] = deque()

        self.ip_windows[ip].append(timestamp)
        self.global_window.append(timestamp)

        # Evict old stuff
        cutoff = timestamp - self.window_sec
        while self.ip_windows[ip] and self.ip_windows[ip][0] < cutoff:
            self.ip_windows[ip].popleft()
        while self.global_window and self.global_window[0] < cutoff:
            self.global_window.popleft()
```

See that `while` loop? That's the eviction logic. Anything older than 60 seconds gets booted. And because it's a deque, it's fast. I measured it — even under load, this takes microseconds.

Rate calculation is dead simple then:
```python
rate = len(self.ip_windows[ip]) / 60.0  # requests per second
```

---

## The Baseline: Learning What "Normal" Means

Okay so now I know an IP is doing 5 req/s. Is that bad? Well... it depends. If my server normally gets 0.1 req/s, then yeah, 5 is sus. But if I'm having a busy day and normal is 4 req/s, then 5 is totally fine.

This is where most simple rate-limiters fail. They use hardcoded thresholds like "block anyone above 10 req/s." But what if your baseline *is* 10 req/s? Now you're blocking legitimate traffic.

So I built a **rolling baseline** that learns from actual traffic:

1. Look at the last 30 minutes of data
2. Count requests per second (so you get ~1800 data points)
3. Calculate mean and standard deviation
4. Recalculate every 60 seconds

```python
import math

# Example: per-second counts over 30 minutes
counts = [2, 3, 1, 5, 2, 4, 3, 2, ...]  # 1800 values (30 min × 60 sec)

mean = sum(counts) / len(counts)          # e.g., 2.5 req/s
variance = sum((c - mean)**2 for c in counts) / len(counts)
stddev = math.sqrt(variance)               # e.g., 1.2
```

The standard deviation is the key here. It measures how "spread out" your traffic is. Low stddev means traffic is predictable — even a small spike is suspicious. High stddev means traffic is all over the place — you need a bigger spike to trigger an alert.

Oh and I added this "current hour preference" thing. If the current hour has 60+ samples, I use that hour's stats instead of the full 30-minute window. Makes it more responsive to recent patterns. Learned that one from staring at graphs for way too long.

### Preventing Division by Zero

What if traffic is perfectly flat (every second has exactly 2 requests)? The stddev would be 0, and dividing by zero crashes the program. So we floor it:

```python
if stddev < 0.1:
    stddev = 0.1  # Minimum value to prevent division by zero
```

---

## Detection: The "Is This an Attack?" Logic

So I've got:
- Current rate from the sliding window
- Baseline mean and stddev from the rolling calculator

Now I need to decide: **anomaly or not?**

I use two checks. Either one can trigger a ban:

**Check 1: Z-Score**
```python
z_score = (current_rate - baseline_mean) / baseline_stddev
if z_score > 3.0:
    # This is statistically significant. Less than 0.3% chance it's normal.
    block_it()
```

**Check 2: Rate Multiplier**
```python
rate_ratio = current_rate / baseline_mean
if rate_ratio > 5.0:
    # Even if variance is high, 5x normal is obviously wrong
    block_it()
```

The z-score catches subtle attacks during quiet periods. The rate multiplier catches obvious floods even when traffic is naturally noisy. Together they cover almost everything.

And here's a neat trick I added: if an IP is throwing lots of 4xx/5xx errors (failed logins, forbidden pages, etc.), I tighten its threshold. Instead of z > 3.0, I use z > 1.8. Because if you're already failing repeatedly, you're probably up to no good.

```python
if ip_error_rate > baseline_error_rate * 3.0:
    threshold = 3.0 * 0.6  # 1.8 instead of 3.0
else:
    threshold = 3.0
```

---

## Blocking: Going Nuclear with iptables

Once we detect an anomaly, we need to stop it. I use iptables because it's already there on every Linux box — no extra software needed.

```python
import subprocess

def block_ip(ip):
    cmd = ["/usr/sbin/iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
    subprocess.run(cmd, check=True)
```

`-j DROP` means silently discard packets. The attacker gets no response. They don't even know they're blocked — they just think your server is down. Beautiful.

But wait — permanent bans are dangerous. What if it's a false positive? A legit user with a script that went haywire? So I built an auto-unban system with a backoff schedule:

- 1st ban: 10 minutes
- 2nd ban: 30 minutes
- 3rd ban: 2 hours
- 4th+ ban: permanent (you had your chances)

A background thread checks every 10 seconds:
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

## The Dashboard: Because Pretty Charts Matter

I built a Flask dashboard on port 8080. It shows:
- Live global request rate
- Banned IPs with countdown timers
- Top 10 source IPs
- CPU/memory usage
- Baseline stats with hourly breakdowns

Auto-refreshes every 3 seconds. Served through Nginx at [http://abimbola-project1.xyz](http://abimbola-project1.xyz) (yes, I bought a domain for this, no regrets).

The first version of the dashboard was ugly as sin. Pure HTML tables, no CSS. My eyes bled. So I added some basic styling. Still not winning design awards, but it gets the job done.

---

## It Actually Caught Real Attackers

Here's the crazy part. Within an hour of deploying this to the public internet, it started catching actual malicious traffic. Like, real scanners and bots.

I watched the Slack notifications roll in:
- `IP BLOCKED: 204.76.203.206 | rate_ratio=30.00x | 3.00 req/s`
- `IP BLOCKED: 85.217.149.16 | rate_ratio=30.00x | 3.00 req/s`

30x the baseline! These weren't subtle attacks — they were full-on scans. And my detector caught them automatically, added iptables rules, and sent me Slack alerts before I even knew what was happening.

The audit log looks like this:
```
[2026-04-29T17:36:22Z] BAN 204.76.203.206 | rate_ratio=30.00x | 3.00 req/s | mean=0.10, stddev=0.10 | duration=600s
[2026-04-29T17:46:22Z] UNBAN 204.76.203.206 | after 10.0 minutes
```

Beautifully structured. I can grep it, parse it, chart it. Perfect for post-incident analysis (or for showing off to friends).

---

## What I Messed Up (And Fixed)

Look, this wasn't smooth sailing. I hit so many bugs:

**Bug #1: Empty baseline crash**
When the detector starts, there are no logs yet. My baseline returned `None`, and the detector crashed trying to do math on `None`. Fixed by returning `{"mean": 0.0, "stddev": 0.1}` for empty windows.

**Bug #2: iptables path in systemd**
Worked fine when I ran it manually. Broke under systemd because `$PATH` was different. Had to hardcode `/usr/sbin/iptables`.

**Bug #3: Timestamp parsing**
Nginx logs ISO 8601 timestamps. Python's `datetime.strptime` with the wrong format string gave me garbage. Eventually settled on `datetime.fromisoformat()` after cleaning up the timezone suffix.

**Bug #4: Config nesting**
My detector code was reading `config.get("detection.rate_multiplier_threshold")` on a nested YAML dict, so it always fell back to the hardcoded default `5.0` instead of reading the actual config value. Fixed by properly extracting the nested `detection` dict first.

Each bug taught me something. That's the real value of building from scratch instead of just installing a pre-made tool.

---

## Lessons Learned

1. **Deques are underrated.** I knew they were fast, but seeing O(1) eviction under real load was satisfying.

2. **Z-scores need backup.** Relying purely on statistical deviation fails when variance is high. Always pair with an absolute check.

3. **Baselines must be adaptive.** Hardcoded thresholds are technical debt. Let the system learn.

4. **iptables is simpler than you think.** I was intimidated by firewall rules. Turns out it's just `iptables -A INPUT -s IP -j DROP`. Done.

5. **Run the detector on the host.** Don't fight Docker networking for iptables access. Just don't.

---

## Try It Yourself

Everything is open source: [github.com/Adeolu1024/hng14-stage3-devops](https://github.com/Adeolu1024/hng14-stage3-devops)

- **Live Dashboard**: [http://abimbola-project1.xyz](http://abimbola-project1.xyz)
- **Nextcloud**: [http://98.89.178.68](http://98.89.178.68)
- **Server**: AWS EC2 `t3.small` with Ubuntu 24.04

The repo has a `setup.sh` script that installs everything. Should take about 10 minutes on a fresh VPS.

---

*Built for HNG's anomaly detection challenge. No Fail2Ban, no rate-limiting libraries, no copy-paste from StackOverflow (okay maybe a little). Just Python, determination, and way too much coffee.*
