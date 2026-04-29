# Screenshots Directory

Place the following screenshots here after deploying and running the tool:

1. **tool-running.png** — Terminal showing the daemon running and processing log lines
   - Run: `sudo journalctl -u hng-detector -f`
   - Screenshot the output showing log entries being processed

2. **ban-slack.png** — Slack notification showing an IP ban alert
   - Trigger: Send rapid requests from a single IP (`ab -n 1000 -c 50 http://YOUR_IP/`)
   - Screenshot the Slack channel showing the ban notification

3. **unban-slack.png** — Slack notification showing an IP unban alert
   - Wait 10 minutes after a ban for auto-unban to trigger
   - Screenshot the Slack channel showing the unban notification

4. **global-alert-slack.png** — Slack notification showing a global anomaly alert
   - Trigger: Send high-volume traffic from multiple IPs simultaneously
   - Screenshot the Slack channel showing the global anomaly alert

5. **iptables-banned.png** — Output of `sudo iptables -L -n` showing a blocked IP
   - Run after an IP has been banned
   - Screenshot the terminal showing the DROP rule

6. **audit-log.png** — Structured audit log with ban, unban, and baseline recalculation events
   - Run: `sudo tail -f /var/log/detector/audit.log`
   - Screenshot showing at least one BAN, one UNBAN, and one BASELINE_RECALC entry

7. **baseline-graph.png** — Baseline over time showing at least two hourly slots with visibly different effective_mean values
   - Access the dashboard at `http://monitor.yourdomain.com`
   - Screenshot the "Baseline Stats" section showing multiple hourly slots
   - Alternatively, query the API: `curl http://localhost:8080/api/metrics | jq .baseline.hour_slots`
