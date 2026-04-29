#!/usr/bin/env python3
"""Generate architecture.png for docs/"""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

fig, ax = plt.subplots(figsize=(16, 10))
ax.set_xlim(0, 16)
ax.set_ylim(0, 10)
ax.axis("off")
fig.patch.set_facecolor("#f0f2f5")

# Title
ax.text(8, 9.7, "HNG Anomaly Detection Engine - Architecture", fontsize=18, fontweight="bold", ha="center", color="#1a1a2e")

# Helper
def box(x, y, w, h, label, sublabel="", color="#4a90d9"):
    rect = mpatches.FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.15", facecolor=color, edgecolor="white", linewidth=2)
    ax.add_patch(rect)
    ax.text(x + w/2, y + h/2 + 0.1, label, fontsize=12, fontweight="bold", ha="center", va="center", color="white")
    if sublabel:
        ax.text(x + w/2, y + h/2 - 0.25, sublabel, fontsize=9, ha="center", va="center", color="white", alpha=0.9)

def arrow(x1, y1, x2, y2, label=""):
    ax.annotate("", xy=(x2, y2), xytext=(x1, y1), arrowprops=dict(arrowstyle="->", color="#333", lw=2))
    if label:
        mx, my = (x1+x2)/2, (y1+y2)/2
        ax.text(mx+0.3, my, label, fontsize=8, color="#555", style="italic")

# Clients
box(6, 8.5, 4, 0.7, "HTTP Clients", "(Users / Attackers)", "#4a90d9")
arrow(8, 8.5, 8, 7.8)

# Nginx
box(5, 6.8, 6, 1.0, "Nginx Reverse Proxy (Docker)", "JSON logs -> HNG-nginx-logs volume", "#00c853")
arrow(5, 7.3, 2.5, 7.3, "proxy_pass")
arrow(11, 7.3, 13, 7.3, "write logs")

# Nextcloud
box(1, 5.5, 3, 0.8, "Nextcloud", "(Docker)", "#ff9800")
arrow(2.5, 5.5, 2.5, 4.7)

# MariaDB
box(1, 3.9, 3, 0.8, "MariaDB", "(Docker)", "#9c27b0")

# Volume
box(12.5, 6.3, 3, 1.0, "HNG-nginx-logs", "Named Docker Volume", "#607d8b")
arrow(14, 6.3, 14, 5.3, "read-only")

# Detector box
det_rect = mpatches.FancyBboxPatch((11.5, 2.5), 4.5, 2.8, boxstyle="round,pad=0.15", facecolor="none", edgecolor="#e91e63", linewidth=2, linestyle="--")
ax.add_patch(det_rect)
ax.text(13.75, 5.15, "Detector Daemon (Host)", fontsize=11, fontweight="bold", ha="center", color="#e91e63")

# Detector sub-components
box(11.8, 4.3, 1.8, 0.5, "Log Monitor", color="#e91e63")
box(14.0, 4.3, 1.8, 0.5, "Sliding Window", color="#e91e63")
box(11.8, 3.6, 1.8, 0.5, "Rolling Baseline", color="#e91e63")
box(14.0, 3.6, 1.8, 0.5, "Anomaly Detector", color="#e91e63")
box(12.9, 2.8, 1.8, 0.5, "IP Blocker", color="#e91e63")

# Arrows from detector
arrow(11.8, 4.05, 10.5, 4.05)
arrow(11.8, 3.85, 10.5, 3.85)

# iptables
box(8.5, 3.5, 2, 0.8, "iptables DROP", "Host Firewall", "#f44336")

# Slack
box(8.5, 2.2, 2, 0.8, "Slack Webhook", "Alerts & Notifications", "#611f69")
arrow(11.8, 3.05, 10.5, 2.6)

# Dashboard
box(5.5, 1.5, 5, 0.8, "Live Dashboard (Flask :8080)", "Served at abimbola-project1.xyz", "#2196f3")
arrow(8, 3.5, 8, 2.3)

# Docker boundary
docker_rect = mpatches.FancyBboxPatch((0.5, 3.5), 10.5, 4.5, boxstyle="round,pad=0.2", facecolor="none", edgecolor="#333", linewidth=1.5, linestyle="--")
ax.add_patch(docker_rect)
ax.text(0.7, 7.8, "Docker Compose Stack", fontsize=10, color="#333", fontweight="bold")

# Legend
legend_items = [
    ("#00c853", "Nginx (Docker)"),
    ("#ff9800", "Nextcloud"),
    ("#e91e63", "Detector (Host)"),
    ("#f44336", "iptables"),
    ("#611f69", "Slack"),
    ("#2196f3", "Dashboard"),
]
for i, (color, label) in enumerate(legend_items):
    y = 0.8 - i * 0.25
    rect = mpatches.FancyBboxPatch((0.5, y), 0.3, 0.2, boxstyle="round,pad=0.03", facecolor=color)
    ax.add_patch(rect)
    ax.text(0.9, y + 0.1, label, fontsize=9, va="center", color="#333")

plt.tight_layout()
plt.savefig("docs/architecture.png", dpi=150, bbox_inches="tight", facecolor="#f0f2f5")
print("Generated docs/architecture.png")
