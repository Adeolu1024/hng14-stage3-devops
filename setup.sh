#!/bin/bash
set -e

echo "=== HNG Anomaly Detector - VPS Setup Script ==="

# 1. Install system dependencies
echo "[1/6] Installing dependencies..."
apt update && apt install -y python3 python3-pip python3-venv iptables docker.io docker-compose-plugin

# 2. Start Docker
echo "[2/6] Starting Docker..."
systemctl enable --now docker

# 3. Clone repo (if not already present)
REPO_DIR="/opt/hng-anomaly-detector"
if [ ! -d "$REPO_DIR" ]; then
    echo "[3/6] Cloning repository..."
    git clone https://github.com/YOUR_USERNAME/hng-anomaly-detector.git "$REPO_DIR"
else
    echo "[3/6] Repository already exists at $REPO_DIR"
fi

cd "$REPO_DIR"

# 4. Set up Python virtual environment for detector
echo "[4/6] Setting up Python environment..."
python3 -m venv /opt/hng-detector-venv
/opt/hng-detector-venv/bin/pip install -r detector/requirements.txt

# 5. Configure Slack webhook
echo "[5/6] Configuring Slack webhook..."
echo "Enter your Slack webhook URL (or press Enter to skip and edit config.yaml manually):"
read -r WEBHOOK_URL
if [ -n "$WEBHOOK_URL" ]; then
    sed -i "s|https://hooks.slack.com/services/YOUR/WEBHOOK/URL|$WEBHOOK_URL|" detector/config.yaml
fi

# 6. Start Docker Compose stack
echo "[6/6] Starting Nextcloud + Nginx stack..."
docker compose up -d

# Wait for nginx to create the log file
echo "Waiting for nginx to initialize..."
sleep 5

# Create symlink for detector to access Docker volume logs
LOG_DIR="/var/log/nginx"
LOG_SOURCE="/var/lib/docker/volumes/HNG-nginx-logs/_data/hng-access.log"
mkdir -p "$LOG_DIR"
if [ -f "$LOG_SOURCE" ]; then
    ln -sf "$LOG_SOURCE" "$LOG_DIR/hng-access.log"
    echo "Symlinked $LOG_SOURCE → $LOG_DIR/hng-access.log"
else
    echo "WARNING: Log file not found at $LOG_SOURCE yet. Detector will retry on startup."
fi

# 7. Install and start detector service
echo "Installing detector systemd service..."
cp detector/hng-detector.service /etc/systemd/system/
sed -i "s|/opt/hng-anomaly-detector|$REPO_DIR|g" /etc/systemd/system/hng-detector.service
sed -i "s|/usr/bin/python3|/opt/hng-detector-venv/bin/python3|g" /etc/systemd/system/hng-detector.service
systemctl daemon-reload
systemctl enable --now hng-detector

echo ""
echo "=== Setup Complete ==="
echo "Nextcloud: http://$(curl -s ifconfig.me)"
echo "Dashboard: http://monitor.yourdomain.com (update nginx.conf with your domain)"
echo "Detector logs: journalctl -u hng-detector -f"
echo "Audit log: /var/log/detector/audit.log"
echo ""
echo "IMPORTANT: Update monitor.yourdomain.com in nginx/nginx.conf with your actual domain"
echo "Then reload nginx: docker exec hng-nginx nginx -s reload"
