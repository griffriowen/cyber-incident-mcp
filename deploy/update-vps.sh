#!/usr/bin/env bash
# Redeploy after `git pull`. Keeps .env and the ticket/call data.
#   cd ~/cyber-incident-mcp && git pull && sudo ./deploy/update-vps.sh
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "Run with sudo." >&2; exit 1; }

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
APP_DIR=/opt/cyber-incident-mcp

# Older installs: make sure the auto-detected incident store exists and is configured.
[[ -f /var/lib/cyber-incident-mcp/incidents.json ]] || echo "[]" > /var/lib/cyber-incident-mcp/incidents.json
grep -q '^INCIDENT_STORE_PATH=' "$APP_DIR/.env" 2>/dev/null || echo "INCIDENT_STORE_PATH=/var/lib/cyber-incident-mcp/incidents.json" >> "$APP_DIR/.env"
chown mcp:mcp /var/lib/cyber-incident-mcp/incidents.json 2>/dev/null || true

rsync -a --delete --exclude node_modules --exclude dist --exclude .env --exclude .git "$REPO_DIR"/ "$APP_DIR"/
cd "$APP_DIR"
npm ci
npm run build
chown -R mcp:mcp "$APP_DIR"
systemctl restart cyber-incident-mcp
sleep 2
curl -fsS http://127.0.0.1:3000/health && echo " updated"
