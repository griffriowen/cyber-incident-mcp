#!/usr/bin/env bash
# One-time setup of the cyber incident MCP server on a fresh Ubuntu 22.04/24.04 VPS.
#
# Before running:
#   1. Point your domain's DNS A record (e.g. mcp.yourdomain.co.uk) at this server's IP.
#   2. Clone the repo onto the server and run this from inside it:
#        sudo ./deploy/setup-vps.sh mcp.yourdomain.co.uk,yourdomain.co.uk <MCP_API_KEY> [BOARD_PASSWORD]
#      The first argument is one domain or a comma-separated list (all point at this server).
#      Add a board password only if you want the desk to require sign-in; without one it opens straight away.
#
# Result: Node app on 127.0.0.1:3000 (systemd), Caddy in front on 80/443 with an
# automatic Let's Encrypt certificate, firewall allowing only SSH, HTTP and HTTPS.
set -euo pipefail

DOMAINS="${1:-}"
API_KEY="${2:-}"
BOARD_PASSWORD="${3:-}"
if [[ -z "$DOMAINS" || -z "$API_KEY" ]]; then
  echo "Usage: sudo $0 <domain[,domain2]> <MCP_API_KEY> [BOARD_PASSWORD]" >&2
  exit 1
fi
if [[ $EUID -ne 0 ]]; then
  echo "Run with sudo." >&2
  exit 1
fi

DOMAIN="${DOMAINS%%,*}"                 # first domain, used in the messages below
CADDY_SITES="${DOMAINS//,/, }"          # "a.example, example" for the Caddyfile

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
APP_DIR=/opt/cyber-incident-mcp
DATA_DIR=/var/lib/cyber-incident-mcp
SERVICE_USER=mcp

echo "==> Installing packages"
apt-get update -y
apt-get install -y curl ca-certificates gnupg debian-keyring debian-archive-keyring apt-transport-https ufw rsync

node_ok() { command -v node >/dev/null && [[ "$(node -v | cut -d. -f1 | tr -d v)" -ge 20 ]]; }
if ! node_ok; then
  # NodeSource first; if it doesn't support this Ubuntu release yet, fall back to Ubuntu's own package.
  if curl -fsSL https://deb.nodesource.com/setup_22.x | bash -; then
    apt-get install -y nodejs
  fi
  if ! node_ok; then
    echo "NodeSource unavailable for this release, using Ubuntu's nodejs package"
    apt-get install -y nodejs npm
  fi
  node_ok || { echo "Node.js 20 or newer is required but could not be installed." >&2; exit 1; }
fi
echo "Node $(node -v)"

if ! command -v caddy >/dev/null; then
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' > /etc/apt/sources.list.d/caddy-stable.list
  apt-get update -y
  apt-get install -y caddy
fi

echo "==> Creating service user and folders"
id -u "$SERVICE_USER" >/dev/null 2>&1 || useradd --system --home "$APP_DIR" --shell /usr/sbin/nologin "$SERVICE_USER"
mkdir -p "$APP_DIR" "$DATA_DIR"
rsync -a --delete --exclude node_modules --exclude dist --exclude .env --exclude .git "$REPO_DIR"/ "$APP_DIR"/

# Seed the ticket and call stores once; later deploys never overwrite them.
[[ -f "$DATA_DIR/tickets.json" ]] || cp "$APP_DIR/data/mock/tickets.json" "$DATA_DIR/tickets.json"
[[ -f "$DATA_DIR/calls.json" ]] || echo "[]" > "$DATA_DIR/calls.json"
[[ -f "$DATA_DIR/incidents.json" ]] || echo "[]" > "$DATA_DIR/incidents.json"

cat > "$APP_DIR/.env" <<EOF
PORT=3000
HOST=127.0.0.1
MCP_API_KEY=$API_KEY
BOARD_PASSWORD=$BOARD_PASSWORD
TICKET_STORE_PATH=$DATA_DIR/tickets.json
CALL_STORE_PATH=$DATA_DIR/calls.json
INCIDENT_STORE_PATH=$DATA_DIR/incidents.json
CLUSTER_THRESHOLD=3
CLUSTER_WINDOW_MIN=60
EOF
chmod 600 "$APP_DIR/.env"

echo "==> Building"
cd "$APP_DIR"
npm ci
npm run build
chown -R "$SERVICE_USER":"$SERVICE_USER" "$APP_DIR" "$DATA_DIR"

echo "==> Installing systemd service"
cat > /etc/systemd/system/cyber-incident-mcp.service <<EOF
[Unit]
Description=Cyber incident MCP server
After=network-online.target
Wants=network-online.target

[Service]
User=$SERVICE_USER
WorkingDirectory=$APP_DIR
ExecStart=/usr/bin/node dist/server.js
Restart=always
RestartSec=3
NoNewPrivileges=true
ProtectSystem=full
ReadWritePaths=$DATA_DIR

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now cyber-incident-mcp
systemctl restart cyber-incident-mcp

echo "==> Configuring Caddy (HTTPS)"
cat > /etc/caddy/Caddyfile <<EOF
$CADDY_SITES {
	encode gzip
	reverse_proxy 127.0.0.1:3000
}
EOF
systemctl reload caddy || systemctl restart caddy

echo "==> Firewall"
ufw allow OpenSSH
ufw allow 80/tcp
ufw allow 443/tcp
ufw --force enable

echo "==> Waiting for the app"
for _ in $(seq 1 30); do
  curl -fsS http://127.0.0.1:3000/health >/dev/null 2>&1 && break
  sleep 1
done
curl -fsS http://127.0.0.1:3000/health && echo

cat <<EOF

Done. Give Caddy a minute to get the certificate, then check:
  https://$DOMAIN/health
  https://$DOMAIN/selftest/<MCP_API_KEY>

bMA MCP URL:  https://$DOMAIN/mcp/<MCP_API_KEY>
Ticket board: https://$DOMAIN/board  (and the root of every domain you listed)
Logs:         sudo journalctl -u cyber-incident-mcp -f
Update later: sudo ./deploy/update-vps.sh   (run inside the cloned repo after git pull)
EOF

if [[ -n "$BOARD_PASSWORD" ]]; then
  echo "The desk requires the board password you set."
else
  echo "The desk is open: anyone with the link can view and update tickets (demo data only)."
fi
