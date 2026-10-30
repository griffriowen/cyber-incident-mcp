# Deploying on a VPS

Runs the Node version of the server (`src/server.ts`) behind Caddy, which provides HTTPS with a CA-signed certificate automatically. Same set-up as the First Bus MCP server.

Example subdomain used below: `ironwatch.thhdashboard.co.uk`. Swap in your own.

## 1. DNS

Add an **A record**: `ironwatch` pointing at the VPS IP address.

## 2. Install and build (Ubuntu or Debian)

```bash
# Node 22, if not already installed
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
sudo apt-get install -y nodejs

sudo mkdir -p /opt/cyber-incident-mcp && sudo chown $USER /opt/cyber-incident-mcp
git clone https://github.com/griffriowen/cyber-incident-mcp.git /opt/cyber-incident-mcp
cd /opt/cyber-incident-mcp
npm ci
npm run build

# Port 3005 assumed free; change it if not
cat > .env <<'EOF'
PORT=3005
MCP_API_KEY=<the key Griff gives you>
EOF
chmod 600 .env
```

The repo is private, so either add the VPS user as a collaborator, use a deploy key, or copy the folder over as a zip.

## 3. Run it as a service

`/etc/systemd/system/cyber-incident-mcp.service`:

```ini
[Unit]
Description=Ironwatch cyber incident MCP server
After=network.target

[Service]
WorkingDirectory=/opt/cyber-incident-mcp
ExecStart=/usr/bin/node dist/server.js
Restart=always
User=www-data

[Install]
WantedBy=multi-user.target
```

```bash
sudo chown -R www-data /opt/cyber-incident-mcp/data
sudo systemctl daemon-reload
sudo systemctl enable --now cyber-incident-mcp
curl -s localhost:3005/health   # {"status":"ok"}
```

## 4. HTTPS with Caddy

If Caddy already serves the First Bus site, just add this block to the existing `/etc/caddy/Caddyfile`:

```
ironwatch.thhdashboard.co.uk {
    reverse_proxy localhost:3005
}
```

```bash
sudo systemctl reload caddy
```

If the box uses nginx instead, proxy `ironwatch.thhdashboard.co.uk` to `http://localhost:3005` and add a certificate with certbot, as the First Bus site does.

## 5. Check it

- `https://ironwatch.thhdashboard.co.uk/health` returns `{"status":"ok"}`
- `https://ironwatch.thhdashboard.co.uk/selftest/<key>` returns `"passed": true`

bMA MCP URL: `https://ironwatch.thhdashboard.co.uk/mcp/<key>`

## Day to day

- Logs (every request and tool call, key masked): `sudo journalctl -u cyber-incident-mcp -f`
- Update after a code change: `cd /opt/cyber-incident-mcp && git pull && npm ci && npm run build && sudo systemctl restart cyber-incident-mcp`
- Reset demo tickets: `git checkout data/mock/tickets.json && echo '[]' > data/mock/calls.json && sudo systemctl restart cyber-incident-mcp`
