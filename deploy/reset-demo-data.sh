#!/usr/bin/env bash
# Put tickets, call logs and auto-detected incidents back to the starting demo data (run before a demo).
#   sudo ./deploy/reset-demo-data.sh
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "Run with sudo." >&2; exit 1; }
cp /opt/cyber-incident-mcp/data/mock/tickets.json /var/lib/cyber-incident-mcp/tickets.json
echo "[]" > /var/lib/cyber-incident-mcp/calls.json
echo "[]" > /var/lib/cyber-incident-mcp/incidents.json
chown mcp:mcp /var/lib/cyber-incident-mcp/*.json
systemctl restart cyber-incident-mcp
echo "Demo data reset."
