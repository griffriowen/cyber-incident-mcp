# Cyber Incident MCP Server (ComXo demo)

Mock security ticketing backend for the storm bMA cyber incident line. The bMA calls these tools mid-conversation over MCP; FLOW calls one REST endpoint after the bMA finishes to populate the CKS record.

## Run it

```bash
npm install
cp .env.example .env      # then set MCP_API_KEY to a real random token
npm run dev               # or: npm run build && npm start
npm test                  # in a second terminal, exercises every tool
```

## Endpoints

| Path | Caller | Purpose |
|---|---|---|
| `POST /mcp` | bMA | MCP endpoint (Streamable HTTP, stateless). Bearer token in the Authorization header. |
| `POST /mcp/<MCP_API_KEY>` | bMA | Same endpoint with the token in the URL, for when only a URL can be configured. |
| `POST /api/ticket/by-call` | FLOW REST API cell | Body `{ "call_id": "<@ID>" }`. Returns flat ticket fields plus `agent_assist_text`. |
| `GET /health` | Anyone | Liveness check, no auth. |

## MCP tools

| Tool | When the bMA should call it |
|---|---|
| `identify_caller` | Start of the call, to greet by name and spot open tickets |
| `check_known_incidents` | Once the issue is roughly understood, before raising a ticket |
| `create_ticket` | Once name, category, affected system and description are known. Pass `call_id` (@ID) so FLOW can find the ticket afterwards |
| `get_ticket_status` | Caller ringing back about an existing ticket |

Every tool returns a `speak` field: a ready-made sentence the bMA can say. Ticket references come back spelt out (`S E C 2 4 0 9 8 2`) so text to speech reads them clearly. Errors come back as `{ "error": true, "code", "message" }` rather than throwing.

`create_ticket` sets severity automatically (ransomware and data breach P1, account compromise and malware P2, phishing P3, and so on), bumps critical-tier customers up one level, and returns `transfer_to_agent: true` for P1.

## Mock data (`data/mock/`)

- `mock_customers.json`: three callers on Ofcom drama numbers (07700 900101 and 900103; James uses 07590 412370)
- `known_incidents.json`: an active Microsoft 365 phishing campaign and a VPN outage
- `tickets.json`: one existing ticket (SEC-240981) for the call-back scenario. New tickets are appended here; reset it before each demo.

## Demo scenarios

1. **Ransomware (P1, warm transfer):** call from 07700 900103 (Priya, critical tier). Files renamed, ransom note. Ticket raised at P1, containment advice given, transferred to analyst.
2. **Phishing (known incident):** call from 07700 900101. Clicked a link and entered a password on a Microsoft login page. bMA recognises the live campaign, links the ticket to MI-2026-0417.
3. **Call-back:** call from 07590 412370 (James). bMA spots open ticket SEC-240981 and gives a status update.

## Hosting (Render example)

1. Push this folder to a GitHub repo.
2. In Render, create a Web Service from the repo.
3. Build command `npm install && npm run build`, start command `npm start`.
4. Add environment variable `MCP_API_KEY` (a long random string).
5. Give the bMA `https://<your-service>.onrender.com/mcp/<MCP_API_KEY>`.

The filesystem resets on redeploy, which conveniently resets the mock tickets.

## Hosting on Cloudflare Workers

The same tools run as a Worker (`worker/index.ts`, config in `wrangler.toml`). State lives in one Durable Object, so tickets and call logs survive restarts and are never put to sleep.

1. Cloudflare dashboard: **Workers & Pages > Create > Import a repository**, pick this repo. Build settings: deploy command `npx wrangler deploy`, leave the rest as default.
2. Worker **Settings > Variables and Secrets**: add secret `MCP_API_KEY`.
3. Give the bMA `https://cyber-incident-mcp.<your-subdomain>.workers.dev/mcp/<MCP_API_KEY>`.
4. Check it: open `/selftest/<MCP_API_KEY>`; `"passed": true` means it works.

Extra endpoint on Cloudflare: `POST /reset/<MCP_API_KEY>` puts tickets and call logs back to the seed data before a demo.

## Checking everything works

```bash
npx tsx scripts/full-check.mts https://mcp.griffriowen.co.uk <MCP_API_KEY>          # read-only, safe on a live server
npx tsx scripts/full-check.mts https://mcp.griffriowen.co.uk <MCP_API_KEY> --write  # full suite; reset demo data afterwards
```

## Before going live

- Serve over HTTPS with a CA-signed certificate (required for FLOW's REST API action cell; assume the bMA needs the same).
- Confirm how the bMA is configured to connect to an MCP server (URL, transport and auth header support). Not yet verified.
