import "dotenv/config";
import express, { type NextFunction, type Request, type Response } from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { registerTools } from "./mcp/tools.js";
import { getTicketByCallId, spokenRef } from "./store/ticketStore.js";

const PORT = Number(process.env.PORT ?? 3000);
const API_KEY = process.env.MCP_API_KEY;

if (!API_KEY || API_KEY === "change-me") {
  console.error("MCP_API_KEY is not set. Copy .env.example to .env and set a real token.");
  process.exit(1);
}

function auth(req: Request, res: Response, next: NextFunction): void {
  const header = req.header("authorization") ?? "";
  // Fallback for callers that can only be given a URL: /mcp/<token>
  const pathKey = typeof req.params?.key === "string" ? req.params.key : "";
  if (header !== `Bearer ${API_KEY}` && pathKey !== API_KEY) {
    res.status(401).json({ error: true, code: "unauthorised", message: "Invalid or missing bearer token." });
    return;
  }
  next();
}

function buildServer(): McpServer {
  const server = new McpServer({ name: "cyber-incident-mcp", version: "0.1.0" });
  registerTools(server);
  return server;
}

const app = express();
app.use(express.json({ limit: "100kb" }));

// Log every request (token masked) so Render's Logs tab shows what the bMA and FLOW send.
app.use((req, res, next) => {
  const started = Date.now();
  const safePath = req.path.replace(/^\/mcp\/.+/, "/mcp/<key>");
  const rpc = req.body && typeof req.body === "object" ? req.body : null;
  const detail =
    rpc?.method === "tools/call"
      ? ` tools/call ${rpc.params?.name} ${JSON.stringify(rpc.params?.arguments ?? {}).slice(0, 300)}`
      : rpc?.method
        ? ` ${rpc.method}`
        : "";
  res.on("finish", () => {
    console.log(`${req.method} ${safePath} -> ${res.statusCode} (${Date.now() - started}ms)${detail}`);
  });
  next();
});

app.get("/health", (_req, res) => {
  res.json({ status: "ok" });
});

// MCP endpoint for the bMA. Stateless: a fresh server and transport per request.
app.post(["/mcp", "/mcp/:key"], auth, async (req, res) => {
  const server = buildServer();
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
  res.on("close", () => {
    void transport.close();
    void server.close();
  });
  try {
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  } catch (err) {
    console.error("MCP request failed:", err);
    if (!res.headersSent) {
      res.status(500).json({
        jsonrpc: "2.0",
        error: { code: -32603, message: "Internal server error" },
        id: null,
      });
    }
  }
});

const methodNotAllowed = (_req: Request, res: Response) => {
  res.status(405).json({
    jsonrpc: "2.0",
    error: { code: -32000, message: "Method not allowed. This server is stateless; use POST." },
    id: null,
  });
};
app.get(["/mcp", "/mcp/:key"], methodNotAllowed);
app.delete(["/mcp", "/mcp/:key"], methodNotAllowed);

// REST endpoint for FLOW: fetch the ticket raised during this call so
// Update CKS Record can populate the agent's screen pop. Flat fields only,
// well under the 20KB REST API action cell limit.
app.post("/api/ticket/by-call", auth, (req, res) => {
  const callId = typeof req.body?.call_id === "string" ? req.body.call_id : "";
  if (!callId) {
    res.status(400).json({ found: false, agent_assist_text: "No call ID supplied." });
    return;
  }
  const t = getTicketByCallId(callId);
  if (!t) {
    res.json({
      found: false,
      agent_assist_text: "No security ticket was raised by the virtual agent on this call. Please triage manually.",
    });
    return;
  }
  res.json({
    found: true,
    ticket_ref: t.ticket_ref,
    severity: t.severity,
    category: t.category,
    status: t.status,
    assigned_team: t.assigned_team,
    affected_system: t.affected_system,
    caller_name: t.caller_name,
    organisation: t.organisation ?? "",
    description: t.description.slice(0, 1000),
    containment_actions_taken: t.containment_actions_taken.join("; ").slice(0, 500),
    linked_incident_ref: t.linked_incident_ref ?? "",
    agent_assist_text:
      `${t.severity} ${t.category.replace("_", " ")} ticket ${t.ticket_ref} raised for ${t.caller_name}` +
      `${t.organisation ? ` (${t.organisation})` : ""}. Affected system: ${t.affected_system}.` +
      `${t.linked_incident_ref ? ` Linked to known incident ${t.linked_incident_ref}.` : ""}`,
    ticket_ref_spoken: spokenRef(t.ticket_ref),
  });
});

app.listen(PORT, () => {
  console.log(`cyber-incident-mcp listening on http://localhost:${PORT} (MCP at /mcp)`);
});
