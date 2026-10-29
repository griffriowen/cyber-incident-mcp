import "dotenv/config";
import express, { type NextFunction, type Request, type Response } from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { registerTools } from "./mcp/tools.js";
import { getCallLog, getTicketByCallId, getTicketByRef, spokenRef } from "./store/ticketStore.js";

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
  const safePath = req.path.replace(/^\/(mcp|selftest)\/.+/, "/$1/<key>");
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
  // Every field is always present (empty string when unknown) so FLOW object mappings stay stable.
  const log = getCallLog(callId);
  const t = getTicketByCallId(callId) ?? (log?.ticket_ref ? getTicketByRef(log.ticket_ref) : null);
  if (!t && !log) {
    res.json({
      found: false,
      call_logged: false,
      ticket_ref: "", severity: "", category: "", status: "", assigned_team: "",
      affected_system: "", caller_name: "", organisation: "", description: "",
      containment_actions_taken: "", linked_incident_ref: "",
      verification_status: "", call_reason: "", advice_given: "", transfer_priority: "",
      summary: "", notes: "",
      agent_assist_text: "The virtual agent did not log this call or raise a ticket. Please triage manually.",
    });
    return;
  }
  const assist = t
    ? `${t.severity} ${t.category.replace("_", " ")} ticket ${t.ticket_ref} for ${t.caller_name}` +
      `${t.organisation ? ` (${t.organisation})` : ""}. Affected system: ${t.affected_system}.` +
      `${t.linked_incident_ref ? ` Linked to known incident ${t.linked_incident_ref}.` : ""}` +
      `${log ? ` Caller ${log.verification_status.toLowerCase()}.` : ""}${log?.notes ? ` Note: ${log.notes}` : ""}`
    : `No ticket raised. Caller ${log!.caller_name ?? "unknown"} ${log!.verification_status.toLowerCase()}. ${log!.summary}`;
  res.json({
    found: true,
    call_logged: Boolean(log),
    ticket_ref: t?.ticket_ref ?? "",
    severity: t?.severity ?? "",
    category: t?.category ?? "",
    status: t?.status ?? "",
    assigned_team: t?.assigned_team ?? "",
    affected_system: t?.affected_system ?? "",
    caller_name: log?.caller_name ?? t?.caller_name ?? "",
    organisation: log?.organisation ?? t?.organisation ?? "",
    description: (t?.description ?? "").slice(0, 1000),
    containment_actions_taken: (t?.containment_actions_taken ?? []).join("; ").slice(0, 500),
    linked_incident_ref: t?.linked_incident_ref ?? "",
    verification_status: log?.verification_status ?? "",
    call_reason: log?.call_reason ?? "",
    advice_given: (log?.advice_given ?? "").slice(0, 500),
    transfer_priority: log?.transfer_priority ?? (t?.severity === "P1" ? "Urgent" : "Standard"),
    summary: (log?.summary ?? "").slice(0, 1500),
    notes: (log?.notes ?? "").slice(0, 500),
    agent_assist_text: assist.slice(0, 1000),
    ticket_ref_spoken: t ? spokenRef(t.ticket_ref) : "",
  });
});

// Self-test: connects to this server's own PUBLIC MCP URL as an MCP client
// (the same route the bMA uses) and runs read-only tool calls. Creates no tickets.
app.get("/selftest/:key", async (req, res) => {
  if (req.params.key !== API_KEY) {
    res.status(401).json({ error: true, code: "unauthorised" });
    return;
  }
  const base = process.env.RENDER_EXTERNAL_URL ?? `https://${req.get("host")}`;
  const steps: Array<Record<string, unknown>> = [];
  const client = new Client({ name: "selftest", version: "0.1.0" });
  const started = Date.now();
  try {
    await client.connect(new StreamableHTTPClientTransport(new URL(`${base}/mcp/${API_KEY}`)));
    steps.push({ step: "connect + initialize", ok: true });
    const { tools } = await client.listTools();
    steps.push({ step: "tools/list", ok: true, tools: tools.map((t) => t.name) });
    const calls: Array<[string, Record<string, unknown>]> = [
      ["identify_caller", { caller_phone: "07590412370" }],
      ["get_ticket_status", { ticket_ref: "SEC-240981" }],
      ["get_ticket_status", { caller_phone: "07590412370" }],
      ["check_known_incidents", { category: "phishing", affected_system: "email", description: "entered password on a fake microsoft sign in page" }],
    ];
    for (const [name, args] of calls) {
      const r = await client.callTool({ name, arguments: args });
      const text = (r.content as Array<{ text: string }>)[0]?.text ?? "";
      steps.push({ step: `tools/call ${name}`, ok: !r.isError, args, result: JSON.parse(text) });
    }
  } catch (err) {
    steps.push({ step: "error", ok: false, message: (err as Error).message });
  } finally {
    await client.close().catch(() => undefined);
  }
  res.json({ target: `${base}/mcp/<key>`, passed: steps.every((s) => s.ok), ms: Date.now() - started, steps });
});

app.listen(PORT, () => {
  console.log(`cyber-incident-mcp listening on http://localhost:${PORT} (MCP at /mcp)`);
});
