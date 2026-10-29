import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

const BASE = process.env.BASE ?? "http://localhost:3000";
const KEY = process.env.MCP_API_KEY!;
const c = new Client({ name: "t", version: "1" });
await c.connect(new StreamableHTTPClientTransport(new URL(`${BASE}/mcp/${KEY}`)));
console.log("tools:", (await c.listTools()).tools.map((t) => t.name).join(", "));

async function call(name: string, args: Record<string, unknown>) {
  const r = await c.callTool({ name, arguments: args });
  const j = JSON.parse((r.content as Array<{ text: string }>)[0].text);
  console.log(`\n> ${name}${r.isError ? " (error)" : ""}\n${JSON.stringify(j).slice(0, 600)}`);
  return j;
}
async function byCall(id: string) {
  const r = await fetch(`${BASE}/api/ticket/by-call`, {
    method: "POST",
    headers: { Authorization: `Bearer ${KEY}`, "Content-Type": "application/json" },
    body: JSON.stringify({ call_id: id }),
  });
  console.log(`\n> by-call ${id}\n${await r.text()}`);
}

// Griff: new caller, new incident
await call("identify_caller", { caller_phone: "07700900999" });
await call("create_ticket", { call_id: "CALL-GRIFF", caller_name: "Griff Owen", caller_phone: "07700900999", organisation: "Content Guru", category: "account_compromise", affected_system: "CRM account", description: "Logins to CRM account from abroad he did not make.", time_detected: "29/10/2026 11:15", containment_actions_taken: ["Logged out of all sessions"] });
await call("log_call", { call_id: "CALL-GRIFF", caller_phone: "07700900999", caller_name: "Griff Owen", organisation: "Content Guru", verification_status: "Unverified", call_reason: "new_incident", advice_given: "Do not log in again; password reset and sessions revoked", transfer_priority: "Standard", summary: "Griff Owen from Content Guru reported unauthorised CRM logins." });
await byCall("CALL-GRIFF");

// James: call-back, status only (no ticket raised on this call)
await call("get_ticket_status", { caller_phone: "07590412370" });
await call("log_call", { call_id: "CALL-JAMES-1", caller_phone: "07590412370", caller_name: "James Okafor", organisation: "Harrow Valley Housing", verification_status: "Verified", call_reason: "existing_ticket", ticket_ref: "SEC-240981", transfer_priority: "Standard", summary: "James Okafor asked for an update on SEC-240981. No change reported." });
await byCall("CALL-JAMES-1");

// James rings again: identify_caller should now remember the earlier call
await call("identify_caller", { caller_phone: "07590412370" });

// Guard: an invented reference is rejected
await call("log_call", { call_id: "CALL-FAKE", verification_status: "Verified", call_reason: "new_incident", ticket_ref: "IW-3742", transfer_priority: "Standard", summary: "test" });

// A call nobody logged
await byCall("CALL-NOTHING");
await c.close();
