import "dotenv/config";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

const BASE = process.env.TEST_BASE_URL ?? `http://localhost:${process.env.PORT ?? 3000}`;
const headers = { Authorization: `Bearer ${process.env.MCP_API_KEY}` };

const client = new Client({ name: "test-client", version: "0.1.0" });
await client.connect(
  new StreamableHTTPClientTransport(new URL(`${BASE}/mcp`), { requestInit: { headers } }),
);

const { tools } = await client.listTools();
console.log("Tools:", tools.map((t) => t.name).join(", "));

async function call(name: string, args: Record<string, unknown>) {
  const r = await client.callTool({ name, arguments: args });
  const text = (r.content as Array<{ text: string }>)[0].text;
  console.log(`\n> ${name}${r.isError ? " (error)" : ""}\n${text}`);
  return JSON.parse(text);
}

await call("identify_caller", { caller_phone: "07700 900103" });
await call("check_known_incidents", { affected_system: "email", description: "clicked a link and typed my password into a microsoft login page" });
await call("check_known_incidents", { category: "ransomware", affected_system: "laptop", description: "files renamed and a ransom note" });
const created = await call("create_ticket", {
  caller_name: "Priya Shah",
  caller_phone: "+447700900103",
  call_id: `TEST-${Date.now()}`,
  category: "ransomware",
  affected_system: "finance laptop",
  description: "Files on the finance laptop have been renamed and a ransom note appeared on the desktop.",
  containment_actions_taken: ["Wi-Fi turned off"],
});
await call("get_ticket_status", { ticket_ref: created.ticket.ticket_ref.replace("-", " ") });
await call("get_ticket_status", { caller_phone: "+447590412370" });
await call("get_ticket_status", {});

const rest = await fetch(`${BASE}/api/ticket/by-call`, {
  method: "POST",
  headers: { ...headers, "Content-Type": "application/json" },
  body: JSON.stringify({ call_id: created.ticket.call_id }),
});
const restBody = await rest.text();
console.log(`\n> POST /api/ticket/by-call (${rest.status}, ${restBody.length} bytes)\n${restBody}`);

const unauth = await fetch(`${BASE}/mcp`, { method: "POST", body: "{}" });
console.log(`\n> Unauthenticated /mcp: ${unauth.status}`);

await client.close();
