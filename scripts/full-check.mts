/**
 * Full end-to-end check of the MCP server, the FLOW endpoint and the desk API.
 *
 *   npx tsx scripts/full-check.mts <base-url> <MCP_API_KEY> [--write]
 *
 * Without --write it only reads (safe on a live demo server).
 * With --write it also raises test tickets, logs calls and triggers an outbreak,
 * so run ./deploy/reset-demo-data.sh afterwards on a real server.
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

const [BASE = "http://127.0.0.1:3000", KEY = process.env.MCP_API_KEY ?? ""] = process.argv.slice(2).filter((a) => !a.startsWith("--"));
const WRITE = process.argv.includes("--write");
const results: Array<{ area: string; check: string; ok: boolean; detail: string }> = [];
const check = (area: string, name: string, ok: boolean, detail = "") => results.push({ area, check: name, ok, detail });

async function http(path: string, init: RequestInit = {}) {
  const r = await fetch(BASE + path, init);
  const text = await r.text();
  let body: any = text;
  try { body = JSON.parse(text); } catch { const d = text.split("\n").find((l) => l.startsWith("data: ")); if (d) body = JSON.parse(d.slice(6)); }
  return { status: r.status, body };
}
const rpc = (path: string, method: string, params: object, headers: Record<string, string> = {}) =>
  http(path, { method: "POST", headers: { "Content-Type": "application/json", Accept: "application/json, text/event-stream", ...headers }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }) });

const client = new Client({ name: "full-check", version: "1" });
const tool = async (name: string, args: object) => {
  const r = await client.callTool({ name, arguments: args as Record<string, unknown> });
  return { error: Boolean(r.isError), data: JSON.parse((r.content as Array<{ text: string }>)[0].text) };
};

const run = Date.now().toString(36);

try {
  // ---------- Reachability and security ----------
  const h = await http("/health");
  check("Server", "Health check", h.status === 200 && h.body.status === "ok", JSON.stringify(h.body));
  check("Security", "Wrong key in URL is refused", (await rpc("/mcp/wrong-key", "tools/list", {})).status === 401);
  check("Security", "No key is refused", (await rpc("/mcp", "tools/list", {})).status === 401);
  check("Security", "Key in Authorization header accepted", (await rpc("/mcp", "tools/list", {}, { Authorization: `Bearer ${KEY}` })).status === 200);
  check("Security", "GET on MCP endpoint refused (POST only)", (await http(`/mcp/${KEY}`)).status === 405);
  check("Security", "FLOW endpoint needs the key", (await http("/api/ticket/by-call", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" })).status === 401);

  // ---------- MCP handshake ----------
  await client.connect(new StreamableHTTPClientTransport(new URL(`${BASE}/mcp/${KEY}`)));
  check("MCP", "Connect and initialise", true);
  const tools = (await client.listTools()).tools.map((t) => t.name).sort();
  const expected = ["check_known_incidents", "create_ticket", "get_ticket_status", "identify_caller", "log_call"];
  check("MCP", "All 5 tools listed", JSON.stringify(tools) === JSON.stringify(expected), tools.join(", "));

  // ---------- Read-only tool behaviour ----------
  const james = await tool("identify_caller", { caller_phone: "07590 412370" });
  check("identify_caller", "Finds James by phone (spaces allowed)", james.data.found && james.data.customer.name === "James Okafor");
  check("identify_caller", "Returns his open ticket", (james.data.open_ticket_refs ?? []).includes("SEC-240981"));
  check("identify_caller", "Has call history field", Array.isArray(james.data.recent_calls));
  const unknown = await tool("identify_caller", { caller_phone: "07700 900999" });
  check("identify_caller", "Unknown number returns found:false (not an error)", !unknown.error && unknown.data.found === false);
  check("identify_caller", "Missing input is a clean error", (await tool("identify_caller", {})).error);
  const byName = await tool("identify_caller", { caller_name: "James", organisation: "Harrow Valley" });
  check("identify_caller", "Verifies James by name and short organisation, no phone", byName.data.verification === "Verified" && byName.data.customer?.customer_id === "CUST-1002");
  check("identify_caller", "Name-only lookup returns his open ticket", (byName.data.open_ticket_refs ?? []).includes("SEC-240981"));
  const wrongOrg = await tool("identify_caller", { caller_name: "James Okafor", organisation: "Kestrel Logistics" });
  check("identify_caller", "Right name, wrong organisation is Unverified and reveals nothing", wrongOrg.data.verification === "Unverified" && !wrongOrg.data.customer);
  const spoof = await tool("identify_caller", { caller_phone: "07590412370", caller_name: "Priya Shah", organisation: "Kestrel Logistics" });
  check("identify_caller", "Known number, different person is Failed and reveals nothing", spoof.data.verification === "Failed" && !spoof.data.customer);
  check("get_ticket_status", "Finds tickets by name and organisation", (await tool("get_ticket_status", { caller_name: "James Okafor", organisation: "Harrow Valley Housing" })).data.found);

  const st = await tool("get_ticket_status", { ticket_ref: "SEC 240981" });
  check("get_ticket_status", "Finds ticket by reference (loose format)", st.data.found && st.data.ticket.ticket_ref === "SEC-240981");
  check("get_ticket_status", "Reference spelled out for speech", /S E C 2 4 0 9 8 1/.test(st.data.speak));
  check("get_ticket_status", "Finds tickets by phone", (await tool("get_ticket_status", { caller_phone: "07590412370" })).data.found);
  check("get_ticket_status", "Unknown reference handled", (await tool("get_ticket_status", { ticket_ref: "IW-3742" })).data.found === false);

  const ph = await tool("check_known_incidents", { category: "phishing", affected_system: "email", description: "typed my password into a fake microsoft sign in page" });
  check("check_known_incidents", "Matches the live phishing campaign", ph.data.match && ph.data.incident_ref === "MI-2026-0417");
  check("check_known_incidents", "No match for unrelated issue", (await tool("check_known_incidents", { category: "lost_device", affected_system: "work phone", description: "left it on a train" })).data.match === false);

  check("Self-test", "Built-in self-test passes", (await http(`/selftest/${KEY}`)).body.passed === true);

  if (WRITE) {
    // ---------- Ticket creation ----------
    const p1 = await tool("create_ticket", { call_id: `FC-${run}-1`, caller_name: "Priya Shah", caller_phone: "07700900103", category: "ransomware", affected_system: "Finance laptop", description: "Files encrypted, ransom note on screen." });
    check("create_ticket", "Ransomware is P1", p1.data.ticket.severity === "P1");
    check("create_ticket", "P1 goes to Major Incident Response", p1.data.ticket.assigned_team === "Major Incident Response");
    check("create_ticket", "P1 asks for a transfer", p1.data.transfer_to_agent === true);
    check("create_ticket", "Customer linked from phone", p1.data.ticket.customer_id === "CUST-1003" && p1.data.ticket.organisation === "Kestrel Logistics Ltd");
    check("create_ticket", "Reference is SEC format", /^SEC-\d+$/.test(p1.data.ticket.ticket_ref), p1.data.ticket.ticket_ref);
    const crit = await tool("create_ticket", { call_id: `FC-${run}-2`, caller_name: "Priya Shah", caller_phone: "07700900103", category: "phishing", affected_system: "Inbox", description: "Clicked a link." });
    check("create_ticket", "Critical-tier customer bumped up a level (phishing P3 to P2)", crit.data.ticket.severity === "P2");
    const dup = await tool("create_ticket", { call_id: `FC-${run}-1`, caller_name: "Priya Shah", category: "ransomware", affected_system: "Finance laptop", description: "again" });
    check("create_ticket", "Same call can't raise two tickets", dup.data.duplicate === true && dup.data.ticket.ticket_ref === p1.data.ticket.ticket_ref);
    const newCaller = await tool("create_ticket", { call_id: `FC-${run}-3`, caller_name: "Griff Owen", organisation: "Content Guru", caller_phone: "07700900999", category: "lost_device", affected_system: "Work phone", description: "Left on a train." });
    const noPhone = await tool("create_ticket", { call_id: `FC-${run}-np`, caller_name: "Sarah", organisation: "Northbridge Legal", category: "lost_device", affected_system: "work tablet", description: "Left the tablet on a train." });
    check("create_ticket", "Links the customer from name and organisation when there is no phone", noPhone.data.ticket.customer_id === "CUST-1001");
    check("create_ticket", "Works for callers with no customer record", newCaller.data.ticket.customer_id === null && newCaller.data.ticket.severity === "P3");

    // ---------- Call logging and the FLOW endpoint ----------
    const lg = await tool("log_call", { call_id: `FC-${run}-1`, caller_phone: "07700900103", caller_name: "Priya Shah", organisation: "Kestrel Logistics Ltd", verification_status: "Verified", call_reason: "new_incident", advice_given: "Keep it on but disconnected", transfer_priority: "Urgent", summary: "Full-check test call." });
    check("log_call", "Call logged and joined to its ticket", lg.data.logged && lg.data.ticket_ref === p1.data.ticket.ticket_ref);
    check("log_call", "Invented reference is rejected", (await tool("log_call", { call_id: `FC-${run}-x`, verification_status: "Verified", call_reason: "other", ticket_ref: "IW-3742", transfer_priority: "Standard", summary: "x" })).error);
    const flow = await http("/api/ticket/by-call", { method: "POST", headers: { "Content-Type": "application/json", Authorization: `Bearer ${KEY}` }, body: JSON.stringify({ call_id: `FC-${run}-1` }) });
    check("FLOW endpoint", "Returns the ticket and call log for @ID", flow.body.found && flow.body.call_logged && flow.body.severity === "P1" && flow.body.verification_status === "Verified");
    check("FLOW endpoint", "Ready-made agent briefing included", typeof flow.body.agent_assist_text === "string" && flow.body.agent_assist_text.includes(p1.data.ticket.ticket_ref));
    check("FLOW endpoint", "Response well under FLOW's 20KB limit", JSON.stringify(flow.body).length < 20_000, `${JSON.stringify(flow.body).length} bytes`);
    const none = await http("/api/ticket/by-call", { method: "POST", headers: { "Content-Type": "application/json", Authorization: `Bearer ${KEY}` }, body: JSON.stringify({ call_id: "never-happened" }) });
    check("FLOW endpoint", "Unknown call returns found:false with every field present", none.body.found === false && "severity" in none.body);
    const again = await tool("identify_caller", { caller_phone: "07700900103" });
    check("Memory", "Caller's earlier call is remembered", (again.data.recent_calls ?? []).some((c: any) => c.ticket_ref === p1.data.ticket.ticket_ref));

    // ---------- Outbreak detection ----------
    const sys = `Payroll${run}`; // unique system so earlier runs don't interfere
    const ob: any[] = [];
    for (let n = 1; n <= 3; n++) ob.push((await tool("create_ticket", { call_id: `FC-${run}-ob${n}`, caller_name: "Griff Owen", organisation: "Content Guru", caller_phone: "07700900999", category: "account_compromise", affected_system: `${sys} system`, description: "Logins from abroad." })).data);
    check("Outbreaks", "Reports 1 and 2 don't trigger anything", !ob[0].known_incident && !ob[1].known_incident);
    check("Outbreaks", "Report 3 opens a known incident", ob[2].known_incident?.newly_detected === true && ob[2].known_incident.reports === 3, ob[2].known_incident?.incident_ref);
    check("Outbreaks", "Aggie tells caller 3 it's been flagged", /3 similar reports/.test(ob[2].speak));
    const fourth = await tool("check_known_incidents", { category: "account_compromise", affected_system: sys, description: "odd logins" });
    check("Outbreaks", "Caller 4 is told it's already known", fourth.data.match && fourth.data.incident_ref === ob[2].known_incident?.incident_ref && /aware/i.test(fourth.data.speak));
    const t4 = await tool("create_ticket", { call_id: `FC-${run}-ob4`, caller_name: "Tom Ashby", category: "account_compromise", affected_system: sys, description: "odd logins" });
    check("Outbreaks", "Caller 4's ticket is linked automatically", t4.data.ticket.linked_incident_ref === ob[2].known_incident?.incident_ref);
    const elsewhere = await tool("check_known_incidents", { category: "account_compromise", affected_system: `Unrelated${run}`, description: "x" });
    check("Outbreaks", "Different system isn't swept in", elsewhere.data.incident_ref !== ob[2].known_incident?.incident_ref);
  }

  // ---------- Desk API ----------
  const desk = await http("/board/api/state");
  if (desk.status === 200) {
    check("Desk", "Desk API is serving", Array.isArray(desk.body.tickets) && Array.isArray(desk.body.incidents));
    if (WRITE) check("Desk", "New tickets show on the desk", desk.body.tickets.length >= 5);
    check("Desk", "Desk updates need the desk header", (await http("/board/api/tickets/SEC-240981", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ note: "x" }) })).status === 400);
  } else {
    check("Desk", "Desk API is serving", desk.status === 401, desk.status === 401 ? "password protected" : `HTTP ${desk.status}`);
  }
} catch (e) {
  check("Run", "Unexpected error", false, (e as Error).message);
} finally {
  await client.close().catch(() => undefined);
}

const failed = results.filter((r) => !r.ok);
let area = "";
for (const r of results) {
  if (r.area !== area) { area = r.area; console.log(`\n${area}`); }
  console.log(`  ${r.ok ? "PASS" : "FAIL"}  ${r.check}${r.detail && !r.ok ? `  (${r.detail})` : ""}`);
}
console.log(`\n${results.length - failed.length} of ${results.length} checks passed${WRITE ? "" : " (read-only run; add --write for the full suite)"}.`);
process.exit(failed.length ? 1 : 0);
