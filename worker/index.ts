/**
 * Cloudflare Workers host for the cyber incident MCP server.
 *
 * All state lives in a single Durable Object ("main"), so every request sees
 * the same tickets and call logs, and they survive restarts. Same endpoints as
 * the Node/Render version:
 *   POST /mcp/<key>            MCP (Streamable HTTP, stateless) for the bMA
 *   POST /mcp                  MCP with Authorization: Bearer <key>
 *   POST /api/ticket/by-call   FLOW REST API cell, body {"call_id": "..."}
 *   GET  /selftest/<key>       Read-only end-to-end MCP test
 *   POST /reset/<key>          Reset tickets and call logs to the seed data
 *   GET  /health               Liveness, no auth
 */
import { DurableObject } from "cloudflare:workers";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { registerTools } from "../src/mcp/tools.js";
import { initStore, type StoreData } from "../src/store/ticketStore.js";
import { buildByCallResponse } from "../src/http/byCall.js";
import seedTickets from "../data/mock/tickets.json";
import seedCustomers from "../data/mock/mock_customers.json";
import seedIncidents from "../data/mock/known_incidents.json";

interface Env {
  MCP_API_KEY: string;
  INCIDENT_STORE: DurableObjectNamespace<IncidentStore>;
}

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

function seed(): StoreData {
  return {
    tickets: seedTickets as StoreData["tickets"],
    calls: [],
    customers: seedCustomers as StoreData["customers"],
    knownIncidents: seedIncidents as StoreData["knownIncidents"],
  };
}

export class IncidentStore extends DurableObject<Env> {
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    ctx.blockConcurrencyWhile(async () => {
      const saved = await ctx.storage.get<Pick<StoreData, "tickets" | "calls">>("state");
      const base = seed();
      initStore(
        // Customers and known incidents always come from the repo, so edits deploy straight through.
        { ...base, tickets: saved?.tickets ?? base.tickets, calls: saved?.calls ?? [] },
        (d) => void ctx.storage.put("state", { tickets: d.tickets, calls: d.calls }),
      );
    });
  }

  private authorised(request: Request, pathKey: string | undefined): boolean {
    const key = this.env.MCP_API_KEY;
    if (!key) return false;
    return pathKey === key || request.headers.get("authorization") === `Bearer ${key}`;
  }

  async fetch(request: Request): Promise<Response> {
    const started = Date.now();
    const url = new URL(request.url);
    const parts = url.pathname.split("/").filter(Boolean);
    const pathKey = parts[1];
    let detail = "";
    let response: Response;

    try {
      if (parts[0] === "mcp") {
        if (!this.authorised(request, pathKey)) {
          response = json({ error: true, code: "unauthorised", message: "Invalid or missing bearer token." }, 401);
        } else if (request.method !== "POST") {
          response = json({ jsonrpc: "2.0", error: { code: -32000, message: "Method not allowed. This server is stateless; use POST." }, id: null }, 405);
        } else {
          const body = await request.clone().json().catch(() => null) as { method?: string; params?: { name?: string; arguments?: unknown } } | null;
          detail = body?.method === "tools/call"
            ? ` tools/call ${body.params?.name} ${JSON.stringify(body.params?.arguments ?? {}).slice(0, 300)}`
            : body?.method ? ` ${body.method}` : "";
          const server = new McpServer({ name: "cyber-incident-mcp", version: "0.2.0" });
          registerTools(server);
          const transport = new WebStandardStreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
          await server.connect(transport);
          response = await transport.handleRequest(request);
        }
      } else if (parts[0] === "api" && parts[1] === "ticket" && parts[2] === "by-call" && request.method === "POST") {
        if (!this.authorised(request, undefined)) {
          response = json({ error: true, code: "unauthorised" }, 401);
        } else {
          const body = await request.json().catch(() => null) as { call_id?: unknown } | null;
          const callId = typeof body?.call_id === "string" ? body.call_id : "";
          response = callId
            ? json(buildByCallResponse(callId))
            : json({ found: false, agent_assist_text: "No call ID supplied." }, 400);
        }
      } else if (parts[0] === "selftest" && request.method === "GET") {
        response = this.authorised(request, pathKey)
          ? json(await this.selftest(url.origin))
          : json({ error: true, code: "unauthorised" }, 401);
      } else if (parts[0] === "requests" && request.method === "GET") {
        // Last 50 requests this server received, newest first, so you can see whether the bMA called it.
        response = this.authorised(request, pathKey)
          ? json({ now: new Date().toISOString(), requests: (await this.ctx.storage.get<string[]>("requestLog")) ?? [] })
          : json({ error: true, code: "unauthorised" }, 401);
      } else if (parts[0] === "reset" && request.method === "POST") {
        if (!this.authorised(request, pathKey)) {
          response = json({ error: true, code: "unauthorised" }, 401);
        } else {
          await this.ctx.storage.delete("state");
          initStore(seed(), (d) => void this.ctx.storage.put("state", { tickets: d.tickets, calls: d.calls }));
          response = json({ reset: true });
        }
      } else {
        response = json({ error: true, code: "not_found" }, 404);
      }
    } catch (err) {
      console.error("Request failed:", err);
      response = json({ jsonrpc: "2.0", error: { code: -32603, message: "Internal server error" }, id: null }, 500);
    }

    const safePath = url.pathname.replace(/^\/(mcp|selftest|reset|requests)\/.+/, "/$1/<key>");
    const line = `${request.method} ${safePath} -> ${response.status} (${Date.now() - started}ms)${detail}`;
    console.log(line);
    if (parts[0] !== "requests") {
      const who = request.headers.get("user-agent")?.slice(0, 60) ?? "unknown client";
      const ip = request.headers.get("cf-connecting-ip") ?? "";
      const log = (await this.ctx.storage.get<string[]>("requestLog")) ?? [];
      log.unshift(`${new Date().toISOString()} ${line} | ${who} ${ip}`);
      await this.ctx.storage.put("requestLog", log.slice(0, 50));
    }
    return response;
  }

  /** Runs read-only MCP calls through this object's own HTTP handler, exactly as the bMA's requests are handled. */
  private async selftest(origin: string) {
    const steps: Array<Record<string, unknown>> = [];
    const started = Date.now();
    const client = new Client({ name: "selftest", version: "0.2.0" });
    try {
      await client.connect(
        new StreamableHTTPClientTransport(new URL(`${origin}/mcp/${this.env.MCP_API_KEY}`), {
          fetch: (input, init) => this.fetch(new Request(input, init)),
        }),
      );
      steps.push({ step: "connect + initialize", ok: true });
      const { tools } = await client.listTools();
      steps.push({ step: "tools/list", ok: true, tools: tools.map((t) => t.name) });
      const calls: Array<[string, Record<string, unknown>]> = [
        ["identify_caller", { caller_phone: "07590412370" }],
        ["get_ticket_status", { ticket_ref: "SEC-240981" }],
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
    return { host: "cloudflare", passed: steps.every((s) => s.ok), ms: Date.now() - started, steps };
  }
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === "/health") {
      // Reports whether the key secret is present, plus its length and a short hash, never the key itself.
      const key = env.MCP_API_KEY ?? "";
      const digest = key
        ? [...new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(key)))]
            .slice(0, 4).map((b) => b.toString(16).padStart(2, "0")).join("")
        : "";
      return json({ status: "ok", host: "cloudflare", key_configured: Boolean(key), key_length: key.length, key_sha256_prefix: digest });
    }
    const stub = env.INCIDENT_STORE.get(env.INCIDENT_STORE.idFromName("main"));
    return stub.fetch(request);
  },
} satisfies ExportedHandler<Env>;
