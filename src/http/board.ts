import crypto from "node:crypto";
import path from "node:path";
import express, { type NextFunction, type Request, type Response, type Router } from "express";
import {
  getTicketByRef,
  listCalls,
  listKnownIncidents,
  listTickets,
  storeVersion,
  updateTicket,
} from "../store/ticketStore.js";
import type { Ticket, TicketStatus } from "../types/incident.types.js";

/**
 * Ironwatch incident desk: a password-protected web app showing tickets, calls
 * and known incidents live. Mounted at /board by the Node server.
 *
 * Env:
 *   BOARD_PASSWORD  shared password (the board is turned off if unset)
 *   BOARD_SECRET    optional; signs the login cookie (falls back to MCP_API_KEY)
 */

const COOKIE = "board_session";
const NAME_COOKIE = "board_name";
const SESSION_HOURS = 12;
const STATUSES: TicketStatus[] = ["new", "triaged", "in_progress", "escalated", "resolved", "closed"];
const PUBLIC_DIR = path.resolve(process.cwd(), "public");

function secret(): string {
  return process.env.BOARD_SECRET || process.env.MCP_API_KEY || "";
}

function sign(expires: number): string {
  const sig = crypto.createHmac("sha256", secret()).update(`board:${expires}`).digest("base64url");
  return `${expires}.${sig}`;
}

/** Returns the session expiry time if the token is valid, otherwise null. */
function sessionExpiry(token: string | undefined): number | null {
  if (!token) return null;
  const [exp, sig] = token.split(".");
  const expires = Number(exp);
  if (!Number.isFinite(expires) || expires < Date.now() || !sig) return null;
  const expected = sign(expires).split(".")[1];
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  return a.length === b.length && crypto.timingSafeEqual(a, b) ? expires : null;
}

function readCookie(req: Request, name: string): string | undefined {
  const raw = req.headers.cookie ?? "";
  for (const part of raw.split(";")) {
    const [k, ...v] = part.trim().split("=");
    if (k === name) {
      try {
        return decodeURIComponent(v.join("="));
      } catch {
        return undefined;
      }
    }
  }
  return undefined;
}

function handlerName(req: Request): string {
  const n = (readCookie(req, NAME_COOKIE) ?? "").replace(/[^\p{L}\p{N} .'-]/gu, "").trim().slice(0, 40);
  return n || "Incident handler";
}

function passwordMatches(given: string): boolean {
  const expected = process.env.BOARD_PASSWORD ?? "";
  if (!expected) return false;
  const a = crypto.createHash("sha256").update(given).digest();
  const b = crypto.createHash("sha256").update(expected).digest();
  return crypto.timingSafeEqual(a, b);
}

// Login throttle: 10 attempts per IP per 10 minutes.
const attempts = new Map<string, { count: number; resetAt: number }>();
function tooManyAttempts(ip: string): boolean {
  const now = Date.now();
  const entry = attempts.get(ip);
  if (!entry || entry.resetAt < now) {
    attempts.set(ip, { count: 1, resetAt: now + 10 * 60_000 });
    return false;
  }
  entry.count += 1;
  return entry.count > 10;
}

function requireSession(req: Request, res: Response, next: NextFunction): void {
  if (sessionExpiry(readCookie(req, COOKIE))) return next();
  res.status(401).json({ error: true, code: "signed_out", message: "Sign in to view the desk." });
}

/** The call that raised a ticket, if Aggie logged one. */
function raisingCall(t: Ticket) {
  return listCalls().find((c) => (t.call_id && c.call_id === t.call_id) || c.ticket_ref === t.ticket_ref) ?? null;
}

/** First handler action on a ticket: when the response clock stops. */
function firstResponseAt(t: Ticket): string | null {
  if (t.notes?.length) return t.notes[0].at;
  // Tickets moved on outside the desk (e.g. seed data) count as responded at their last update.
  return ["in_progress", "resolved", "closed"].includes(t.status) ? t.updated_at : null;
}

function ticketSummary(t: Ticket) {
  const call = raisingCall(t);
  return {
    ticket_ref: t.ticket_ref,
    severity: t.severity,
    category: t.category,
    status: t.status,
    assigned_team: t.assigned_team,
    affected_system: t.affected_system,
    caller_name: t.caller_name,
    organisation: t.organisation,
    linked_incident_ref: t.linked_incident_ref,
    created_at: t.created_at,
    updated_at: t.updated_at,
    first_response_at: firstResponseAt(t),
    verification_status: call?.verification_status ?? null,
    note_count: t.notes?.length ?? 0,
  };
}

/** Most recent events across tickets, notes and calls, newest first. */
function activity(limit = 20) {
  type Event = { at: string; kind: "raised" | "status" | "note" | "call"; ticket_ref: string | null; severity: string | null; text: string; by: string };
  const events: Event[] = [];
  for (const t of listTickets()) {
    events.push({ at: t.created_at, kind: "raised", ticket_ref: t.ticket_ref, severity: t.severity, by: "Aggie", text: `${t.caller_name}${t.organisation ? ` at ${t.organisation}` : ""} reported ${t.category.replace("_", " ")} on ${t.affected_system}` });
    for (const n of t.notes ?? []) {
      events.push({ at: n.at, kind: n.kind === "status" ? "status" : "note", ticket_ref: t.ticket_ref, severity: t.severity, by: n.author, text: n.text });
    }
  }
  for (const c of listCalls()) {
    if (c.call_reason === "new_incident" && c.ticket_ref) continue; // already shown as "raised"
    events.push({
      at: c.logged_at, kind: "call", ticket_ref: c.ticket_ref, severity: null, by: "Aggie",
      text: c.call_reason === "failed_verification"
        ? `Failed verification: caller gave the name ${c.caller_name ?? "unknown"}${c.organisation ? ` from ${c.organisation}` : ""}`
        : `${c.caller_name ?? "A caller"} called about ${c.ticket_ref ?? "an enquiry"}`,
    });
  }
  return events.sort((a, b) => b.at.localeCompare(a.at)).slice(0, limit);
}

export function boardRouter(): Router {
  const router = express.Router();
  router.use(express.urlencoded({ extended: false, limit: "10kb" }));

  router.use("/assets", express.static(path.join(PUBLIC_DIR, "board"), { maxAge: "5m", index: false }));

  router.get("/", (req, res) => {
    if (!process.env.BOARD_PASSWORD) {
      res.status(503).type("text/plain").send("The board is turned off. Set BOARD_PASSWORD in .env and restart the server.");
      return;
    }
    const page = sessionExpiry(readCookie(req, COOKIE)) ? "board.html" : "login.html";
    res.set("Cache-Control", "no-store");
    res.set("X-Frame-Options", "DENY");
    res.sendFile(path.join(PUBLIC_DIR, "board", page));
  });

  router.post("/login", (req, res) => {
    const ip = req.ip ?? "unknown";
    if (tooManyAttempts(ip)) {
      res.redirect(303, "/board?error=locked");
      return;
    }
    const given = typeof req.body?.password === "string" ? req.body.password : "";
    if (!passwordMatches(given)) {
      res.redirect(303, "/board?error=wrong");
      return;
    }
    attempts.delete(ip);
    const expires = Date.now() + SESSION_HOURS * 3_600_000;
    const secure = req.secure || req.headers["x-forwarded-proto"] === "https" ? "; Secure" : "";
    const name = typeof req.body?.name === "string" ? req.body.name.trim().slice(0, 40) : "";
    const maxAge = SESSION_HOURS * 3600;
    res.setHeader("Set-Cookie", [
      `${COOKIE}=${encodeURIComponent(sign(expires))}; Path=/board; HttpOnly; SameSite=Strict; Max-Age=${maxAge}${secure}`,
      `${NAME_COOKIE}=${encodeURIComponent(name)}; Path=/board; HttpOnly; SameSite=Strict; Max-Age=${maxAge}${secure}`,
    ]);
    res.redirect(303, "/board");
  });

  router.post("/logout", (_req, res) => {
    res.setHeader("Set-Cookie", [
      `${COOKIE}=; Path=/board; HttpOnly; SameSite=Strict; Max-Age=0`,
      `${NAME_COOKIE}=; Path=/board; HttpOnly; SameSite=Strict; Max-Age=0`,
    ]);
    res.redirect(303, "/board?signed_out=1");
  });

  router.get("/api/state", requireSession, (req, res) => {
    const tickets = listTickets()
      .map(ticketSummary)
      .sort((a, b) => b.created_at.localeCompare(a.created_at));
    const calls = listCalls()
      .sort((a, b) => b.logged_at.localeCompare(a.logged_at))
      .slice(0, 100)
      .map((c) => ({
        call_id: c.call_id,
        logged_at: c.logged_at,
        caller_name: c.caller_name,
        organisation: c.organisation,
        verification_status: c.verification_status,
        call_reason: c.call_reason,
        ticket_ref: c.ticket_ref,
        transfer_priority: c.transfer_priority,
        summary: c.summary,
        notes: c.notes,
      }));
    const incidents = listKnownIncidents().map((i) => ({
      incident_ref: i.incident_ref,
      title: i.title,
      category: i.category,
      status: i.status,
      affected_systems: i.affected_systems,
      caller_guidance: i.caller_guidance,
      started_at: i.started_at,
      linked_tickets: listTickets().filter((t) => t.linked_incident_ref === i.incident_ref).map((t) => t.ticket_ref),
    }));
    res.set("Cache-Control", "no-store");
    res.json({
      version: storeVersion(),
      server_time: new Date().toISOString(),
      signed_in_as: handlerName(req),
      session_expires: sessionExpiry(readCookie(req, COOKIE)),
      tickets,
      calls,
      incidents,
      activity: activity(),
    });
  });

  router.get("/api/tickets/:ref", requireSession, (req, res) => {
    const t = getTicketByRef(String(req.params.ref));
    if (!t) {
      res.status(404).json({ error: true, code: "not_found", message: "No ticket with that reference." });
      return;
    }
    const calls = listCalls()
      .filter((c) => c.ticket_ref === t.ticket_ref || (t.call_id && c.call_id === t.call_id))
      .sort((a, b) => a.logged_at.localeCompare(b.logged_at));
    const incident = t.linked_incident_ref ? listKnownIncidents().find((i) => i.incident_ref === t.linked_incident_ref) ?? null : null;
    res.set("Cache-Control", "no-store");
    res.json({ ticket: { ...t, notes: t.notes ?? [], first_response_at: firstResponseAt(t) }, calls, incident });
  });

  router.post("/api/tickets/:ref", requireSession, express.json({ limit: "10kb" }), (req, res) => {
    // Extra header so a plain cross-site form post can't trigger an update.
    if (req.get("x-board-request") !== "1") {
      res.status(400).json({ error: true, code: "bad_request", message: "Missing board header." });
      return;
    }
    const status = req.body?.status;
    const note = typeof req.body?.note === "string" ? req.body.note : undefined;
    if (status !== undefined && !STATUSES.includes(status)) {
      res.status(400).json({ error: true, code: "bad_status", message: `Status must be one of: ${STATUSES.join(", ")}.` });
      return;
    }
    if (!status && !note?.trim()) {
      res.status(400).json({ error: true, code: "nothing_to_save", message: "Choose a new status or write a note." });
      return;
    }
    const t = updateTicket(String(req.params.ref), { status, note, author: handlerName(req) });
    if (!t) {
      res.status(404).json({ error: true, code: "not_found", message: "No ticket with that reference." });
      return;
    }
    res.json({ ticket: t });
  });

  return router;
}
