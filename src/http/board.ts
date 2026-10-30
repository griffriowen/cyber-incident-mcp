import crypto from "node:crypto";
import path from "node:path";
import express, { type NextFunction, type Request, type Response, type Router } from "express";
import { listCalls, listTickets, getTicketByRef, storeVersion, updateTicket } from "../store/ticketStore.js";
import type { TicketStatus } from "../types/incident.types.js";

/**
 * Incident handler board: a password-protected web page that shows tickets and
 * calls live. Mounted at /board by the Node server.
 *
 * Env:
 *   BOARD_PASSWORD  shared password for the board (board is disabled if unset)
 *   BOARD_SECRET    optional; signs the login cookie (falls back to MCP_API_KEY)
 */

const COOKIE = "board_session";
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

function validSession(token: string | undefined): boolean {
  if (!token) return false;
  const [exp, sig] = token.split(".");
  const expires = Number(exp);
  if (!Number.isFinite(expires) || expires < Date.now() || !sig) return false;
  const expected = sign(expires).split(".")[1];
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function readCookie(req: Request, name: string): string | undefined {
  const raw = req.headers.cookie ?? "";
  for (const part of raw.split(";")) {
    const [k, ...v] = part.trim().split("=");
    if (k === name) return decodeURIComponent(v.join("="));
  }
  return undefined;
}

function passwordMatches(given: string): boolean {
  const expected = process.env.BOARD_PASSWORD ?? "";
  if (!expected) return false;
  const a = crypto.createHash("sha256").update(given).digest();
  const b = crypto.createHash("sha256").update(expected).digest();
  return crypto.timingSafeEqual(a, b);
}

// Simple login throttle: 10 attempts per IP per 10 minutes.
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
  if (validSession(readCookie(req, COOKIE))) return next();
  res.status(401).json({ error: true, code: "signed_out", message: "Sign in to view the board." });
}

/** Trimmed ticket for the list view. */
function ticketSummary(t: ReturnType<typeof listTickets>[number]) {
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
    note_count: t.notes?.length ?? 0,
  };
}

export function boardRouter(): Router {
  const router = express.Router();
  router.use(express.urlencoded({ extended: false, limit: "10kb" }));

  // Static assets (CSS, JS). Data only ever comes from the signed-in API below.
  router.use("/assets", express.static(path.join(PUBLIC_DIR, "board"), { maxAge: "5m", index: false }));

  router.get("/", (req, res) => {
    if (!process.env.BOARD_PASSWORD) {
      res.status(503).type("text/plain").send("The board is turned off. Set BOARD_PASSWORD in .env and restart the server.");
      return;
    }
    const page = validSession(readCookie(req, COOKIE)) ? "board.html" : "login.html";
    res.set("Cache-Control", "no-store");
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
    const secure = req.secure || req.headers["x-forwarded-proto"] === "https";
    res.setHeader(
      "Set-Cookie",
      `${COOKIE}=${encodeURIComponent(sign(expires))}; Path=/board; HttpOnly; SameSite=Strict; Max-Age=${SESSION_HOURS * 3600}${secure ? "; Secure" : ""}`,
    );
    res.redirect(303, "/board");
  });

  router.post("/logout", (_req, res) => {
    res.setHeader("Set-Cookie", `${COOKIE}=; Path=/board; HttpOnly; SameSite=Strict; Max-Age=0`);
    res.redirect(303, "/board");
  });

  // Everything the board shows, in one small payload. The page polls this every few seconds.
  router.get("/api/state", requireSession, (_req, res) => {
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
    res.set("Cache-Control", "no-store");
    res.json({ version: storeVersion(), server_time: new Date().toISOString(), tickets, calls });
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
    res.set("Cache-Control", "no-store");
    res.json({ ticket: { ...t, notes: t.notes ?? [] }, calls });
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
    const t = updateTicket(String(req.params.ref), { status, note, author: "Incident handler" });
    if (!t) {
      res.status(404).json({ error: true, code: "not_found", message: "No ticket with that reference." });
      return;
    }
    res.json({ ticket: t });
  });

  return router;
}
