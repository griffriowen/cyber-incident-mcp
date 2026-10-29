import fs from "node:fs";
import path from "node:path";
import type {
  CallLog,
  Customer,
  IncidentCategory,
  KnownIncident,
  Severity,
  Ticket,
} from "../types/incident.types.js";

const DATA_DIR = path.resolve(process.cwd(), "data/mock");
const TICKET_STORE_PATH = path.resolve(
  process.cwd(),
  process.env.TICKET_STORE_PATH ?? "data/mock/tickets.json",
);

function readJson<T>(file: string, fallback: T): T {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8")) as T;
  } catch {
    return fallback;
  }
}

let tickets: Ticket[] = readJson<Ticket[]>(TICKET_STORE_PATH, []);
const knownIncidents: KnownIncident[] = readJson<KnownIncident[]>(
  path.join(DATA_DIR, "known_incidents.json"),
  [],
);
const customers: Customer[] = readJson<Customer[]>(
  path.join(DATA_DIR, "mock_customers.json"),
  [],
);

const CALL_STORE_PATH = path.resolve(
  process.cwd(),
  process.env.CALL_STORE_PATH ?? "data/mock/calls.json",
);
let calls: CallLog[] = readJson<CallLog[]>(CALL_STORE_PATH, []);

/** Saves (or replaces) the log for a call. One log per call_id. */
export function saveCallLog(log: Omit<CallLog, "logged_at">): CallLog {
  const entry: CallLog = { ...log, logged_at: new Date().toISOString() };
  calls = calls.filter((c) => c.call_id !== log.call_id);
  calls.push(entry);
  try {
    fs.writeFileSync(CALL_STORE_PATH, JSON.stringify(calls, null, 2));
  } catch (err) {
    console.error("Failed to persist call log:", (err as Error).message);
  }
  return entry;
}

export function getCallLog(callId: string): CallLog | null {
  return calls.find((c) => c.call_id === callId) ?? null;
}

/** Most recent logged calls from this number, newest first. */
export function getCallLogsByPhone(phone: string, limit = 3): CallLog[] {
  const target = normalisePhone(phone);
  return calls
    .filter((c) => normalisePhone(c.caller_phone) === target)
    .sort((a, b) => b.logged_at.localeCompare(a.logged_at))
    .slice(0, limit);
}

function persist(): void {
  try {
    fs.writeFileSync(TICKET_STORE_PATH, JSON.stringify(tickets, null, 2));
  } catch (err) {
    // Persistence is best effort for a mock store; in-memory state still holds.
    console.error("Failed to persist tickets:", (err as Error).message);
  }
}

/** Normalise UK numbers so 07700..., +447700... and 447700... all match. */
export function normalisePhone(phone: string | null | undefined): string | null {
  if (!phone) return null;
  let digits = phone.replace(/[^\d+]/g, "");
  if (digits.startsWith("+")) digits = digits.slice(1);
  if (digits.startsWith("0")) digits = "44" + digits.slice(1);
  return digits || null;
}

function nextTicketRef(): string {
  const max = tickets.reduce((acc, t) => {
    const n = parseInt(t.ticket_ref.replace(/\D/g, ""), 10);
    return Number.isFinite(n) && n > acc ? n : acc;
  }, 240980);
  return `SEC-${max + 1}`;
}

/** Spells the reference out so text to speech reads it clearly. */
export function spokenRef(ref: string): string {
  return ref.replace("-", "").split("").join(" ");
}

const BASE_SEVERITY: Record<IncidentCategory, Severity> = {
  ransomware: "P1",
  data_breach: "P1",
  ddos: "P2",
  account_compromise: "P2",
  malware: "P2",
  phishing: "P3",
  lost_device: "P3",
  other: "P4",
};

const TEAM_BY_SEVERITY: Record<Severity, string> = {
  P1: "Major Incident Response",
  P2: "Security Operations",
  P3: "Security Operations",
  P4: "IT Service Desk",
};

export const CALLER_ADVICE: Record<IncidentCategory, string> = {
  ransomware:
    "Disconnect the affected device from the network by unplugging the cable or turning off Wi-Fi, but do not switch it off. Do not pay or respond to any ransom demand.",
  data_breach:
    "Do not delete or alter any files or emails related to the breach, and avoid discussing it outside the response team.",
  ddos: "No action is needed on your device. Our network team is working with the provider to filter the traffic.",
  account_compromise:
    "Do not log in to the account again until we contact you. We are resetting your password and signing out all active sessions.",
  malware:
    "Stop using the device and disconnect it from the network, but leave it switched on so it can be examined.",
  phishing:
    "Do not click any further links or reply to the email. If you entered a password, we will reset it straight away.",
  lost_device:
    "We will remotely lock the device and revoke its access. Let us know if you find it so we can restore access.",
  other: "Keep any evidence such as screenshots or emails, and avoid making changes to the affected system.",
};

export function suggestSeverity(
  category: IncidentCategory,
  customerTier: Customer["tier"] | null,
): Severity {
  const base = BASE_SEVERITY[category];
  if (customerTier === "critical" && base !== "P1") {
    // Critical tier customers are bumped one level.
    return (`P${Math.max(1, parseInt(base[1], 10) - 1)}`) as Severity;
  }
  return base;
}

export function findCustomerByPhone(phone: string | null | undefined): Customer | null {
  const target = normalisePhone(phone);
  if (!target) return null;
  return customers.find((c) => normalisePhone(c.phone) === target) ?? null;
}

export function findCustomerById(id: string | null | undefined): Customer | null {
  if (!id) return null;
  return customers.find((c) => c.customer_id === id) ?? null;
}

export function createTicket(
  input: Omit<
    Ticket,
    "ticket_ref" | "status" | "assigned_team" | "created_at" | "updated_at" | "severity"
  > & { severity?: Severity | null },
  customerTier: Customer["tier"] | null,
): Ticket {
  const now = new Date().toISOString();
  const severity = input.severity ?? suggestSeverity(input.category, customerTier);
  const ticket: Ticket = {
    ...input,
    ticket_ref: nextTicketRef(),
    severity,
    status: severity === "P1" ? "escalated" : "triaged",
    assigned_team: TEAM_BY_SEVERITY[severity],
    created_at: now,
    updated_at: now,
  };
  tickets.push(ticket);
  persist();
  return ticket;
}

export function getTicketByRef(ref: string): Ticket | null {
  const norm = ref.toUpperCase().replace(/\s+/g, "");
  const withDash = /^SEC\d+$/.test(norm) ? norm.replace("SEC", "SEC-") : norm;
  const digitsOnly = /^\d+$/.test(norm) ? `SEC-${norm}` : withDash;
  return tickets.find((t) => t.ticket_ref === digitsOnly) ?? null;
}

export function getTicketsByPhone(phone: string): Ticket[] {
  const target = normalisePhone(phone);
  return tickets
    .filter((t) => normalisePhone(t.caller_phone) === target)
    .sort((a, b) => b.created_at.localeCompare(a.created_at));
}

export function getTicketByCallId(callId: string): Ticket | null {
  return tickets.find((t) => t.call_id === callId) ?? null;
}

export function matchKnownIncidents(params: {
  category?: IncidentCategory | null;
  affected_system?: string | null;
  description?: string | null;
}): KnownIncident[] {
  const haystack = `${params.affected_system ?? ""} ${params.description ?? ""}`.toLowerCase();
  return knownIncidents
    .filter((i) => i.status !== "resolved")
    .map((i) => {
      let score = 0;
      if (params.category && i.category === params.category) score += 2;
      for (const s of i.affected_systems) if (haystack.includes(s)) score += 2;
      for (const k of i.keywords) if (haystack.includes(k)) score += 1;
      return { i, score };
    })
    .filter((x) => x.score >= 2)
    .sort((a, b) => b.score - a.score)
    .map((x) => x.i);
}
