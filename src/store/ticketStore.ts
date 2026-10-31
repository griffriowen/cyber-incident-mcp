import type {
  CallLog,
  Customer,
  IncidentCategory,
  KnownIncident,
  Severity,
  Ticket,
  TicketStatus,
} from "../types/incident.types.js";

/**
 * In-memory store. The host (the Node server) loads the data and supplies a callback that persists every change.
 */
export interface StoreData {
  tickets: Ticket[];
  calls: CallLog[];
  customers: Customer[];
  knownIncidents: KnownIncident[];
}

let tickets: Ticket[] = [];
let calls: CallLog[] = [];
let customers: Customer[] = [];
let knownIncidents: KnownIncident[] = [];
let onChange: (data: StoreData) => void = () => undefined;

export function initStore(data: StoreData, persistFn?: (data: StoreData) => void): void {
  tickets = [...data.tickets];
  calls = [...data.calls];
  customers = [...data.customers];
  knownIncidents = [...data.knownIncidents];
  if (persistFn) onChange = persistFn;
}

/** Seed incidents first; any saved copy with the same reference (e.g. auto-detected or resolved) replaces it. */
export function mergeIncidents(seed: KnownIncident[], saved: KnownIncident[]): KnownIncident[] {
  const byRef = new Map(seed.map((i) => [i.incident_ref, i] as const));
  for (const i of saved) byRef.set(i.incident_ref, i);
  return Array.from(byRef.values());
}

/** Incidents worth saving: auto-detected ones and any whose status changed on the desk. */
export function incidentsToSave(all: KnownIncident[]): KnownIncident[] {
  return all.filter((i) => i.auto_detected || i.status === "resolved");
}

export function snapshot(): StoreData {
  return { tickets, calls, customers, knownIncidents };
}

let version = 0;

/** Increments on every change, so the board can tell when to redraw. */
export function storeVersion(): number {
  return version;
}

export function listTickets(): Ticket[] {
  return [...tickets];
}

export function listCalls(): CallLog[] {
  return [...calls];
}

export function listKnownIncidents(): KnownIncident[] {
  return [...knownIncidents];
}

/** Handler update from the board: change status and/or add a note. Returns null if the ticket doesn't exist. */
export function updateTicket(
  ref: string,
  change: { status?: TicketStatus; note?: string; author: string },
): Ticket | null {
  const t = getTicketByRef(ref);
  if (!t) return null;
  const now = new Date().toISOString();
  t.notes = t.notes ?? [];
  if (change.status && change.status !== t.status) {
    t.notes.push({ at: now, author: change.author, kind: "status", text: `Status changed from ${t.status.replace("_", " ")} to ${change.status.replace("_", " ")}` });
    t.status = change.status;
  }
  const note = change.note?.trim();
  if (note) t.notes.push({ at: now, author: change.author, kind: "note", text: note.slice(0, 2000) });
  t.updated_at = now;
  persist();
  return t;
}

function persist(): void {
  version += 1;
  try {
    onChange(snapshot());
  } catch (err) {
    // Persistence is best effort for a mock store; in-memory state still holds.
    console.error("Failed to persist store:", (err as Error).message);
  }
}

/** Saves (or replaces) the log for a call. One log per call_id. */
export function saveCallLog(log: Omit<CallLog, "logged_at">): CallLog {
  const entry: CallLog = { ...log, logged_at: new Date().toISOString() };
  calls = calls.filter((c) => c.call_id !== log.call_id);
  calls.push(entry);
  persist();
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

// ---------- Matching callers by what they say ----------
// Callers give their name and organisation out loud, so matching is forgiving:
// "James" matches James Okafor, "Harrow Valley" matches Harrow Valley Housing,
// and company suffixes such as Ltd or LLP are ignored.

const ORG_NOISE = new Set(["ltd", "limited", "llp", "plc", "inc", "group", "uk", "the", "and", "co", "company", "services"]);

function words(text: string | null | undefined): string[] {
  return (text ?? "")
    .toLowerCase()
    .replace(/&/g, " and ")
    .replace(/[^\p{L}\p{N}\s]/gu, " ")
    .split(/\s+/)
    .filter(Boolean);
}

/** True when every word the caller said is part of the record's name, and the first name matches. */
export function nameMatches(said: string | null | undefined, record: string): boolean {
  const s = words(said), r = words(record);
  if (!s.length || !r.length) return false;
  return s[0] === r[0] && s.every((w) => r.includes(w));
}

/** Same person, whichever side gave the shorter form ("James" and "James Okafor"). */
function sameName(a: string | null | undefined, b: string | null | undefined): boolean {
  return Boolean(a && b) && (nameMatches(a, b!) || nameMatches(b, a!));
}

/** True when the organisation the caller gave is the record's organisation, or a short form of it. */
export function organisationMatches(said: string | null | undefined, record: string | null | undefined): boolean {
  const s = words(said).filter((w) => !ORG_NOISE.has(w));
  const r = words(record).filter((w) => !ORG_NOISE.has(w));
  if (!s.length || !r.length) return false;
  return s.every((w) => r.includes(w)) || r.every((w) => s.includes(w));
}

/** The customer whose name and organisation both match what the caller said, if exactly one does. */
export function findCustomerByName(name: string | null | undefined, organisation: string | null | undefined): Customer | null {
  const hits = customers.filter((c) => nameMatches(name, c.name) && organisationMatches(organisation, c.organisation));
  return hits.length === 1 ? hits[0] : null;
}

/** Tickets raised for this customer, by customer ID, phone number or name and organisation. Newest first. */
export function getTicketsForCustomer(c: Customer): Ticket[] {
  const phone = normalisePhone(c.phone);
  return tickets
    .filter((t) => t.customer_id === c.customer_id || (phone && normalisePhone(t.caller_phone) === phone) || (sameName(t.caller_name, c.name) && organisationMatches(t.organisation, c.organisation)))
    .sort((a, b) => b.created_at.localeCompare(a.created_at));
}

/** Calls logged for this customer, by phone number or name and organisation. Newest first. */
export function getCallLogsForCustomer(c: Customer, limit = 3): CallLog[] {
  const phone = normalisePhone(c.phone);
  return calls
    .filter((l) => (phone && normalisePhone(l.caller_phone) === phone) || (sameName(l.caller_name, c.name) && organisationMatches(l.organisation, c.organisation)))
    .sort((a, b) => b.logged_at.localeCompare(a.logged_at))
    .slice(0, limit);
}

/** Tickets for a caller with no customer record, matched on the name and organisation they gave. */
export function getTicketsByName(name: string, organisation: string | null | undefined): Ticket[] {
  return tickets
    .filter((t) => sameName(name, t.caller_name) && (!organisation || organisationMatches(organisation, t.organisation)))
    .sort((a, b) => b.created_at.localeCompare(a.created_at));
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

// ---------- Outbreak detection ----------
// When CLUSTER_THRESHOLD tickets with the same category on a similar system arrive within
// CLUSTER_WINDOW_MIN minutes (from anyone, including the same caller ringing repeatedly),
// the server opens a known incident itself. Later callers are then told it's already known.

const CLUSTER_THRESHOLD = Number(globalThis.process?.env?.CLUSTER_THRESHOLD ?? 3);
const CLUSTER_WINDOW_MIN = Number(globalThis.process?.env?.CLUSTER_WINDOW_MIN ?? 60);

const STOPWORDS = new Set(["the", "a", "an", "my", "our", "their", "his", "her", "its", "work", "works", "company", "system", "systems", "account", "accounts", "on", "of", "and", "for", "to", "in", "at", "all", "main", "shared", "office", "staff"]);
const SYNONYMS: Record<string, string> = {
  outlook: "email", mail: "email", inbox: "email", emails: "email", m365: "email", "365": "email", exchange: "email",
  salesforce: "crm", dynamics: "crm", hubspot: "crm",
  pc: "device", laptop: "device", laptops: "device", computer: "device", desktop: "device", workstation: "device", macbook: "device",
  "file": "files", share: "files", sharepoint: "files", drive: "files", onedrive: "files",
  website: "web", site: "web", portal: "web",
  remote: "vpn", globalprotect: "vpn",
  phone: "mobile", iphone: "mobile", android: "mobile",
};

/** Normalised words that describe a system, e.g. "Finance laptop" -> ["finance", "device"]. */
export function systemTokens(system: string | null | undefined): string[] {
  return Array.from(new Set(
    (system ?? "").toLowerCase().split(/[^a-z0-9]+/).filter((w) => w && !STOPWORDS.has(w)).map((w) => SYNONYMS[w] ?? w),
  ));
}

function systemsOverlap(a: string, b: string): boolean {
  const tb = new Set(systemTokens(b));
  return systemTokens(a).some((w) => tb.has(w));
}

const CATEGORY_LABEL: Record<IncidentCategory, string> = {
  ransomware: "ransomware", phishing: "phishing", account_compromise: "account compromise", malware: "malware",
  data_breach: "data exposure", ddos: "service outage", lost_device: "lost device", other: "security",
};

function nextIncidentRef(): string {
  const year = new Date().getFullYear();
  const max = knownIncidents.reduce((acc, i) => {
    const m = /^MI-\d{4}-(\d+)$/.exec(i.incident_ref);
    return m ? Math.max(acc, Number(m[1])) : acc;
  }, 400);
  return `MI-${year}-${String(max + 1).padStart(4, "0")}`;
}

/** Unresolved auto-detected incident covering this ticket's issue, if any. */
function matchingAutoIncident(t: Ticket): KnownIncident | null {
  return knownIncidents.find((i) =>
    i.auto_detected && i.status !== "resolved" && i.category === t.category &&
    i.affected_systems.some((s) => systemsOverlap(s, t.affected_system)),
  ) ?? null;
}

/**
 * Called after every new ticket. Links it to a matching auto-detected incident, or opens a
 * new one if this ticket is the CLUSTER_THRESHOLD-th similar report inside the window.
 */
export function detectOutbreak(t: Ticket): { incident: KnownIncident; created: boolean; reports: number } | null {
  const existing = matchingAutoIncident(t);
  if (existing) {
    existing.source_tickets = Array.from(new Set([...(existing.source_tickets ?? []), t.ticket_ref]));
    if (!t.linked_incident_ref) t.linked_incident_ref = existing.incident_ref;
    persist();
    return { incident: existing, created: false, reports: existing.source_tickets.length };
  }
  if (t.linked_incident_ref) return null; // already explained by a known incident

  const since = Date.now() - CLUSTER_WINDOW_MIN * 60_000;
  const similar = tickets.filter((x) =>
    x.category === t.category &&
    !x.linked_incident_ref &&
    new Date(x.created_at).getTime() >= since &&
    systemsOverlap(x.affected_system, t.affected_system),
  );
  if (similar.length < CLUSTER_THRESHOLD) return null;

  const shared = systemTokens(t.affected_system).filter((w) => similar.every((x) => systemTokens(x.affected_system).includes(w)));
  const systems = Array.from(new Set(similar.map((x) => x.affected_system.toLowerCase())));
  const label = CATEGORY_LABEL[t.category];
  const orgs = Array.from(new Set(similar.map((x) => x.organisation).filter(Boolean)));
  // Name the system the way callers did: the shortest description that contains the shared word (e.g. "CRM").
  const originals = similar.map((x) => x.affected_system.trim()).sort((a, b) => a.length - b.length);
  const what = originals.find((o) => shared.length && systemTokens(o).includes(shared[0])) ?? originals[0];
  const incident: KnownIncident = {
    incident_ref: nextIncidentRef(),
    title: `Multiple ${label} reports affecting ${what}`,
    category: t.category,
    affected_systems: Array.from(new Set([...systems, ...shared])),
    keywords: Array.from(new Set(similar.flatMap((x) => systemTokens(x.affected_system)))),
    status: "investigating",
    caller_guidance:
      `We're aware of several similar reports of ${label} involving ${what}, and our security team is already investigating. ` +
      `${CALLER_ADVICE[t.category]}`,
    started_at: new Date().toISOString(),
    auto_detected: true,
    source_tickets: similar.map((x) => x.ticket_ref),
  };
  knownIncidents.push(incident);
  for (const x of similar) x.linked_incident_ref = incident.incident_ref;
  persist();
  console.log(`Outbreak detected: ${incident.incident_ref} from ${similar.length} reports (${orgs.join(", ") || "unknown organisations"})`);
  return { incident, created: true, reports: similar.length };
}

/** Desk action: change a known incident's status (e.g. resolve an auto-detected outbreak). */
export function updateKnownIncident(ref: string, status: KnownIncident["status"]): KnownIncident | null {
  const i = knownIncidents.find((x) => x.incident_ref === ref.toUpperCase());
  if (!i) return null;
  i.status = status;
  if (status === "resolved") i.resolved_at = new Date().toISOString();
  persist();
  return i;
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
      let systemHit = false;
      if (params.category && i.category === params.category) score += 2;
      for (const s of i.affected_systems) if (haystack.includes(s)) { score += 2; systemHit = true; }
      for (const k of i.keywords) if (haystack.includes(k)) { score += 1; systemHit = true; }
      // Auto-detected incidents must also match on the system, not just the category.
      if (i.auto_detected && !systemHit && !systemsOverlap(i.affected_systems.join(" "), params.affected_system ?? "")) score = 0;
      return { i, score };
    })
    .filter((x) => x.score >= 2)
    .sort((a, b) => b.score - a.score)
    .map((x) => x.i);
}
