import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import {
  CALLER_ADVICE,
  createTicket,
  findCustomerById,
  findCustomerByPhone,
  getTicketByCallId,
  getTicketByRef,
  getTicketsByPhone,
  getCallLogsByPhone,
  matchKnownIncidents,
  detectOutbreak,
  saveCallLog,
  spokenRef,
} from "../store/ticketStore.js";
import type { ToolError } from "../types/incident.types.js";

const CATEGORIES = [
  "ransomware",
  "phishing",
  "account_compromise",
  "malware",
  "data_breach",
  "ddos",
  "lost_device",
  "other",
] as const;

const SEVERITIES = ["P1", "P2", "P3", "P4"] as const;

function ok(payload: Record<string, unknown>): CallToolResult {
  return { content: [{ type: "text", text: JSON.stringify(payload) }] };
}

function fail(code: string, message: string): CallToolResult {
  const err: ToolError = { error: true, code, message };
  return { isError: true, content: [{ type: "text", text: JSON.stringify(err) }] };
}

/** Wraps a handler so it never throws; every failure becomes a structured error. */
function safe<A>(fn: (args: A) => CallToolResult) {
  return async (args: A): Promise<CallToolResult> => {
    try {
      return fn(args);
    } catch (e) {
      return fail("internal_error", (e as Error).message);
    }
  };
}

export function registerTools(server: McpServer): void {
  server.registerTool(
    "identify_caller",
    {
      title: "Identify caller",
      description:
        "Look up the caller's record by phone number or customer ID. Call this at the start of the conversation to greet the caller by name and confirm their organisation.",
      inputSchema: {
        caller_phone: z.string().optional().describe("Caller's phone number, e.g. +447700900101"),
        customer_id: z.string().optional().describe("Customer ID from CKS, if known"),
      },
    },
    safe(({ caller_phone, customer_id }: { caller_phone?: string; customer_id?: string }) => {
      if (!caller_phone && !customer_id) {
        return fail("missing_input", "Provide caller_phone or customer_id.");
      }
      const customer = findCustomerById(customer_id) ?? findCustomerByPhone(caller_phone);
      if (!customer) {
        return ok({
          found: false,
          speak: "I could not find your details on our system. Could you tell me your name and organisation, please?",
        });
      }
      const open = getTicketsByPhone(customer.phone).filter(
        (t) => t.status !== "resolved" && t.status !== "closed",
      );
      return ok({
        found: true,
        customer,
        open_ticket_refs: open.map((t) => t.ticket_ref),
        // Earlier calls logged with log_call. Only use these once the caller is verified.
        recent_calls: getCallLogsByPhone(customer.phone).map((c) => ({
          logged_at: c.logged_at,
          call_reason: c.call_reason,
          ticket_ref: c.ticket_ref,
          summary: c.summary,
        })),
        speak: open.length
          ? `Thanks ${customer.name.split(" ")[0]}, I can see you are calling from ${customer.organisation}. You already have ${open.length} open ticket${open.length > 1 ? "s" : ""} with us. Is this about ${open.length > 1 ? "one of those" : "that"}, or something new?`
          : `Thanks ${customer.name.split(" ")[0]}, I can see you are calling from ${customer.organisation}. What has happened?`,
      });
    }),
  );

  server.registerTool(
    "check_known_incidents",
    {
      title: "Check known incidents",
      description:
        "Check whether the caller's issue matches an incident the security team is already handling. Call this BEFORE create_ticket once you know roughly what has happened, so you can reassure the caller and link their ticket.",
      inputSchema: {
        category: z.enum(CATEGORIES).optional(),
        affected_system: z.string().optional().describe("e.g. email, VPN, laptop, finance system"),
        description: z.string().optional().describe("Short summary of what the caller reported"),
      },
    },
    safe((args: { category?: (typeof CATEGORIES)[number]; affected_system?: string; description?: string }) => {
      const matches = matchKnownIncidents(args);
      if (!matches.length) {
        return ok({ match: false, speak: "" });
      }
      const top = matches[0];
      return ok({
        match: true,
        incident_ref: top.incident_ref,
        title: top.title,
        status: top.status,
        other_matches: matches.slice(1).map((m) => m.incident_ref),
        speak: top.caller_guidance,
      });
    }),
  );

  server.registerTool(
    "create_ticket",
    {
      title: "Create security incident ticket",
      description:
        "Raise a security incident ticket once you have the caller's name, what happened, the affected system and the category. Returns the ticket reference, severity, assigned team and immediate advice to read to the caller.",
      inputSchema: {
        caller_name: z.string(),
        caller_phone: z.string().optional(),
        customer_id: z.string().optional(),
        call_id: z.string().optional().describe("storm @ID for this call, so FLOW can find the ticket later"),
        organisation: z.string().optional(),
        category: z.enum(CATEGORIES),
        affected_system: z.string(),
        description: z.string().describe("Two or three sentences describing what happened"),
        time_detected: z.string().optional().describe("When the caller noticed, in any format"),
        containment_actions_taken: z.array(z.string()).optional(),
        severity: z.enum(SEVERITIES).optional().describe("Leave blank to let the system decide"),
        linked_incident_ref: z.string().optional().describe("From check_known_incidents, if matched"),
      },
    },
    safe((args: {
      caller_name: string;
      caller_phone?: string;
      customer_id?: string;
      call_id?: string;
      organisation?: string;
      category: (typeof CATEGORIES)[number];
      affected_system: string;
      description: string;
      time_detected?: string;
      containment_actions_taken?: string[];
      severity?: (typeof SEVERITIES)[number];
      linked_incident_ref?: string;
    }) => {
      if (args.call_id) {
        const existing = getTicketByCallId(args.call_id);
        if (existing) {
          return ok({
            duplicate: true,
            ticket: existing,
            ticket_ref_spoken: spokenRef(existing.ticket_ref),
            speak: `I have already raised a ticket for this call. Your reference is ${spokenRef(existing.ticket_ref)}.`,
          });
        }
      }
      const customer = findCustomerById(args.customer_id) ?? findCustomerByPhone(args.caller_phone);
      const ticket = createTicket(
        {
          call_id: args.call_id ?? null,
          customer_id: customer?.customer_id ?? args.customer_id ?? null,
          caller_name: args.caller_name,
          caller_phone: args.caller_phone ?? customer?.phone ?? null,
          organisation: args.organisation ?? customer?.organisation ?? null,
          category: args.category,
          affected_system: args.affected_system,
          description: args.description,
          time_detected: args.time_detected ?? null,
          containment_actions_taken: args.containment_actions_taken ?? [],
          linked_incident_ref: args.linked_incident_ref ?? null,
          severity: args.severity ?? null,
        },
        customer?.tier ?? null,
      );
      const urgent = ticket.severity === "P1";
      // Repeated similar reports become a known incident automatically.
      const outbreak = detectOutbreak(ticket);
      const outbreakLine = !outbreak
        ? ""
        : outbreak.created
          ? `We've now had ${outbreak.reports} similar reports, so I've flagged this to the security team as a wider incident and they're looking at it together. `
          : `This matches an issue we're already investigating, so your report has been added to it. `;
      return ok({
        ticket,
        ticket_ref_spoken: spokenRef(ticket.ticket_ref),
        advice_for_caller: CALLER_ADVICE[ticket.category],
        transfer_to_agent: urgent,
        known_incident: outbreak
          ? { incident_ref: outbreak.incident.incident_ref, title: outbreak.incident.title, newly_detected: outbreak.created, reports: outbreak.reports }
          : null,
        speak:
          `I have raised ticket ${spokenRef(ticket.ticket_ref)} at priority ${ticket.severity[1]}, assigned to ${ticket.assigned_team}. ` +
          outbreakLine +
          `${CALLER_ADVICE[ticket.category]} ` +
          (urgent
            ? "Because this is critical, I am putting you through to a security analyst now."
            : "Is there anything else you can tell me that would help the team?"),
      });
    }),
  );

  server.registerTool(
    "log_call",
    {
      title: "Log the call",
      description:
        "Save the outcome of this call. Call this ONCE, just before every handover, on every call, including failed verification and status checks. FLOW reads it back by call_id to update the CKS record.",
      inputSchema: {
        call_id: z.string().describe("storm @ID for this call"),
        caller_phone: z.string().optional(),
        caller_name: z.string().optional(),
        organisation: z.string().optional(),
        verification_status: z.enum(["Verified", "Unverified", "Failed"]),
        call_reason: z.enum(["new_incident", "existing_ticket", "failed_verification", "other"]),
        ticket_ref: z.string().optional().describe("Only a reference returned by create_ticket or get_ticket_status"),
        advice_given: z.string().optional(),
        transfer_priority: z.enum(["Urgent", "Standard"]),
        summary: z.string().describe("Up to five sentences, facts only"),
        notes: z.string().optional().describe("Anything the handler must know: distress, press, suspicious behaviour, tool failures"),
      },
    },
    safe((args: {
      call_id: string;
      caller_phone?: string;
      caller_name?: string;
      organisation?: string;
      verification_status: "Verified" | "Unverified" | "Failed";
      call_reason: "new_incident" | "existing_ticket" | "failed_verification" | "other";
      ticket_ref?: string;
      advice_given?: string;
      transfer_priority: "Urgent" | "Standard";
      summary: string;
      notes?: string;
    }) => {
      let ticketRef = args.ticket_ref ?? getTicketByCallId(args.call_id)?.ticket_ref ?? null;
      if (ticketRef && !getTicketByRef(ticketRef)) {
        return fail("unknown_ticket_ref", `${ticketRef} does not exist. Only use a reference returned by create_ticket or get_ticket_status.`);
      }
      if (ticketRef) ticketRef = getTicketByRef(ticketRef)!.ticket_ref;
      const log = saveCallLog({
        call_id: args.call_id,
        caller_phone: args.caller_phone ?? null,
        caller_name: args.caller_name ?? null,
        organisation: args.organisation ?? null,
        verification_status: args.verification_status,
        call_reason: args.call_reason,
        ticket_ref: ticketRef,
        advice_given: args.advice_given ?? null,
        transfer_priority: args.transfer_priority,
        summary: args.summary.slice(0, 1500),
        notes: args.notes ?? null,
      });
      return ok({ logged: true, call_id: log.call_id, ticket_ref: log.ticket_ref, speak: "" });
    }),
  );

  server.registerTool(
    "get_ticket_status",
    {
      title: "Get ticket status",
      description:
        "Look up an existing ticket by reference, or the caller's most recent tickets by phone number. Use when the caller is ringing back about something already reported.",
      inputSchema: {
        ticket_ref: z.string().optional().describe("e.g. SEC-240981, or digits only"),
        caller_phone: z.string().optional(),
      },
    },
    safe(({ ticket_ref, caller_phone }: { ticket_ref?: string; caller_phone?: string }) => {
      if (ticket_ref) {
        const t = getTicketByRef(ticket_ref);
        if (!t) {
          return ok({
            found: false,
            speak: "I could not find that reference. Could you read it out again for me?",
          });
        }
        return ok({
          found: true,
          ticket: t,
          speak: `Ticket ${spokenRef(t.ticket_ref)} is currently ${t.status.replace("_", " ")} with ${t.assigned_team}, last updated ${new Date(t.updated_at).toLocaleString("en-GB", { dateStyle: "medium", timeStyle: "short", timeZone: "Europe/London" })}.`,
        });
      }
      if (caller_phone) {
        const list = getTicketsByPhone(caller_phone).slice(0, 3);
        if (!list.length) {
          return ok({ found: false, speak: "I cannot see any tickets for this number. Do you have a reference?" });
        }
        return ok({
          found: true,
          tickets: list.map((t) => ({
            ticket_ref: t.ticket_ref,
            category: t.category,
            severity: t.severity,
            status: t.status,
            updated_at: t.updated_at,
          })),
          speak: `I can see ${list.length} recent ticket${list.length > 1 ? "s" : ""} for this number. The latest is ${spokenRef(list[0].ticket_ref)}, which is ${list[0].status.replace("_", " ")}.`,
        });
      }
      return fail("missing_input", "Provide ticket_ref or caller_phone.");
    }),
  );
}
