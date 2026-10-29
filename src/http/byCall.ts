import { getCallLog, getTicketByCallId, getTicketByRef, spokenRef } from "../store/ticketStore.js";

/**
 * Body for POST /api/ticket/by-call. Shared by the Node and Cloudflare hosts.
 * Every field is always present (empty string when unknown) so FLOW object
 * mappings stay stable, and the payload stays well under FLOW's 20KB limit.
 */
export function buildByCallResponse(callId: string): Record<string, unknown> {
  const log = getCallLog(callId);
  const t = getTicketByCallId(callId) ?? (log?.ticket_ref ? getTicketByRef(log.ticket_ref) : null);
  if (!t && !log) {
    return {
      found: false,
      call_logged: false,
      ticket_ref: "", severity: "", category: "", status: "", assigned_team: "",
      affected_system: "", caller_name: "", organisation: "", description: "",
      containment_actions_taken: "", linked_incident_ref: "",
      verification_status: "", call_reason: "", advice_given: "", transfer_priority: "",
      summary: "", notes: "",
      agent_assist_text: "The virtual agent did not log this call or raise a ticket. Please triage manually.",
      ticket_ref_spoken: "",
    };
  }
  const assist = t
    ? `${t.severity} ${t.category.replace("_", " ")} ticket ${t.ticket_ref} for ${t.caller_name}` +
      `${t.organisation ? ` (${t.organisation})` : ""}. Affected system: ${t.affected_system}.` +
      `${t.linked_incident_ref ? ` Linked to known incident ${t.linked_incident_ref}.` : ""}` +
      `${log ? ` Caller ${log.verification_status.toLowerCase()}.` : ""}${log?.notes ? ` Note: ${log.notes}` : ""}`
    : `No ticket raised. Caller ${log!.caller_name ?? "unknown"} ${log!.verification_status.toLowerCase()}. ${log!.summary}`;
  return {
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
  };
}
