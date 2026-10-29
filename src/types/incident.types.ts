export type Severity = "P1" | "P2" | "P3" | "P4";

export type IncidentCategory =
  | "ransomware"
  | "phishing"
  | "account_compromise"
  | "malware"
  | "data_breach"
  | "ddos"
  | "lost_device"
  | "other";

export type TicketStatus =
  | "new"
  | "triaged"
  | "in_progress"
  | "escalated"
  | "resolved"
  | "closed";

export interface Ticket {
  ticket_ref: string;
  call_id: string | null;
  customer_id: string | null;
  caller_name: string;
  caller_phone: string | null;
  organisation: string | null;
  category: IncidentCategory;
  severity: Severity;
  affected_system: string;
  description: string;
  time_detected: string | null;
  containment_actions_taken: string[];
  status: TicketStatus;
  assigned_team: string;
  linked_incident_ref: string | null;
  created_at: string;
  updated_at: string;
}

export interface KnownIncident {
  incident_ref: string;
  title: string;
  category: IncidentCategory;
  affected_systems: string[];
  keywords: string[];
  status: "investigating" | "identified" | "monitoring" | "resolved";
  caller_guidance: string;
  started_at: string;
}

export interface Customer {
  customer_id: string;
  name: string;
  organisation: string;
  phone: string;
  role: string;
  tier: "standard" | "priority" | "critical";
}

export interface ToolError {
  error: true;
  code: string;
  message: string;
}
