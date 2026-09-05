/**
 * Shared TypeScript types for the SafeCheck API.
 *
 * These mirror backend/app/models/check.py exactly. If the backend
 * contract changes, update this file to match -- do not let the two
 * drift silently.
 */

export type SourceType = "TEXT" | "URL" | "EMAIL" | "DOCUMENT";

/** Only TEXT, URL, EMAIL are valid *request* values for POST /v1/check.
 * DOCUMENT is a response-only value (used by POST /v1/document). */
export type CheckRequestSourceType = "TEXT" | "URL" | "EMAIL";

export type RiskBand = "LOW" | "UNCERTAIN" | "MEDIUM" | "HIGH";

export interface CheckPayload {
  text?: string;
  url?: string;
  sender?: string;
  subject?: string;
  body?: string;
  attachments?: string[];
}

export interface CheckRequest {
  source_type: CheckRequestSourceType;
  payload: CheckPayload;
}

export interface RiskInfo {
  score: number;
  band: RiskBand;
}

export interface EvidenceItem {
  signal: string;
  category: "rules" | "url" | "ml";
  points: number;
  reason: string;
  source: string;
  confidence: string;
  availability: "available" | "unavailable";
  correlationGroup: string;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
}

export interface Explanation {
  summary: string;
  why: string[];
  next_action: string;
  uncertainty: string[];
}

export interface CheckResponse {
  case_id: string;
  source_type: SourceType;
  risk: RiskInfo;
  evidence: EvidenceItem[];
  explanation: Explanation;
  safe_actions: string[];
  created_at: string;
}

/** Gmail on-demand polling API contracts (backend/app/models/email.py). */
export interface EmailStatusResponse {
  connected: boolean;
  email_address: string | null;
  last_checked_at: string | null;
}

export interface ConnectStartResponse {
  authorization_url: string;
}

export interface SkippedAttachment {
  filename: string;
  reason: string;
}

/** Phishing contact-warning workflow. Confirmation-only: SafeCheck never
 * sends a warning without an explicit user click on the reviewed draft. */
export interface RecentSentContact {
  address: string;
  display_name: string;
  last_sent_at: string;
}

export interface WarningDraftRequest {
  gmail_message_id: string;
  risk_score: number;
  risk_band: "MEDIUM" | "HIGH";
  signals: string[];
  recipient_addresses: string[];
}

export interface WarningDraft {
  warning_id: string;
  recipients: string[];
  subject: string;
  body: string;
  status: string;
}

export interface WarningConfirmRequest {
  confirmed: boolean;
  idempotency_key: string;
  subject: string;
  body: string;
}

export interface WarningDelivery {
  recipient: string;
  status: string;
  gmail_message_id: string | null;
  error: string | null;
}

export interface WarningConfirmResponse {
  warning_id: string;
  status: string;
  deliveries: WarningDelivery[];
}

export interface AnalysisCoverage {
  urls_found: number;
  urls_analyzed: number;
  attachments_found: number;
  attachments_analyzed: number;
  skipped_attachments: SkippedAttachment[];
}

export interface CheckedMessage {
  message_id: string;
  from: string;
  subject: string;
  received_at: string;
  analysis_coverage: AnalysisCoverage;
  check: CheckResponse;
}

export interface CheckNowResponse {
  checked_count: number;
  results: CheckedMessage[];
}

/** Shape of a FastAPI HTTPException error body, e.g. {"detail": "..."} */
export interface ApiErrorBody {
  detail?: string | { msg: string }[];
}

/** Fraud-recovery / reporting-email workflow (backend/app/models/recovery.py).
 * Analyze -> identify org -> find official contact -> generate email ->
 * user reviews -> user clicks Send. Organization identification and
 * contact lookup are deterministic; only the email wording is
 * LLM-drafted, and nothing is ever sent without explicit confirmation. */
export interface OrgContact {
  key: string;
  display_name: string;
  email: string | null;
  phone: string | null;
  portal_url: string | null;
  note: string;
}

export interface RecoveryDraftRequest {
  case_id: string;
  risk_score: number;
  risk_band: "MEDIUM" | "HIGH" | "UNCERTAIN";
  signals: string[];
  context_text: string;
  org_key?: string;
}

export interface RecoveryDraft {
  report_id: string;
  organization: OrgContact;
  alternate_organizations: OrgContact[];
  subject: string;
  body: string;
  status: string;
  can_send: boolean;
}

export interface RecoveryConfirmRequest {
  confirmed: boolean;
  idempotency_key: string;
  subject: string;
  body: string;
}

export interface RecoveryConfirmResponse {
  report_id: string;
  status: string;
  gmail_message_id: string | null;
  error: string | null;
}
