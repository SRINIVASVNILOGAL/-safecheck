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

export interface CheckedMessage {
  message_id: string;
  from: string;
  subject: string;
  received_at: string;
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
