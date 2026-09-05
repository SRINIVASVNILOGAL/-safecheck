import type {
  ApiErrorBody,
  CheckNowResponse,
  CheckRequest,
  CheckResponse,
  ConnectStartResponse,
  EmailStatusResponse,
  RecentSentContact,
  RecoveryConfirmRequest,
  RecoveryConfirmResponse,
  RecoveryDraft,
  RecoveryDraftRequest,
  WarningConfirmRequest,
  WarningConfirmResponse,
  WarningDraft,
  WarningDraftRequest,
} from "./types";

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://127.0.0.1:8000";

/** Thrown for any non-2xx response from the SafeCheck API. Carries the
 * human-readable message extracted from FastAPI's error body, so
 * callers can display it directly without re-parsing the response. */
export class ApiError extends Error {
  status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

/** Extracts a human-readable message from a FastAPI error body.
 *
 * FastAPI produces two different shapes depending on the failure:
 * - HTTPException(detail="...") -> {"detail": "some string"}
 * - Pydantic validation error   -> {"detail": [{"msg": "...", ...}, ...]}
 * Both are handled here so the UI never shows "[object Object]".
 */
function extractErrorMessage(body: unknown, fallback: string): string {
  const detail = (body as ApiErrorBody | undefined)?.detail;
  if (typeof detail === "string") {
    return detail;
  }
  if (Array.isArray(detail) && detail.length > 0) {
    return detail.map((item) => item.msg).join(" ");
  }
  return fallback;
}

async function parseJsonSafely(response: Response): Promise<unknown> {
  try {
    return await response.json();
  } catch {
    return undefined;
  }
}

/** POST /v1/check -- analyzes TEXT, URL, or EMAIL content. */
export async function checkContent(
  request: CheckRequest
): Promise<CheckResponse> {
  const response = await fetch(`${API_URL}/v1/check`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(request),
  });

  const body = await parseJsonSafely(response);

  if (!response.ok) {
    throw new ApiError(
      response.status,
      extractErrorMessage(body, `Request failed with status ${response.status}`)
    );
  }

  return body as CheckResponse;
}

/** POST /v1/document -- analyzes an uploaded PDF/PNG/JPEG file. */
export async function checkDocument(file: File): Promise<CheckResponse> {
  const formData = new FormData();
  formData.append("file", file);

  const response = await fetch(`${API_URL}/v1/document`, {
    method: "POST",
    body: formData,
  });

  const body = await parseJsonSafely(response);

  if (!response.ok) {
    throw new ApiError(
      response.status,
      extractErrorMessage(body, `Request failed with status ${response.status}`)
    );
  }

  return body as CheckResponse;
}

/** GET /v1/health -- used for a lightweight backend-reachability check. */
export async function checkHealth(): Promise<{ status: string }> {
  const response = await fetch(`${API_URL}/v1/health`);
  if (!response.ok) {
    throw new ApiError(response.status, "Backend health check failed.");
  }
  return response.json();
}

/** GET /v1/email/status -- reports the connected Gmail account, if any. */
export async function getEmailStatus(): Promise<EmailStatusResponse> {
  const response = await fetch(`${API_URL}/v1/email/status`);
  const body = await parseJsonSafely(response);

  if (!response.ok) {
    throw new ApiError(
      response.status,
      extractErrorMessage(body, `Request failed with status ${response.status}`)
    );
  }

  return body as EmailStatusResponse;
}

/** POST /v1/email/connect/start -- returns the Google OAuth consent URL. */
export async function startEmailConnect(): Promise<ConnectStartResponse> {
  const response = await fetch(`${API_URL}/v1/email/connect/start`, {
    method: "POST",
  });
  const body = await parseJsonSafely(response);

  if (!response.ok) {
    throw new ApiError(
      response.status,
      extractErrorMessage(body, `Request failed with status ${response.status}`)
    );
  }

  return body as ConnectStartResponse;
}

/** POST /v1/email/check-now -- fetches and analyzes the recent inbox batch. */
export async function checkEmailNow(): Promise<CheckNowResponse> {
  const response = await fetch(`${API_URL}/v1/email/check-now`, {
    method: "POST",
  });
  const body = await parseJsonSafely(response);

  if (!response.ok) {
    throw new ApiError(
      response.status,
      extractErrorMessage(body, `Request failed with status ${response.status}`)
    );
  }

  return body as CheckNowResponse;
}


/** GET /v1/email/recent-sent-contacts -- bounded recent Sent-mail recipients. */
export async function getRecentSentContacts(): Promise<RecentSentContact[]> {
  const response = await fetch(`${API_URL}/v1/email/recent-sent-contacts`);
  const body = await parseJsonSafely(response);
  if (!response.ok) {
    throw new ApiError(response.status, extractErrorMessage(body, `Request failed with status ${response.status}`));
  }
  return body as RecentSentContact[];
}

/** POST /v1/email/warnings/draft -- prepares an editable preview. Never sends. */
export async function createWarningDraft(request: WarningDraftRequest): Promise<WarningDraft> {
  const response = await fetch(`${API_URL}/v1/email/warnings/draft`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(request),
  });
  const body = await parseJsonSafely(response);
  if (!response.ok) {
    throw new ApiError(response.status, extractErrorMessage(body, `Request failed with status ${response.status}`));
  }
  return body as WarningDraft;
}

/** POST /v1/email/warnings/{id}/confirm -- the only call that can send. */
export async function confirmWarning(
  warningId: string,
  request: WarningConfirmRequest
): Promise<WarningConfirmResponse> {
  const response = await fetch(`${API_URL}/v1/email/warnings/${warningId}/confirm`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(request),
  });
  const body = await parseJsonSafely(response);
  if (!response.ok) {
    throw new ApiError(response.status, extractErrorMessage(body, `Request failed with status ${response.status}`));
  }
  return body as WarningConfirmResponse;
}

/** POST /v1/recovery/draft -- identifies the relevant organization and
 * generates an editable fraud-report email. Never sends anything. */
export async function createRecoveryDraft(request: RecoveryDraftRequest): Promise<RecoveryDraft> {
  const response = await fetch(`${API_URL}/v1/recovery/draft`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(request),
  });
  const body = await parseJsonSafely(response);
  if (!response.ok) {
    throw new ApiError(response.status, extractErrorMessage(body, `Request failed with status ${response.status}`));
  }
  return body as RecoveryDraft;
}

/** POST /v1/recovery/{id}/confirm -- the only call that can send a recovery report. */
export async function confirmRecoveryReport(
  reportId: string,
  request: RecoveryConfirmRequest
): Promise<RecoveryConfirmResponse> {
  const response = await fetch(`${API_URL}/v1/recovery/${reportId}/confirm`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(request),
  });
  const body = await parseJsonSafely(response);
  if (!response.ok) {
    throw new ApiError(response.status, extractErrorMessage(body, `Request failed with status ${response.status}`));
  }
  return body as RecoveryConfirmResponse;
}
