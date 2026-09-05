"use client";

import { AlertTriangle, Copy, ExternalLink, Loader2, Mail, Send, ShieldAlert } from "lucide-react";
import { useState } from "react";

import { ApiError, confirmRecoveryReport, createRecoveryDraft } from "@/lib/api";
import type { CheckResponse, OrgContact, RecoveryConfirmResponse, RecoveryDraft } from "@/lib/types";

type Stage = "idle" | "drafting" | "preview" | "sending" | "sent" | "error";

/** Fraud-recovery / reporting-email panel.
 *
 * Flow: Analyze (already done by the caller) -> identify the relevant
 * organization -> find official reporting details -> generate email ->
 * user reviews -> user clicks Send. Organization identification and
 * contact-detail lookup are fully deterministic on the backend; only
 * the email wording is LLM-drafted. SafeCheck never sends this report
 * without an explicit "Confirm and send" click on the exact previewed
 * text, and offers a copy-to-clipboard fallback whenever Gmail sending
 * is unavailable (no account connected, or the organization has no
 * direct report-fraud email on file). */
export function RecoveryPanel({
  caseId,
  contextText,
  result,
}: {
  caseId: string;
  contextText: string;
  result: CheckResponse;
}) {
  const [stage, setStage] = useState<Stage>("idle");
  const [error, setError] = useState<string | null>(null);
  const [draft, setDraft] = useState<RecoveryDraft | null>(null);
  const [subject, setSubject] = useState("");
  const [body, setBody] = useState("");
  const [confirmResult, setConfirmResult] = useState<RecoveryConfirmResponse | null>(null);
  const [copied, setCopied] = useState(false);

  if (result.risk.band !== "HIGH" && result.risk.band !== "MEDIUM" && result.risk.band !== "UNCERTAIN") {
    return null;
  }

  async function requestDraft(orgKey?: string) {
    setStage("drafting");
    setError(null);
    try {
      const signals = result.evidence
        .filter((item) => item.availability === "available")
        .map((item) => item.signal)
        .slice(0, 12);
      const created = await createRecoveryDraft({
        case_id: caseId,
        risk_score: result.risk.score,
        risk_band: result.risk.band as "MEDIUM" | "HIGH" | "UNCERTAIN",
        signals: signals.length > 0 ? signals : ["SUSPICIOUS_CONTENT"],
        context_text: contextText.slice(0, 5000),
        org_key: orgKey,
      });
      setDraft(created);
      setSubject(created.subject);
      setBody(created.body);
      setCopied(false);
      setStage("preview");
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : "Could not generate a reporting email draft.");
      setStage("error");
    }
  }

  async function confirmAndSend() {
    if (!draft) return;
    setStage("sending");
    setError(null);
    try {
      const idempotencyKey = `${draft.report_id}-${crypto.randomUUID()}`;
      const response = await confirmRecoveryReport(draft.report_id, {
        confirmed: true,
        idempotency_key: idempotencyKey,
        subject,
        body,
      });
      setConfirmResult(response);
      setStage("sent");
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : "Could not send the report. Please try again.");
      setStage("error");
    }
  }

  async function copyToClipboard() {
    try {
      await navigator.clipboard.writeText(`Subject: ${subject}\n\n${body}`);
      setCopied(true);
    } catch {
      setCopied(false);
    }
  }

  function switchOrganization(target: OrgContact) {
    void requestDraft(target.key);
  }

  return (
    <div className="mt-3 rounded-xl border border-accent-blue/30 bg-accent-blue/5 p-4">
      {stage === "idle" && (
        <button
          type="button"
          onClick={() => requestDraft()}
          className="flex items-center gap-2 rounded-lg border border-accent-blue/40 px-3 py-2 text-sm font-medium text-accent-blue hover:bg-accent-blue/10"
        >
          <ShieldAlert className="h-4 w-4" /> Report this &amp; get help recovering
        </button>
      )}

      {stage === "drafting" && (
        <div className="flex items-center gap-2 text-sm text-foreground-muted">
          <Loader2 className="h-4 w-4 animate-spin" /> Identifying the right organization and drafting a report…
        </div>
      )}

      {stage === "preview" && draft && (
        <div>
          <p className="text-sm font-medium text-foreground">Reporting to: {draft.organization.display_name}</p>
          <div className="mt-1 flex flex-wrap gap-3 text-xs text-foreground-muted">
            {draft.organization.phone && <span>Helpline: {draft.organization.phone}</span>}
            {draft.organization.email && <span>Email: {draft.organization.email}</span>}
            {draft.organization.portal_url && (
              <a
                href={draft.organization.portal_url}
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center gap-1 text-accent-blue hover:underline"
              >
                Official portal <ExternalLink className="h-3 w-3" />
              </a>
            )}
          </div>
          {draft.organization.note && (
            <p className="mt-1 text-xs italic text-foreground-subtle">{draft.organization.note}</p>
          )}

          {draft.alternate_organizations.length > 0 && (
            <div className="mt-3">
              <p className="text-xs font-medium text-foreground-subtle">Report to a different organization instead:</p>
              <div className="mt-1 flex flex-wrap gap-2">
                {draft.alternate_organizations.map((org) => (
                  <button
                    key={org.key}
                    type="button"
                    onClick={() => switchOrganization(org)}
                    className="rounded-full border border-border px-3 py-1 text-xs text-foreground hover:bg-surface-elevated"
                  >
                    {org.display_name}
                  </button>
                ))}
              </div>
            </div>
          )}

          <label className="mt-4 block text-xs font-medium text-foreground-subtle">Subject</label>
          <input
            value={subject}
            onChange={(event) => setSubject(event.target.value)}
            maxLength={180}
            className="mt-1 w-full rounded-lg border border-border bg-surface px-3 py-2 text-sm text-foreground"
          />
          <label className="mt-3 block text-xs font-medium text-foreground-subtle">Message</label>
          <textarea
            value={body}
            onChange={(event) => setBody(event.target.value)}
            maxLength={4000}
            rows={8}
            className="mt-1 w-full rounded-lg border border-border bg-surface px-3 py-2 text-sm text-foreground"
          />
          <p className="mt-1 text-xs text-foreground-subtle">
            Review carefully, and fill in any bracketed placeholders (like transaction details) before sending.
          </p>

          <div className="mt-3 flex flex-wrap gap-2">
            {draft.can_send ? (
              <button
                type="button"
                onClick={confirmAndSend}
                className="flex items-center gap-2 rounded-lg bg-accent-blue px-4 py-2 text-sm font-medium text-white hover:bg-accent-blue-hover"
              >
                <Send className="h-4 w-4" /> Confirm and send
              </button>
            ) : (
              <>
                <button
                  type="button"
                  onClick={copyToClipboard}
                  className="flex items-center gap-2 rounded-lg border border-border px-4 py-2 text-sm font-medium text-foreground hover:bg-surface-elevated"
                >
                  <Copy className="h-4 w-4" /> {copied ? "Copied!" : "Copy email text"}
                </button>
                {draft.organization.email && (
                  <a
                    href={`mailto:${draft.organization.email}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`}
                    className="flex items-center gap-2 rounded-lg border border-border px-4 py-2 text-sm font-medium text-foreground hover:bg-surface-elevated"
                  >
                    <Mail className="h-4 w-4" /> Open in your email app
                  </a>
                )}
              </>
            )}
          </div>
          {!draft.can_send && (
            <p className="mt-2 text-xs text-foreground-subtle">
              {draft.organization.email
                ? "Connect Gmail on the Gmail Monitor page to send this directly, or copy it and send it yourself."
                : "This organization has no direct report-fraud email on file -- use its phone helpline or official portal above."}
            </p>
          )}
        </div>
      )}

      {stage === "sending" && (
        <div className="flex items-center gap-2 text-sm text-foreground-muted">
          <Loader2 className="h-4 w-4 animate-spin" /> Sending…
        </div>
      )}

      {stage === "sent" && confirmResult && (
        <div>
          <p className="text-sm font-medium text-foreground">
            Report status: {confirmResult.status}
            {confirmResult.error ? ` — ${confirmResult.error}` : ""}
          </p>
        </div>
      )}

      {stage === "error" && (
        <div className="flex items-center gap-2 text-sm text-accent-red">
          <AlertTriangle className="h-4 w-4" /> {error}
        </div>
      )}
    </div>
  );
}
