"use client";

import { AlertTriangle, Loader2, Send, ShieldAlert } from "lucide-react";
import { useState } from "react";

import {
  ApiError,
  confirmWarning,
  createWarningDraft,
  getRecentSentContacts,
} from "@/lib/api";
import type {
  CheckResponse,
  RecentSentContact,
  WarningConfirmResponse,
  WarningDraft,
} from "@/lib/types";

type Stage = "idle" | "loading_contacts" | "select" | "drafting" | "preview" | "sending" | "sent" | "error";

/** Confirmation-only phishing-contact warning panel.
 *
 * SafeCheck never sends anything from this panel automatically: contacts
 * are fetched only when the user opens it, the LLM-drafted subject/body is
 * always shown for review/edit, and Gmail is only called after the user
 * clicks "Confirm and send" on the exact previewed text. */
export function WarningPanel({
  gmailMessageId,
  result,
}: {
  gmailMessageId: string;
  result: CheckResponse;
}) {
  const [stage, setStage] = useState<Stage>("idle");
  const [error, setError] = useState<string | null>(null);
  const [contacts, setContacts] = useState<RecentSentContact[]>([]);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [draft, setDraft] = useState<WarningDraft | null>(null);
  const [subject, setSubject] = useState("");
  const [body, setBody] = useState("");
  const [confirmResult, setConfirmResult] = useState<WarningConfirmResponse | null>(null);

  if (result.risk.band !== "HIGH" && result.risk.band !== "MEDIUM") {
    return null;
  }

  async function openPanel() {
    setStage("loading_contacts");
    setError(null);
    try {
      const fetched = await getRecentSentContacts();
      setContacts(fetched);
      setSelected(new Set());
      setStage("select");
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : "Could not load recent contacts.");
      setStage("error");
    }
  }

  function toggleContact(address: string) {
    setSelected((current) => {
      const next = new Set(current);
      if (next.has(address)) next.delete(address);
      else next.add(address);
      return next;
    });
  }

  async function requestDraft() {
    setStage("drafting");
    setError(null);
    try {
      const signals = result.evidence
        .filter((item) => item.availability === "available")
        .map((item) => item.signal)
        .slice(0, 8);
      const created = await createWarningDraft({
        gmail_message_id: gmailMessageId,
        risk_score: result.risk.score,
        risk_band: result.risk.band as "MEDIUM" | "HIGH",
        signals: signals.length > 0 ? signals : ["SUSPICIOUS_EMAIL"],
        recipient_addresses: Array.from(selected),
      });
      setDraft(created);
      setSubject(created.subject);
      setBody(created.body);
      setStage("preview");
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : "Could not generate a warning draft.");
      setStage("error");
    }
  }

  async function confirmAndSend() {
    if (!draft) return;
    setStage("sending");
    setError(null);
    try {
      const idempotencyKey = `${draft.warning_id}-${crypto.randomUUID()}`;
      const response = await confirmWarning(draft.warning_id, {
        confirmed: true,
        idempotency_key: idempotencyKey,
        subject,
        body,
      });
      setConfirmResult(response);
      setStage("sent");
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : "Could not send the warning. Please try again.");
      setStage("error");
    }
  }

  return (
    <div className="mt-3 rounded-xl border border-accent-red/30 bg-accent-red/5 p-4">
      {stage === "idle" && (
        <button
          type="button"
          onClick={openPanel}
          className="flex items-center gap-2 rounded-lg border border-accent-red/40 px-3 py-2 text-sm font-medium text-accent-red hover:bg-accent-red/10"
        >
          <ShieldAlert className="h-4 w-4" /> Alert recent contacts
        </button>
      )}

      {stage === "loading_contacts" && (
        <div className="flex items-center gap-2 text-sm text-foreground-muted">
          <Loader2 className="h-4 w-4 animate-spin" /> Loading your recent contacts…
        </div>
      )}

      {stage === "select" && (
        <div>
          <p className="text-sm font-medium text-foreground">Select contacts to warn</p>
          <p className="mt-1 text-xs text-foreground-muted">
            Chosen from people you have recently emailed. Nothing is sent yet.
          </p>
          {contacts.length === 0 ? (
            <p className="mt-3 text-sm text-foreground-muted">No recent contacts were found.</p>
          ) : (
            <ul className="mt-3 max-h-48 space-y-1 overflow-y-auto">
              {contacts.map((contact) => (
                <li key={contact.address}>
                  <label className="flex items-center gap-2 rounded-lg px-2 py-1.5 text-sm hover:bg-surface-elevated">
                    <input
                      type="checkbox"
                      checked={selected.has(contact.address)}
                      onChange={() => toggleContact(contact.address)}
                    />
                    <span className="text-foreground">{contact.display_name || contact.address}</span>
                    <span className="text-xs text-foreground-subtle">{contact.address}</span>
                  </label>
                </li>
              ))}
            </ul>
          )}
          <button
            type="button"
            onClick={requestDraft}
            disabled={selected.size === 0}
            className="mt-3 rounded-lg bg-accent-blue px-4 py-2 text-sm font-medium text-white disabled:cursor-not-allowed disabled:opacity-40"
          >
            Draft warning for {selected.size} contact{selected.size === 1 ? "" : "s"}
          </button>
        </div>
      )}

      {stage === "drafting" && (
        <div className="flex items-center gap-2 text-sm text-foreground-muted">
          <Loader2 className="h-4 w-4 animate-spin" /> Drafting a warning message…
        </div>
      )}

      {stage === "preview" && draft && (
        <div>
          <p className="text-sm font-medium text-foreground">Review before sending</p>
          <p className="mt-1 text-xs text-foreground-muted">
            Sending to {draft.recipients.length} contact{draft.recipients.length === 1 ? "" : "s"}, one private email each.
          </p>
          <label className="mt-3 block text-xs font-medium text-foreground-subtle">Subject</label>
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
            maxLength={3000}
            rows={5}
            className="mt-1 w-full rounded-lg border border-border bg-surface px-3 py-2 text-sm text-foreground"
          />
          <div className="mt-3 flex gap-2">
            <button
              type="button"
              onClick={confirmAndSend}
              className="flex items-center gap-2 rounded-lg bg-accent-red px-4 py-2 text-sm font-medium text-white hover:opacity-90"
            >
              <Send className="h-4 w-4" /> Confirm and send to {draft.recipients.length}
            </button>
            <button
              type="button"
              onClick={() => setStage("select")}
              className="rounded-lg border border-border px-4 py-2 text-sm font-medium text-foreground hover:bg-surface-elevated"
            >
              Back
            </button>
          </div>
        </div>
      )}

      {stage === "sending" && (
        <div className="flex items-center gap-2 text-sm text-foreground-muted">
          <Loader2 className="h-4 w-4 animate-spin" /> Sending…
        </div>
      )}

      {stage === "sent" && confirmResult && (
        <div>
          <p className="text-sm font-medium text-foreground">Warning status: {confirmResult.status}</p>
          <ul className="mt-2 space-y-1 text-sm">
            {confirmResult.deliveries.map((delivery) => (
              <li key={delivery.recipient} className="text-foreground-muted">
                {delivery.recipient} — {delivery.status}
                {delivery.error ? `: ${delivery.error}` : ""}
              </li>
            ))}
          </ul>
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
