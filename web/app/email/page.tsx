"use client";

import { AlertTriangle, Loader2, Mail, RefreshCw, ShieldCheck } from "lucide-react";
import { useEffect, useState } from "react";

import { Header } from "@/components/Header";
import { RecoveryPanel } from "@/components/RecoveryPanel";
import { RiskResultCard } from "@/components/RiskResultCard";
import { WarningPanel } from "@/components/WarningPanel";
import { ApiError, checkEmailNow, getEmailStatus, startEmailConnect } from "@/lib/api";
import type { CheckNowResponse, EmailStatusResponse } from "@/lib/types";

type LoadState = "loading" | "ready" | "error";

export default function EmailPage() {
  const [status, setStatus] = useState<EmailStatusResponse | null>(null);
  const [loadState, setLoadState] = useState<LoadState>("loading");
  const [error, setError] = useState<string | null>(null);
  const [connecting, setConnecting] = useState(false);
  const [checking, setChecking] = useState(false);
  const [results, setResults] = useState<CheckNowResponse | null>(null);

  async function loadStatus() {
    setLoadState("loading");
    setError(null);
    try {
      setStatus(await getEmailStatus());
      setLoadState("ready");
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : "Could not reach the SafeCheck server. Please try again.");
      setLoadState("error");
    }
  }

  useEffect(() => {
    let active = true;
    void getEmailStatus()
      .then((response) => {
        if (active) {
          setStatus(response);
          setLoadState("ready");
        }
      })
      .catch((caught: unknown) => {
        if (active) {
          setError(caught instanceof ApiError ? caught.message : "Could not reach the SafeCheck server. Please try again.");
          setLoadState("error");
        }
      });
    return () => { active = false; };
  }, []);

  async function connectGmail() {
    setConnecting(true);
    setError(null);
    try {
      const { authorization_url } = await startEmailConnect();
      window.location.assign(authorization_url);
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : "Could not start Gmail connection. Please try again.");
      setConnecting(false);
    }
  }

  async function checkInbox() {
    setChecking(true);
    setError(null);
    setResults(null);
    try {
      const response = await checkEmailNow();
      setResults(response);
      setStatus((current) => current ? { ...current, last_checked_at: new Date().toISOString() } : current);
    } catch (caught) {
      const message = caught instanceof ApiError ? caught.message : "Could not check Gmail. Please try again.";
      setError(caught instanceof ApiError && caught.status === 401 ? `${message} Please reconnect Gmail.` : message);
    } finally {
      setChecking(false);
    }
  }

  return (
    <div className="flex min-h-screen flex-col bg-background">
      <Header />
      <main className="mx-auto flex w-full max-w-5xl flex-1 flex-col px-4 py-8 sm:px-6">
        <div className="mb-6">
          <p className="text-xs font-medium text-foreground-subtle">Dashboard / <span className="text-accent-blue">Gmail Monitor</span></p>
          <h2 className="mt-2 text-2xl font-semibold text-foreground sm:text-3xl">Check your Gmail inbox</h2>
          <p className="mt-1 text-sm text-foreground-muted">Connect Gmail, then analyze your recent inbox messages on demand. SafeCheck never sends a phishing-contact warning without your explicit confirmation.</p>
        </div>

        {error && <div className="mb-5 flex items-center gap-2 rounded-xl border border-accent-red/30 bg-accent-red/10 p-4 text-sm text-accent-red"><AlertTriangle className="h-5 w-5" /> {error}</div>}

        <section className="rounded-2xl border border-border bg-surface p-5 sm:p-6">
          {loadState === "loading" && <div className="flex items-center gap-2 text-sm text-foreground-muted"><Loader2 className="h-4 w-4 animate-spin" /> Checking Gmail connection…</div>}
          {loadState === "ready" && status?.connected && <>
            <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
              <div className="flex gap-3"><span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-accent-green/15"><Mail className="h-5 w-5 text-accent-green" /></span><div><p className="font-medium text-foreground">Gmail connected</p><p className="text-sm text-foreground-muted">{status.email_address}</p>{status.last_checked_at && <p className="mt-1 text-xs text-foreground-subtle">Last checked {new Date(status.last_checked_at).toLocaleString()}</p>}</div></div>
              <div className="flex flex-wrap gap-2">
                <button type="button" onClick={checkInbox} disabled={checking} className="flex items-center justify-center gap-2 rounded-lg bg-accent-blue px-5 py-2.5 text-sm font-medium text-white transition-colors hover:bg-accent-blue-hover disabled:cursor-not-allowed disabled:opacity-40">{checking ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />}{checking ? "Checking inbox…" : "Check inbox now"}</button>
                <button type="button" onClick={connectGmail} disabled={connecting} className="flex items-center justify-center gap-2 rounded-lg border border-border px-5 py-2.5 text-sm font-medium text-foreground transition-colors hover:bg-surface-elevated disabled:cursor-not-allowed disabled:opacity-40">{connecting && <Loader2 className="h-4 w-4 animate-spin" />}{connecting ? "Opening Google…" : "Reconnect Gmail"}</button>
              </div>
            </div>
            <p className="mt-5 text-xs text-foreground-subtle">SafeCheck never modifies or deletes Gmail messages, and only sends a phishing-contact warning after you review it and click Confirm and send. If a warning failed with a send-permission error, click Reconnect Gmail and approve both permissions.</p>
          </>}
          {loadState === "ready" && !status?.connected && <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between"><div className="flex gap-3"><span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-accent-blue/15"><ShieldCheck className="h-5 w-5 text-accent-blue" /></span><div><p className="font-medium text-foreground">Connect Gmail to start monitoring</p><p className="text-sm text-foreground-muted">You will approve Google read-only access in a secure Google window.</p></div></div><button type="button" onClick={connectGmail} disabled={connecting} className="flex items-center justify-center gap-2 rounded-lg bg-accent-blue px-5 py-2.5 text-sm font-medium text-white transition-colors hover:bg-accent-blue-hover disabled:cursor-not-allowed disabled:opacity-40">{connecting && <Loader2 className="h-4 w-4 animate-spin" />}{connecting ? "Opening Google…" : "Connect Gmail"}</button></div>}
          {loadState === "error" && <button type="button" onClick={loadStatus} className="rounded-lg border border-border px-4 py-2 text-sm font-medium text-foreground hover:bg-surface-elevated">Try again</button>}
        </section>

        {results && <section className="mt-8"><h3 className="text-lg font-semibold text-foreground">Inbox analysis <span className="text-sm font-normal text-foreground-muted">({results.checked_count} recent messages)</span></h3>{results.checked_count === 0 ? <p className="mt-4 rounded-xl border border-border bg-surface p-5 text-sm text-foreground-muted">No recent inbox messages were found to check.</p> : <div className="mt-4 space-y-5">{results.results.map((message) => <article key={message.message_id}><div className="rounded-t-xl border border-b-0 border-border bg-surface px-5 py-4"><p className="text-sm font-medium text-foreground">{message.subject || "(No subject)"}</p><p className="mt-1 text-xs text-foreground-muted">From: {message.from || "Unknown sender"} · {new Date(message.received_at).toLocaleString()}</p><p className="mt-2 text-xs text-foreground-subtle">Coverage: {message.analysis_coverage.urls_analyzed}/{message.analysis_coverage.urls_found} URL{message.analysis_coverage.urls_found === 1 ? "" : "s"} analyzed · {message.analysis_coverage.attachments_analyzed}/{message.analysis_coverage.attachments_found} attachment{message.analysis_coverage.attachments_found === 1 ? "" : "s"} analyzed{message.analysis_coverage.skipped_attachments.length > 0 ? ` · ${message.analysis_coverage.skipped_attachments.length} skipped` : ""}</p></div><RiskResultCard result={message.check} /><WarningPanel gmailMessageId={message.message_id} result={message.check} /><RecoveryPanel caseId={message.check.case_id} contextText={`${message.subject}\n${message.from}`} result={message.check} /></article>)}</div>}</section>}
      </main>
    </div>
  );
}
