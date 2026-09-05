"use client";

import { AlertTriangle, Link2, Loader2 } from "lucide-react";
import { useState } from "react";

import { Header } from "@/components/Header";
import { InputTabs } from "@/components/InputTabs";
import type { InputTab } from "@/components/InputTabs";
import { FileDropzone } from "@/components/FileDropzone";
import { RiskResultCard } from "@/components/RiskResultCard";
import { ApiError, checkContent, checkDocument } from "@/lib/api";
import type { CheckResponse } from "@/lib/types";

type SubmissionState = "idle" | "loading" | "success" | "error";

export default function CheckPage() {
  const [activeTab, setActiveTab] = useState<InputTab>("text");

  const [text, setText] = useState("");
  const [url, setUrl] = useState("");
  const [file, setFile] = useState<File | null>(null);

  const [fileError, setFileError] = useState<string | null>(null);

  const [submissionState, setSubmissionState] =
    useState<SubmissionState>("idle");
  const [result, setResult] = useState<CheckResponse | null>(null);
  const [submissionError, setSubmissionError] = useState<string | null>(
    null
  );

  const isSubmitDisabled =
    submissionState === "loading" ||
    (activeTab === "text" && text.trim().length === 0) ||
    (activeTab === "url" && url.trim().length === 0) ||
    (activeTab === "document" && file === null);

  /** Switching tabs abandons any previous result -- each tab represents
   * a genuinely separate analysis, not a continuation of the same one. */
  function handleTabChange(tab: InputTab) {
    setActiveTab(tab);
    setSubmissionState("idle");
    setResult(null);
    setSubmissionError(null);
  }

  async function handleSubmit() {
    setSubmissionState("loading");
    setResult(null);
    setSubmissionError(null);

    try {
      let response: CheckResponse;

      if (activeTab === "text") {
        response = await checkContent({
          source_type: "TEXT",
          payload: { text },
        });
      } else if (activeTab === "url") {
        response = await checkContent({
          source_type: "URL",
          payload: { url },
        });
      } else {
        if (!file) {
          // isSubmitDisabled already prevents this, but satisfies
          // TypeScript's narrowing and guards against a future regression.
          throw new Error("No file selected.");
        }
        response = await checkDocument(file);
      }

      setResult(response);
      setSubmissionState("success");
    } catch (error) {
      const message =
        error instanceof ApiError
          ? error.message
          : "Could not reach the SafeCheck server. Please try again.";
      setSubmissionError(message);
      setSubmissionState("error");
    }
  }

  return (
    <div className="flex min-h-screen flex-col bg-background">
      <Header />

      <main className="mx-auto flex w-full max-w-5xl flex-1 flex-col px-4 py-8 sm:px-6">
        <div className="mb-6">
          <p className="text-xs font-medium text-foreground-subtle">
            Dashboard / <span className="text-accent-blue">Manual Check</span>
          </p>
          <h2 className="mt-2 text-2xl font-semibold text-foreground sm:text-3xl">
            Verify a message, URL, or file
          </h2>
          <p className="mt-1 text-sm text-foreground-muted">
            Every submission runs through the same deterministic risk
            engine, whichever way you provide it.
          </p>
        </div>

        <InputTabs active={activeTab} onChange={handleTabChange} />

        <div className="mt-6 rounded-2xl border border-border bg-surface p-5 sm:p-6">
          {activeTab === "document" && (
            <FileDropzone
              file={file}
              onFileSelected={setFile}
              onValidationError={setFileError}
            />
          )}

          {activeTab === "url" && (
            <div>
              <label
                htmlFor="url-input"
                className="mb-2 block text-sm font-medium text-foreground"
              >
                URL to check
              </label>
              <div className="flex flex-col gap-3 sm:flex-row">
                <div className="relative flex-1">
                  <Link2 className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-foreground-subtle" />
                  <input
                    id="url-input"
                    type="text"
                    value={url}
                    onChange={(event) => setUrl(event.target.value)}
                    placeholder="https://example.com/verify"
                    className="w-full rounded-lg border border-border bg-surface-elevated py-2.5 pl-10 pr-3 text-sm text-foreground placeholder:text-foreground-subtle focus:border-border-focus focus:outline-none"
                  />
                </div>
                <button
                  type="button"
                  onClick={handleSubmit}
                  disabled={isSubmitDisabled}
                  className="flex items-center justify-center gap-2 rounded-lg bg-accent-blue px-5 py-2.5 text-sm font-medium text-white transition-colors hover:bg-accent-blue-hover disabled:cursor-not-allowed disabled:opacity-40 sm:w-auto"
                >
                  {submissionState === "loading" && (
                    <Loader2 className="h-4 w-4 animate-spin" />
                  )}
                  Check URL
                </button>
              </div>
            </div>
          )}

          {activeTab === "text" && (
            <div>
              <label
                htmlFor="text-input"
                className="mb-2 block text-sm font-medium text-foreground"
              >
                Paste the message
              </label>
              <textarea
                id="text-input"
                value={text}
                onChange={(event) => setText(event.target.value)}
                rows={6}
                placeholder="Paste an SMS, WhatsApp message, or email text here..."
                className="w-full rounded-lg border border-border bg-surface-elevated p-3 text-sm text-foreground placeholder:text-foreground-subtle focus:border-border-focus focus:outline-none"
              />
            </div>
          )}

          {fileError && (
            <p className="mt-3 flex items-center gap-2 text-sm text-accent-red">
              <AlertTriangle className="h-4 w-4" />
              {fileError}
            </p>
          )}

          {submissionError && (
            <p className="mt-3 flex items-center gap-2 text-sm text-accent-red">
              <AlertTriangle className="h-4 w-4" />
              {submissionError}
            </p>
          )}

          {activeTab !== "url" && (
            <button
              type="button"
              onClick={handleSubmit}
              disabled={isSubmitDisabled}
              className="mt-5 flex w-full items-center justify-center gap-2 rounded-lg bg-accent-blue px-5 py-3 text-sm font-medium text-white transition-colors hover:bg-accent-blue-hover disabled:cursor-not-allowed disabled:opacity-40"
            >
              {submissionState === "loading" && (
                <Loader2 className="h-4 w-4 animate-spin" />
              )}
              {submissionState === "loading" ? "Analyzing..." : "Analyze Now"}
            </button>
          )}
        </div>

        {result && <RiskResultCard result={result} />}

        <p className="mt-4 text-center text-xs text-foreground-subtle">
          We do not store OTPs, PINs, or passwords found in submitted
          content.
        </p>
      </main>
    </div>
  );
}
