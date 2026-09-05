import {
  AlertCircle,
  CheckCircle2,
  HelpCircle,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";

import type { CheckResponse, EvidenceItem, RiskBand } from "@/lib/types";

interface BandStyle {
  label: string;
  icon: LucideIcon;
  textClass: string;
  bgClass: string;
  ringClass: string;
}

/** Visual treatment per risk band. Colors are defined in globals.css as
 * --color-risk-* tokens, matching the 4-band scale from
 * docs/scoring-engine.md exactly (LOW/UNCERTAIN/MEDIUM/HIGH). */
const BAND_STYLES: Record<RiskBand, BandStyle> = {
  LOW: {
    label: "Low Risk",
    icon: ShieldCheck,
    textClass: "text-risk-low",
    bgClass: "bg-risk-low-bg",
    ringClass: "ring-risk-low/30",
  },
  UNCERTAIN: {
    label: "Uncertain",
    icon: HelpCircle,
    textClass: "text-risk-uncertain",
    bgClass: "bg-risk-uncertain-bg",
    ringClass: "ring-risk-uncertain/30",
  },
  MEDIUM: {
    label: "Medium Risk",
    icon: AlertCircle,
    textClass: "text-risk-medium",
    bgClass: "bg-risk-medium-bg",
    ringClass: "ring-risk-medium/30",
  },
  HIGH: {
    label: "High Risk",
    icon: ShieldAlert,
    textClass: "text-risk-high",
    bgClass: "bg-risk-high-bg",
    ringClass: "ring-risk-high/30",
  },
};

function EvidenceRow({ item }: { item: EvidenceItem }) {
  const isUnavailable = item.availability === "unavailable";

  return (
    <li
      className={`flex items-start justify-between gap-3 rounded-lg border px-3 py-2.5 ${
        isUnavailable
          ? "border-border bg-surface"
          : "border-border bg-surface-elevated"
      }`}
    >
      <div className="min-w-0 flex-1">
        <p
          className={`text-sm font-medium ${
            isUnavailable ? "text-foreground-subtle" : "text-foreground"
          }`}
        >
          {formatSignalLabel(item.signal)}
        </p>
        <p className="mt-0.5 text-xs text-foreground-muted">{item.reason}</p>
        {isUnavailable && (
          <p className="mt-1 text-xs italic text-foreground-subtle">
            Check unavailable -- not counted toward the score.
          </p>
        )}
      </div>
      <span
        className={`shrink-0 rounded-full px-2 py-0.5 text-xs font-semibold ${
          isUnavailable
            ? "bg-surface-elevated text-foreground-subtle"
            : "bg-background text-foreground"
        }`}
      >
        {isUnavailable ? "N/A" : `+${item.points}`}
      </span>
    </li>
  );
}

/** "LOOKALIKE_DOMAIN" -> "Lookalike Domain". Signals are stable
 * machine-readable codes on the backend; this is a display-only
 * transform. */
function formatSignalLabel(signal: string): string {
  return signal
    .split("_")
    .map((word) => word.charAt(0) + word.slice(1).toLowerCase())
    .join(" ");
}

export function RiskResultCard({ result }: { result: CheckResponse }) {
  const style = BAND_STYLES[result.risk.band];
  const BandIcon = style.icon;

  // Evidence that actually contributed to the score, shown separately
  // from checks that could not be completed -- these must never be
  // presented as equivalent (per the backend's own availability
  // invariant from docs/scoring-engine.md Section 4).
  const availableEvidence = result.evidence.filter(
    (item) => item.availability === "available"
  );
  const unavailableEvidence = result.evidence.filter(
    (item) => item.availability === "unavailable"
  );

  return (
    <div className="mt-6 overflow-hidden rounded-2xl border border-border bg-surface">
      <div className={`flex items-center gap-4 px-5 py-5 sm:px-6 ${style.bgClass}`}>
        <span
          className={`flex h-14 w-14 shrink-0 items-center justify-center rounded-full ring-4 ${style.ringClass} bg-surface`}
        >
          <BandIcon className={`h-7 w-7 ${style.textClass}`} strokeWidth={2} />
        </span>
        <div>
          <p className={`text-sm font-semibold uppercase tracking-wide ${style.textClass}`}>
            {style.label}
          </p>
          <p className="text-2xl font-bold text-foreground">
            {result.risk.score}
            <span className="text-base font-medium text-foreground-muted">
              {" "}
              / 100
            </span>
          </p>
        </div>
      </div>

      <div className="space-y-5 px-5 py-5 sm:px-6">
        <div>
          <p className="text-sm text-foreground">{result.explanation.summary}</p>
        </div>

        {availableEvidence.length > 0 && (
          <div>
            <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-foreground-subtle">
              Why
            </h3>
            <ul className="space-y-2">
              {availableEvidence.map((item, index) => (
                <EvidenceRow
                  key={`${item.signal}-${item.source}-${item.correlationGroup}-${index}`}
                  item={item}
                />
              ))}
            </ul>
          </div>
        )}

        {unavailableEvidence.length > 0 && (
          <div>
            <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-foreground-subtle">
              Checks that could not be completed
            </h3>
            <ul className="space-y-2">
              {unavailableEvidence.map((item, index) => (
                <EvidenceRow
                  key={`${item.signal}-${item.source}-${item.correlationGroup}-${index}`}
                  item={item}
                />
              ))}
            </ul>
          </div>
        )}

        {result.explanation.uncertainty.length > 0 && (
          <div className="rounded-lg border border-border bg-surface-elevated px-3 py-2.5">
            {result.explanation.uncertainty.map((note, index) => (
              <p key={index} className="text-xs text-foreground-muted">
                {note}
              </p>
            ))}
          </div>
        )}

        <div>
          <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-foreground-subtle">
            What to do
          </h3>
          <p className="text-sm text-foreground">
            {result.explanation.next_action}
          </p>
        </div>

        {result.safe_actions.length > 0 && (
          <ul className="space-y-2">
            {result.safe_actions.map((action, index) => (
              <li
                key={index}
                className="flex items-start gap-2 text-sm text-foreground-muted"
              >
                <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-accent-green" />
                {action}
              </li>
            ))}
          </ul>
        )}

        <p className="text-xs text-foreground-subtle">
          Case {result.case_id} &middot;{" "}
          {new Date(result.created_at).toLocaleString()}
        </p>
      </div>
    </div>
  );
}
