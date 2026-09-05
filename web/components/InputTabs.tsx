"use client";

import { FileText, Link2 } from "lucide-react";
import type { LucideIcon } from "lucide-react";

export type InputTab = "text" | "url";

interface TabDefinition {
  id: InputTab;
  label: string;
  sublabel: string;
  icon: LucideIcon;
}

/** Two tabs matching the two supported manual analyzers. Screenshot/file
 * upload is temporarily removed from the UI (extraction quality was not
 * good enough yet) -- the backend /v1/document endpoint and analyzer are
 * left intact so this can be re-enabled later without re-implementing it.
 * No QR tab -- that backend feature does not exist (deliberately out of
 * scope, per an earlier project decision), so no UI is built to promise it. */
const TABS: TabDefinition[] = [
  {
    id: "url",
    label: "Direct URL",
    sublabel: "Domain & reputation checks",
    icon: Link2,
  },
  {
    id: "text",
    label: "Paste Message",
    sublabel: "SMS, email, or chat text",
    icon: FileText,
  },
];

interface InputTabsProps {
  active: InputTab;
  onChange: (tab: InputTab) => void;
}

export function InputTabs({ active, onChange }: InputTabsProps) {
  return (
    <div
      role="tablist"
      aria-label="Content type to analyze"
      className="grid grid-cols-1 gap-3 sm:grid-cols-3"
    >
      {TABS.map((tab) => {
        const Icon = tab.icon;
        const isActive = tab.id === active;
        return (
          <button
            key={tab.id}
            type="button"
            role="tab"
            aria-selected={isActive}
            onClick={() => onChange(tab.id)}
            className={`flex flex-col items-center gap-2 rounded-xl border px-4 py-5 text-center transition-colors ${
              isActive
                ? "border-accent-blue bg-surface-elevated"
                : "border-border bg-surface hover:border-foreground-subtle"
            }`}
          >
            <span
              className={`flex h-10 w-10 items-center justify-center rounded-full ${
                isActive ? "bg-accent-blue" : "bg-surface-elevated"
              }`}
            >
              <Icon
                className={`h-5 w-5 ${
                  isActive ? "text-white" : "text-foreground-muted"
                }`}
                strokeWidth={2}
              />
            </span>
            <span className="text-sm font-medium text-foreground">
              {tab.label}
            </span>
            <span className="text-xs text-foreground-subtle">
              {tab.sublabel}
            </span>
          </button>
        );
      })}
    </div>
  );
}
