import Link from "next/link";
import { ShieldCheck } from "lucide-react";

/**
 * Top-level app header. Matches the reference mockups' top bar: logo
 * mark, product name, and a short tagline.
 */
export function Header() {
  return (
    <header className="border-b border-border bg-surface">
      <div className="mx-auto flex max-w-5xl items-center justify-between gap-3 px-4 py-4 sm:px-6">
        <Link href="/check" className="flex items-center gap-3" aria-label="SafeCheck manual check">
          <span className="flex h-9 w-9 items-center justify-center rounded-lg bg-accent-blue">
            <ShieldCheck className="h-5 w-5 text-white" strokeWidth={2.5} />
          </span>
          <div>
            <h1 className="text-base font-semibold text-foreground sm:text-lg">
              SafeCheck
            </h1>
            <p className="text-xs text-foreground-muted">
              Digital Safety Copilot
            </p>
          </div>
        </Link>
        <nav aria-label="Primary navigation" className="flex items-center gap-1 text-sm">
          <Link href="/check" className="rounded-md px-2.5 py-1.5 text-foreground-muted transition-colors hover:bg-surface-elevated hover:text-foreground sm:px-3">
            Manual Check
          </Link>
          <Link href="/email" className="rounded-md px-2.5 py-1.5 text-foreground-muted transition-colors hover:bg-surface-elevated hover:text-foreground sm:px-3">
            Gmail Monitor
          </Link>
        </nav>
      </div>
    </header>
  );
}
