import { Info } from "lucide-react";

/**
 * Shown at the top of /app when it's the public, anonymous demo (/app?sample=1). The full app
 * now requires a signed-in, email-verified account (see AppGate); this bar keeps the sample
 * open to marketing/SEO "try it" traffic while nudging visitors to create an account to analyze
 * their own captures.
 */
export function DemoBanner() {
  return (
    <div className="flex flex-wrap items-center justify-center gap-x-3 gap-y-1 border-b border-[var(--color-border)] bg-[color:color-mix(in_srgb,var(--color-accent)_10%,var(--color-surface))] px-4 py-2 text-center t-tag text-[var(--color-text-dim)]">
      <span className="inline-flex items-center gap-1.5">
        <Info size={13} aria-hidden style={{ color: "var(--color-accent)" }} />
        You're exploring a sample capture.
      </span>
      <span>
        <a href="/signup" className="font-medium text-[var(--color-accent-strong)] hover:underline">
          Create a free account
        </a>{" "}
        or{" "}
        <a href="/login" className="font-medium text-[var(--color-accent-strong)] hover:underline">
          sign in
        </a>{" "}
        to analyze your own captures.
      </span>
    </div>
  );
}

export default DemoBanner;
