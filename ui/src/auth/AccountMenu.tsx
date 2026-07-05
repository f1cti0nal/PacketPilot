import { useEffect, useRef, useState } from "react";
import { ChevronDown, User } from "lucide-react";
import type { SessionState } from "./useSession";
import { openPortal } from "./billing";

export function AccountMenu({ session }: { session: SessionState }) {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [billingError, setBillingError] = useState<string | null>(null);
  const ref = useRef<HTMLDivElement>(null);

  // Run a billing action (checkout/portal). On success the page redirects to Stripe, so
  // we only clear `busy` on failure — and surface the error inline.
  const runBilling = async (fn: () => Promise<{ ok: boolean; error?: string }>) => {
    if (busy) return;
    setBusy(true);
    setBillingError(null);
    const r = await fn();
    if (!r?.ok) {
      setBillingError(r?.error ?? "Something went wrong");
      setBusy(false);
    }
  };

  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    document.addEventListener("mousedown", onDoc);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDoc);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  if (session.status === "loading") return null;

  if (session.status === "anon") {
    return (
      <a
        href="/login"
        aria-label="Sign in"
        className="inline-flex items-center gap-1.5 rounded-[var(--r-tile)] border border-[var(--color-border)] bg-transparent px-2.5 py-1.5 text-xs font-medium text-[var(--color-text-dim)] transition-colors hover:border-[var(--color-border-strong)] hover:text-[var(--color-text)]"
      >
        <User size={14} aria-hidden />
        <span className="hidden sm:inline">Sign in</span>
      </a>
    );
  }

  return (
    <div ref={ref} className="relative">
      <button
        type="button"
        aria-label="Account menu"
        aria-haspopup="true"
        aria-expanded={open}
        onClick={() => setOpen((o) => !o)}
        className="inline-flex items-center gap-1.5 rounded-[var(--r-tile)] border border-[var(--color-border)] bg-[var(--color-surface-2)] px-2 py-1.5 text-xs text-[var(--color-text-dim)] hover:text-[var(--color-text)]"
      >
        <User size={14} aria-hidden />
        <span className="hidden max-w-[10rem] truncate lg:inline">{session.email}</span>
        <ChevronDown size={13} aria-hidden />
      </button>
      {open && (
        <div className="absolute right-0 z-40 mt-1 w-52 rounded-[var(--r-tile)] border border-[var(--color-border)] bg-[var(--color-surface-raised)] p-2 shadow-[var(--sh-float)]">
          <div className="truncate px-1 pb-1 text-xs text-[var(--color-text-dim)]">{session.email}</div>
          <div className="px-1 pb-2">
            <span className="inline-flex items-center rounded-[var(--r-chip)] border border-[var(--color-border)] bg-[var(--color-surface-2)] px-1.5 py-0.5 t-tag uppercase text-[var(--color-text-dim)]">
              {session.profile.plan}
            </span>
          </div>
          <a
            href="/account"
            className="block w-full rounded-[var(--r-micro)] px-2 py-1.5 text-left text-sm text-[var(--color-text-dim)] hover:bg-[var(--color-surface-2)] hover:text-[var(--color-text)]"
          >
            Profile &amp; account
          </a>
          {session.profile.plan !== "pro" ? (
            <a
              href="/pricing"
              className="block w-full rounded-[var(--r-micro)] px-2 py-1.5 text-left text-sm text-[var(--color-accent-strong)] hover:bg-[var(--color-surface-2)]"
            >
              Upgrade to Pro
            </a>
          ) : session.profile.hasBilling ? (
            <button
              type="button"
              disabled={busy}
              onClick={() => void runBilling(openPortal)}
              className="w-full rounded-[var(--r-micro)] px-2 py-1.5 text-left text-sm text-[var(--color-text-dim)] hover:bg-[var(--color-surface-2)] hover:text-[var(--color-text)] disabled:opacity-60"
            >
              {busy ? "Opening…" : "Manage billing"}
            </button>
          ) : (
            // Comped Pro (no Stripe customer): nothing to manage — explain instead of offering
            // a button that would only error. /account → Plan & billing says the same.
            <p className="px-2 py-1.5 text-xs text-[var(--color-text-dim)]">Managed by your administrator</p>
          )}
          {billingError && (
            <p role="alert" className="px-1 pt-1 t-tag text-[var(--color-sev-critical)]">
              {billingError}
            </p>
          )}
          <button
            type="button"
            onClick={() => void session.signOut()}
            className="w-full rounded-[var(--r-micro)] px-2 py-1.5 text-left text-sm text-[var(--color-text-dim)] hover:bg-[var(--color-surface-2)] hover:text-[var(--color-text)]"
          >
            Sign out
          </button>
        </div>
      )}
    </div>
  );
}

export default AccountMenu;
