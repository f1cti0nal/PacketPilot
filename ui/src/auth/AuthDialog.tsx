import { useState } from "react";
import { X } from "lucide-react";
import { useDialogA11y } from "../lib/useDialogA11y";
import type { SessionState } from "./useSession";

type AnonSession = Extract<SessionState, { status: "anon" }>;

/**
 * Sign-in entry point. Authentication is handled by Auth0 Universal Login (social,
 * password, MFA), so this dialog just launches the redirect — one button to sign in,
 * one to jump straight to sign-up.
 */
export function AuthDialog({ session, onClose }: { session: AnonSession; onClose: () => void }) {
  const { ref, onKeyDown } = useDialogA11y<HTMLDivElement>(onClose);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const go = async (signUp: boolean) => {
    if (busy) return;
    setBusy(true);
    setError(null);
    try {
      await session.login(signUp ? { signUp: true } : undefined);
      // On success the browser redirects to Auth0; we only land here if that failed to start.
    } catch {
      setError("Couldn't start sign-in. Please try again.");
      setBusy(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 px-4" onClick={onClose}>
      <div
        ref={ref}
        onKeyDown={onKeyDown}
        role="dialog"
        aria-modal="true"
        aria-label="Account"
        onClick={(e) => e.stopPropagation()}
        className="card w-full max-w-sm p-6 shadow-[var(--sh-float)]"
      >
        <div className="mb-4 flex items-center justify-between">
          <h2 className="t-title text-[var(--color-text)]">Sign in</h2>
          <button
            type="button"
            aria-label="Close"
            onClick={onClose}
            className="rounded-[var(--r-tile)] p-1 text-[var(--color-text-faint)] hover:text-[var(--color-text)]"
          >
            <X size={16} aria-hidden />
          </button>
        </div>

        <p className="mb-4 text-sm text-[var(--color-text-dim)]">
          Continue to sign in — reputation enrichment, the AI analyst, and saved preferences unlock once you're in. Your
          captures never leave the browser.
        </p>

        <div className="flex flex-col gap-2">
          <button
            type="button"
            onClick={() => void go(false)}
            disabled={busy}
            className="inline-flex items-center justify-center rounded-[var(--r-tile)] bg-[var(--color-accent-deep)] px-3 py-1.5 text-sm font-medium text-[var(--color-on-accent)] disabled:opacity-60"
          >
            {busy ? "Redirecting…" : "Sign in"}
          </button>
          <button
            type="button"
            onClick={() => void go(true)}
            disabled={busy}
            className="inline-flex items-center justify-center rounded-[var(--r-tile)] border border-[var(--color-border)] bg-[var(--color-surface-2)] px-3 py-1.5 text-sm font-medium text-[var(--color-text)] hover:border-[var(--color-accent)] disabled:opacity-60"
          >
            Create account
          </button>
        </div>

        {error && (
          <p role="alert" className="mt-3 t-tag text-[var(--color-sev-critical)]">
            {error}
          </p>
        )}
      </div>
    </div>
  );
}

export default AuthDialog;
