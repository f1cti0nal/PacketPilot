import { useState, type FormEvent } from "react";
import { X } from "lucide-react";
import { useDialogA11y } from "../lib/useDialogA11y";
import type { SessionState } from "./useSession";

type AnonSession = Extract<SessionState, { status: "anon" }>;

export function AuthDialog({ session, onClose }: { session: AnonSession; onClose: () => void }) {
  const { ref, onKeyDown } = useDialogA11y<HTMLDivElement>(onClose);
  const [mode, setMode] = useState<"signin" | "signup">("signin");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [confirmFor, setConfirmFor] = useState<string | null>(null);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (busy) return;
    setBusy(true);
    setError(null);
    if (mode === "signin") {
      const r = await session.signIn(email, password);
      if (!r.ok) setError(r.error ?? "Sign-in failed");
      else onClose();
    } else {
      const r = await session.signUp(email, password);
      if (!r.ok) setError(r.error ?? "Sign-up failed");
      else if (r.needsConfirm) setConfirmFor(email);
      else onClose();
    }
    setBusy(false);
  };

  const title = confirmFor ? "Check your email" : mode === "signin" ? "Sign in" : "Create account";
  const inputCls =
    "rounded-[var(--r-tile)] border border-[var(--color-border)] bg-[var(--color-surface-2)] px-3 py-1.5 text-[var(--color-text)] outline-none focus:border-[var(--color-accent)]";

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
          <h2 className="t-title text-[var(--color-text)]">{title}</h2>
          <button
            type="button"
            aria-label="Close"
            onClick={onClose}
            className="rounded-[var(--r-tile)] p-1 text-[var(--color-text-faint)] hover:text-[var(--color-text)]"
          >
            <X size={16} aria-hidden />
          </button>
        </div>

        {confirmFor ? (
          <p className="text-sm text-[var(--color-text-dim)]">
            We sent a confirmation link to <span className="text-[var(--color-text)]">{confirmFor}</span>. Click it to
            finish, then sign in.
          </p>
        ) : (
          <form onSubmit={submit} className="flex flex-col gap-3">
            <label className="flex flex-col gap-1 text-sm">
              <span className="t-label text-[var(--color-text-dim)]">Email</span>
              <input type="email" autoComplete="username" required value={email} onChange={(e) => setEmail(e.target.value)} className={inputCls} />
            </label>
            <label className="flex flex-col gap-1 text-sm">
              <span className="t-label text-[var(--color-text-dim)]">Password</span>
              <input
                type="password"
                autoComplete={mode === "signin" ? "current-password" : "new-password"}
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className={inputCls}
              />
            </label>
            {error && (
              <p role="alert" className="t-tag text-[var(--color-sev-critical)]">
                {error}
              </p>
            )}
            <button
              type="submit"
              disabled={busy}
              className="mt-1 inline-flex items-center justify-center rounded-[var(--r-tile)] bg-[var(--color-accent-deep)] px-3 py-1.5 text-sm font-medium text-[var(--color-on-accent)] disabled:opacity-60"
            >
              {busy ? "Working…" : mode === "signin" ? "Sign in" : "Create account"}
            </button>
            <button
              type="button"
              onClick={() => {
                setMode(mode === "signin" ? "signup" : "signin");
                setError(null);
              }}
              className="text-xs text-[var(--color-text-dim)] hover:text-[var(--color-text)]"
            >
              {mode === "signin" ? "No account? Create one" : "Have an account? Sign in"}
            </button>
          </form>
        )}
      </div>
    </div>
  );
}

export default AuthDialog;
