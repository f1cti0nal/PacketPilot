import { useState } from "react";
import { X } from "lucide-react";
import { useDialogA11y } from "../lib/useDialogA11y";
import { AuthPanel, type AuthMode } from "./AuthPanel";
import type { OAuthProvider, SessionState } from "./useSession";

type AnonSession = Extract<SessionState, { status: "anon" }>;

/**
 * Sign-in entry point shown over the app (native Supabase auth: email/password + Google/GitHub).
 * Holds the same card as the standalone /login page, minus the brand panel, with a login↔signup
 * toggle. On sign-up with email confirmation on, it flips to a "check your inbox" state.
 */
export function AuthDialog({ session, onClose }: { session: AnonSession; onClose: () => void }) {
  const { ref, onKeyDown } = useDialogA11y<HTMLDivElement>(onClose);
  const [mode, setMode] = useState<AuthMode>("login");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [confirmSentTo, setConfirmSentTo] = useState<string | null>(null);

  const onSubmit = async (email: string, password: string) => {
    if (busy) return;
    setBusy(true);
    setError(null);
    if (mode === "signup") {
      const r = await session.signUp(email, password);
      if (!r.ok) setError(r.error ?? "Sign-up failed");
      else if (r.needsConfirm) setConfirmSentTo(email);
      else onClose();
    } else {
      const r = await session.signIn(email, password);
      if (!r.ok) setError(r.error ?? "Sign-in failed");
      else onClose();
    }
    setBusy(false);
  };

  const onSocial = async (provider: OAuthProvider) => {
    if (busy) return;
    setBusy(true);
    setError(null);
    const r = await session.signInWithProvider(provider);
    // On success the browser redirects to the provider; only a failure to start returns here.
    if (!r.ok) {
      setError(r.error ?? "Sign-in failed");
      setBusy(false);
    }
  };

  const onResend = async (email: string) => {
    setBusy(true);
    setError(null);
    const r = await session.resendVerification(email);
    setBusy(false);
    if (!r.ok) setError(r.error ?? "Couldn't resend the email");
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
        className="card relative w-full max-w-sm p-6 shadow-[var(--sh-float)]"
      >
        <button
          type="button"
          aria-label="Close"
          onClick={onClose}
          className="absolute right-3 top-3 rounded-[var(--r-tile)] p-1 text-[var(--color-text-faint)] hover:text-[var(--color-text)]"
        >
          <X size={16} aria-hidden />
        </button>

        <AuthPanel
          mode={mode}
          busy={busy}
          error={error}
          confirmSentTo={confirmSentTo}
          onSwitchMode={setMode}
          onSubmit={onSubmit}
          onSocial={onSocial}
          onResend={onResend}
          titleTag="h2"
        />
      </div>
    </div>
  );
}

export default AuthDialog;
