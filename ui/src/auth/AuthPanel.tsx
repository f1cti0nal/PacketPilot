import { useState, type FormEvent } from "react";
import { ArrowLeft, MailCheck, Radar } from "lucide-react";
import { socialProviders } from "./socialProviders";
import type { OAuthProvider } from "./useSession";

export type AuthMode = "login" | "signup";

export interface AuthPanelProps {
  mode: AuthMode;
  /** True while a request is in flight — disables the buttons and relabels the primary. */
  busy: boolean;
  /** Shown as an inline alert if sign-in / sign-up failed. */
  error?: string | null;
  /** When set, the email/password form is replaced by a "check your inbox" confirmation for
   *  this address (sign-up with email confirmation on). */
  confirmSentTo?: string | null;
  /** Toggle between the login and sign-up presentation. */
  onSwitchMode: (next: AuthMode) => void;
  /** Submit the email + password form (native Supabase sign-in / sign-up). */
  onSubmit: (email: string, password: string) => void;
  /** Continue with a social provider (native Supabase OAuth). */
  onSocial: (provider: OAuthProvider) => void;
  /** Resend the confirmation email (shown on the confirm-pending state). */
  onResend?: (email: string) => void;
  /** Render the "Back to the app" link (the standalone page, not the modal). */
  showBackToApp?: boolean;
  /** Heading element — h1 for the standalone page, h2 inside the modal. */
  titleTag?: "h1" | "h2";
}

const socialBtn =
  "inline-flex items-center justify-center gap-2.5 rounded-[var(--r-tile)] border " +
  "border-[var(--color-border-strong)] bg-[var(--color-surface)] px-3 py-2 text-sm font-medium " +
  "text-[var(--color-text)] transition-colors hover:border-[var(--color-accent)] " +
  "disabled:cursor-not-allowed disabled:opacity-60";

const inputCls =
  "w-full rounded-[var(--r-tile)] border border-[var(--color-border-strong)] bg-[var(--color-surface)] " +
  "px-3 py-2 text-sm text-[var(--color-text)] outline-none transition-colors " +
  "focus:border-[var(--color-accent)]";

/**
 * The shared sign-in / sign-up card body: brand mark, a login↔signup toggle, the (env-gated)
 * social buttons, and an email + password form (native Supabase auth). Used by both the standalone
 * /login + /signup pages and the in-app AuthDialog. On sign-up with email confirmation on, it
 * flips to a "check your inbox" state instead of the form.
 */
export function AuthPanel({
  mode,
  busy,
  error,
  confirmSentTo,
  onSwitchMode,
  onSubmit,
  onSocial,
  onResend,
  showBackToApp = false,
  titleTag = "h1",
}: AuthPanelProps) {
  const isSignup = mode === "signup";
  const providers = socialProviders();
  const Title = titleTag;
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");

  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (!busy) onSubmit(email, password);
  };

  return (
    <div className="flex w-full max-w-[340px] flex-col">
      <a
        href="/"
        aria-label="PacketPilot home"
        className="mb-6 inline-flex items-center gap-2 self-start text-[var(--color-text)]"
      >
        <span
          className="flex h-8 w-8 items-center justify-center rounded-[var(--r-tile)]"
          style={{ background: "color-mix(in srgb, var(--color-accent) 16%, transparent)" }}
        >
          <Radar size={17} style={{ color: "var(--color-accent)" }} aria-hidden />
        </span>
        <span className="font-display text-[15px] font-medium tracking-tight">PacketPilot</span>
      </a>

      {confirmSentTo ? (
        <ConfirmPending email={confirmSentTo} busy={busy} onResend={onResend} titleTag={titleTag} />
      ) : (
        <>
          <Title className="t-host text-[var(--color-text)]">
            {isSignup ? "Create your account" : "Welcome back"}
          </Title>
          <p className="mt-1.5 text-sm text-[var(--color-text-dim)]">
            {isSignup ? "Already have an account? " : "New to PacketPilot? "}
            <button
              type="button"
              onClick={() => onSwitchMode(isSignup ? "login" : "signup")}
              className="font-medium text-[var(--color-accent-strong)] underline-offset-2 hover:underline"
            >
              {isSignup ? "Sign in" : "Create an account"}
            </button>
          </p>

          {providers.length > 0 && (
            <>
              <div className="mt-6 flex flex-col gap-2">
                {providers.map((p) => (
                  <button
                    key={p.provider}
                    type="button"
                    disabled={busy}
                    onClick={() => onSocial(p.provider)}
                    className={socialBtn}
                  >
                    <p.Icon width={18} height={18} aria-hidden />
                    Continue with {p.label}
                  </button>
                ))}
              </div>
              <div
                className="my-4 flex items-center gap-3 t-tag text-[var(--color-text-faint)]"
                aria-hidden
              >
                <span className="h-px flex-1 bg-[var(--color-border)]" />
                OR
                <span className="h-px flex-1 bg-[var(--color-border)]" />
              </div>
            </>
          )}

          <form onSubmit={submit} className={"flex flex-col gap-3" + (providers.length > 0 ? "" : " mt-6")}>
            <label className="flex flex-col gap-1.5">
              <span className="t-label text-[var(--color-text-dim)]">Email</span>
              <input
                type="email"
                autoComplete="username"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className={inputCls}
              />
            </label>
            <label className="flex flex-col gap-1.5">
              <span className="t-label text-[var(--color-text-dim)]">Password</span>
              <input
                type="password"
                autoComplete={isSignup ? "new-password" : "current-password"}
                required
                minLength={isSignup ? 8 : undefined}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className={inputCls}
              />
            </label>
            <button
              type="submit"
              disabled={busy}
              className={
                "mt-1 inline-flex items-center justify-center gap-2 rounded-[var(--r-tile)] " +
                "bg-[var(--color-accent-deep)] px-3 py-2 text-sm font-medium text-[var(--color-on-accent)] " +
                "transition-opacity hover:opacity-95 disabled:cursor-not-allowed disabled:opacity-60"
              }
            >
              {busy ? "Working…" : isSignup ? "Create account" : "Sign in"}
            </button>
          </form>

          <p className="mt-3 text-center text-xs leading-relaxed text-[var(--color-text-faint)]">
            By continuing you agree to the{" "}
            <a href="/terms" className="text-[var(--color-text-dim)] hover:text-[var(--color-text)]">
              Terms
            </a>{" "}
            and{" "}
            <a href="/privacy" className="text-[var(--color-text-dim)] hover:text-[var(--color-text)]">
              Privacy Policy
            </a>
            .
          </p>
        </>
      )}

      {error && (
        <p role="alert" className="mt-3 t-tag text-[var(--color-sev-critical)]">
          {error}
        </p>
      )}

      {showBackToApp && (
        <a
          href="/app"
          className="mt-5 inline-flex items-center gap-1 self-start t-tag text-[var(--color-text-dim)] hover:text-[var(--color-text)]"
        >
          <ArrowLeft size={13} aria-hidden /> Back to the app
        </a>
      )}
    </div>
  );
}

/** Post-sign-up "check your inbox" state (email confirmation is on). */
function ConfirmPending({
  email,
  busy,
  onResend,
  titleTag,
}: {
  email: string;
  busy: boolean;
  onResend?: (email: string) => void;
  titleTag: "h1" | "h2";
}) {
  const Title = titleTag;
  return (
    <>
      <div
        className="mb-3 flex h-9 w-9 items-center justify-center rounded-[var(--r-tile)]"
        style={{ background: "color-mix(in srgb, var(--color-accent) 16%, transparent)" }}
      >
        <MailCheck size={18} style={{ color: "var(--color-accent)" }} aria-hidden />
      </div>
      <Title className="t-host text-[var(--color-text)]">Check your email</Title>
      <p className="mt-1.5 text-sm text-[var(--color-text-dim)]">
        We sent a confirmation link to <span className="text-[var(--color-text)]">{email}</span>. Open it to finish
        creating your account, then you'll be signed in.
      </p>
      {onResend && (
        <button
          type="button"
          disabled={busy}
          onClick={() => onResend(email)}
          className={socialBtn + " mt-6"}
        >
          Resend confirmation email
        </button>
      )}
    </>
  );
}

export default AuthPanel;
