import { useEffect, useState, type FormEvent } from "react";
import { Radar, ArrowLeft } from "lucide-react";
import { useSession, type OAuthProvider, type SessionState } from "./useSession";
import { LoadingState } from "../components/state/LoadingState";
import { ThemeToggle } from "../cockpit/ThemeToggle";

type Mode = "login" | "signup" | "logout";
type AnonSession = Extract<SessionState, { status: "anon" }>;

/** Which dedicated auth endpoint we're on. */
export function modeFromPath(pathname: string = window.location.pathname): Mode {
  const p = pathname.replace(/\/+$/, "");
  if (p === "/signup") return "signup";
  if (p === "/logout") return "logout";
  return "login";
}

/**
 * Dedicated /login, /signup, /logout endpoints. Login/signup render a real native form
 * (email/password + Google/GitHub) so the entry point is linkable and monitorable; /logout ends
 * the Supabase session. Already-signed-in users are bounced to /app.
 */
export function AuthApp() {
  const session = useSession();
  const mode = modeFromPath();

  useEffect(() => {
    if (mode === "logout") {
      // Sign out (once the session resolves), then return to the landing page.
      if (session.status === "authed") void session.signOut().then(() => window.location.assign("/"));
      else if (session.status === "anon") window.location.assign("/");
      return;
    }
    if (session.status === "authed") window.location.assign("/app");
  }, [mode, session]);

  return (
    <div className="min-h-screen bg-[var(--color-bg)] text-[var(--color-text)]">
      <header className="flex h-14 items-center gap-3 border-b border-[var(--color-border)] bg-[var(--color-surface)] px-4">
        <a
          href="/"
          aria-label="Home"
          className="flex items-center gap-2 text-[var(--color-text-dim)] hover:text-[var(--color-text)]"
        >
          <span
            className="flex h-7 w-7 items-center justify-center rounded-[var(--r-tile)]"
            style={{ background: "color-mix(in srgb, var(--color-accent) 16%, transparent)" }}
          >
            <Radar size={16} style={{ color: "var(--color-accent)" }} aria-hidden />
          </span>
          <span className="font-display text-[15px] font-medium tracking-tight">PacketPilot</span>
        </a>
        <div className="ml-auto">
          <ThemeToggle />
        </div>
      </header>

      <main className="mx-auto flex w-full max-w-sm flex-col px-4 py-16">
        {mode === "logout" ? (
          <LoadingState label="Signing out…" />
        ) : session.status === "loading" ? (
          <LoadingState label="Loading…" />
        ) : session.status === "authed" ? (
          <LoadingState label="Redirecting…" />
        ) : (
          <AuthCard session={session} initialMode={mode === "signup" ? "signup" : "signin"} />
        )}
      </main>
    </div>
  );
}

/** Full-page native sign-in / sign-up card (email/password + OAuth), with a confirm-pending state. */
function AuthCard({ session, initialMode }: { session: AnonSession; initialMode: "signin" | "signup" }) {
  const [mode, setMode] = useState<"signin" | "signup">(initialMode);
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
      else window.location.assign("/app");
    } else {
      const r = await session.signUp(email, password);
      if (!r.ok) setError(r.error ?? "Sign-up failed");
      else if (r.needsConfirm) setConfirmFor(email);
      else window.location.assign("/app");
    }
    setBusy(false);
  };

  const oauth = async (provider: OAuthProvider) => {
    if (busy) return;
    setBusy(true);
    setError(null);
    const r = await session.signInWithProvider(provider);
    if (!r.ok) {
      setError(r.error ?? "Sign-in failed");
      setBusy(false);
    }
  };

  const inputCls =
    "rounded-[var(--r-tile)] border border-[var(--color-border)] bg-[var(--color-surface-2)] px-3 py-1.5 text-[var(--color-text)] outline-none focus:border-[var(--color-accent)]";

  if (confirmFor) {
    return (
      <section className="card p-6 shadow-[var(--sh-float)]">
        <h1 className="t-title text-[var(--color-text)]">Check your email</h1>
        <p className="mt-2 text-sm text-[var(--color-text-dim)]">
          We sent a confirmation link to <span className="text-[var(--color-text)]">{confirmFor}</span>. Open it to finish
          creating your account, then you'll be signed in.
        </p>
        <a
          href="/app"
          className="mt-4 inline-flex items-center gap-1 t-tag text-[var(--color-text-dim)] hover:text-[var(--color-text)]"
        >
          <ArrowLeft size={13} aria-hidden /> Back to the app
        </a>
      </section>
    );
  }

  return (
    <section className="card p-6 shadow-[var(--sh-float)]">
      <h1 className="t-title text-[var(--color-text)]">{mode === "signup" ? "Create your account" : "Sign in"}</h1>
      <p className="mt-2 text-sm text-[var(--color-text-dim)]">
        Your captures stay in the browser; signing in unlocks reputation enrichment, the AI analyst, and saved
        preferences.
      </p>

      <div className="mt-5 flex flex-col gap-2">
        <button type="button" onClick={() => oauth("google")} disabled={busy} className={oauthBtn}>
          <GoogleIcon />
          Continue with Google
        </button>
        <button type="button" onClick={() => oauth("github")} disabled={busy} className={oauthBtn}>
          <GithubIcon />
          Continue with GitHub
        </button>
      </div>
      <div className="my-4 flex items-center gap-2 text-[var(--color-text-faint)]">
        <span className="h-px flex-1 bg-[var(--color-border)]" aria-hidden />
        <span className="t-tag">or</span>
        <span className="h-px flex-1 bg-[var(--color-border)]" aria-hidden />
      </div>

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
          className="mt-1 inline-flex items-center justify-center rounded-[var(--r-tile)] bg-[var(--color-accent-deep)] px-3 py-2 text-sm font-medium text-[var(--color-on-accent)] disabled:opacity-60"
        >
          {busy ? "Working…" : mode === "signup" ? "Create account" : "Sign in"}
        </button>
      </form>

      <button
        type="button"
        onClick={() => {
          setMode(mode === "signin" ? "signup" : "signin");
          setError(null);
        }}
        className="mt-3 text-xs text-[var(--color-text-dim)] hover:text-[var(--color-text)]"
      >
        {mode === "signin" ? "No account? Create one" : "Have an account? Sign in"}
      </button>
      <a
        href="/app"
        className="mt-4 flex items-center gap-1 t-tag text-[var(--color-text-dim)] hover:text-[var(--color-text)]"
      >
        <ArrowLeft size={13} aria-hidden /> Back to the app
      </a>
    </section>
  );
}

const oauthBtn =
  "inline-flex items-center justify-center gap-2 rounded-[var(--r-tile)] border border-[var(--color-border)] bg-[var(--color-surface-2)] px-3 py-2 text-sm font-medium text-[var(--color-text)] hover:border-[var(--color-accent)] disabled:opacity-60";

/** Google's 4-colour "G" mark. */
function GoogleIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 48 48" aria-hidden focusable="false">
      <path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z" />
      <path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z" />
      <path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z" />
      <path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z" />
    </svg>
  );
}

/** GitHub's octocat mark (inherits the button text colour). */
function GithubIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor" aria-hidden focusable="false">
      <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82a7.6 7.6 0 0 1 2-.27c.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0 0 16 8c0-4.42-3.58-8-8-8z" />
    </svg>
  );
}

export default AuthApp;
