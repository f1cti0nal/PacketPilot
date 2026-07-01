import { useEffect } from "react";
import { Radar, ArrowLeft } from "lucide-react";
import { useSession } from "./useSession";
import { auth0Login, auth0Logout } from "./auth0Client";
import { LoadingState } from "../components/state/LoadingState";
import { ThemeToggle } from "../cockpit/ThemeToggle";

type Mode = "login" | "signup" | "logout";

/** Which dedicated auth endpoint we're on. */
export function modeFromPath(pathname: string = window.location.pathname): Mode {
  const p = pathname.replace(/\/+$/, "");
  if (p === "/signup") return "signup";
  if (p === "/logout") return "logout";
  return "login";
}

/**
 * Dedicated /login, /signup, /logout endpoints. Login/signup render a real page (so the
 * entry point is linkable and easy to monitor) that launches Auth0 Universal Login; /logout
 * ends the Auth0 session. Already-signed-in users are bounced to /app.
 */
export function AuthApp() {
  const session = useSession();
  const mode = modeFromPath();

  useEffect(() => {
    if (mode === "logout") {
      void auth0Logout();
      return;
    }
    if (session.status === "authed") window.location.assign("/app");
  }, [mode, session.status]);

  // Return to /app after auth (a stable, already-registered Auth0 callback) so these
  // transient pages don't each need their own Allowed Callback URL.
  const start = (signUp: boolean) => {
    void auth0Login({ signUp, returnTo: "/app" });
  };

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
          <section className="card p-6 shadow-[var(--sh-float)]">
            <h1 className="t-title text-[var(--color-text)]">
              {mode === "signup" ? "Create your account" : "Sign in"}
            </h1>
            <p className="mt-2 text-sm text-[var(--color-text-dim)]">
              Continue to {mode === "signup" ? "create your account" : "sign in"} — your captures stay in the browser;
              signing in unlocks reputation enrichment, the AI analyst, and saved preferences.
            </p>
            <div className="mt-5 flex flex-col gap-2">
              <button
                type="button"
                onClick={() => start(mode === "signup")}
                className="inline-flex items-center justify-center rounded-[var(--r-tile)] bg-[var(--color-accent-deep)] px-3 py-2 text-sm font-medium text-[var(--color-on-accent)]"
              >
                {mode === "signup" ? "Create account" : "Sign in"}
              </button>
              <a
                href={mode === "signup" ? "/login" : "/signup"}
                className="inline-flex items-center justify-center rounded-[var(--r-tile)] border border-[var(--color-border)] bg-[var(--color-surface-2)] px-3 py-2 text-sm font-medium text-[var(--color-text)] hover:border-[var(--color-accent)]"
              >
                {mode === "signup" ? "I already have an account" : "Create an account"}
              </a>
            </div>
            <a
              href="/app"
              className="mt-4 inline-flex items-center gap-1 t-tag text-[var(--color-text-dim)] hover:text-[var(--color-text)]"
            >
              <ArrowLeft size={13} aria-hidden /> Back to the app
            </a>
          </section>
        )}
      </main>
    </div>
  );
}

export default AuthApp;
