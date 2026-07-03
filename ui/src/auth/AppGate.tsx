import { useEffect, useState, type ReactNode } from "react";
import { Radar, MailCheck } from "lucide-react";
import App from "../App";
import { useSession } from "./useSession";
import { supabase, supabaseConfigured } from "../lib/supabase";
import { LoadingState } from "../components/state/LoadingState";
import { ThemeToggle } from "../cockpit/ThemeToggle";

/**
 * Whether this /app load is the public, anonymous demo. The sanctioned demo entry is
 * /app?sample=1 (SEO/marketing "try it" links, see seo/ToolPage) — the ONLY param that also
 * makes App load the bundled sample, so the demo surface is never blank. Read once at mount:
 * App strips the `sample` param after loading, so re-reading it later would drop demo mode and
 * re-trigger the gate.
 */
function detectDemo(): boolean {
  if (typeof window === "undefined") return false;
  return new URLSearchParams(window.location.search).get("sample") === "1";
}

/**
 * Access gate for /app. The analyzer used to be open to everyone; the product now requires a
 * signed-in, email-verified account to reach the full app. Two escape hatches preserve prior
 * behavior:
 *   - Public demo (/app?sample=1) stays anonymous so marketing/SEO "try it" links keep working.
 *   - Builds without Supabase configured (offline / self-host / tests) have no accounts at all,
 *     so there's nothing to gate — the app stays open.
 *
 * Signed-out visitors are sent to the branded /login page (which offers sign in / create
 * account, then returns to /app). Signed-in-but-unverified visitors are held on a "verify your
 * email" screen until they confirm.
 */
export function AppGate() {
  const identityReady = supabaseConfigured;
  const [isDemo] = useState(detectDemo);
  const session = useSession();
  // The gate only enforces when accounts exist and this isn't the public demo.
  const gatingActive = identityReady && !isDemo;

  // Signed-out → the /login page. A full navigation, so this component unmounts; we still render
  // a "redirecting" placeholder below for the frame before the browser leaves.
  useEffect(() => {
    if (gatingActive && session.status === "anon") {
      window.location.assign("/login");
    }
  }, [gatingActive, session.status]);

  // Offline/self-host (no backend) or the public demo: no gate.
  if (!identityReady) return <App />;
  if (isDemo) return <App demo />;

  if (session.status === "loading") {
    return (
      <GateShell>
        <LoadingState label="Loading…" />
      </GateShell>
    );
  }
  if (session.status === "anon") {
    return (
      <GateShell>
        <LoadingState label="Redirecting to sign in…" />
      </GateShell>
    );
  }
  if (!session.emailVerified) {
    return <VerifyEmailScreen email={session.email} onResend={session.resendVerification} onSignOut={session.signOut} />;
  }
  return <App />;
}

/** Branded chrome shared by the gate's loading / verify screens (mirrors AuthApp). */
function GateShell({ children }: { children: ReactNode }) {
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
      <main className="mx-auto flex w-full max-w-sm flex-col px-4 py-16">{children}</main>
    </div>
  );
}

/**
 * Held here until the account's email is confirmed. With Supabase "Confirm email" on, clicking
 * the link establishes a verified session in the tab it opens — this screen is the fallback for
 * a still-unverified session: "I've verified — continue" force-refreshes the session token to
 * observe the updated `email_confirmed_at`, then reloads so useSession re-derives an
 * authed+verified session; "Resend" re-sends the confirmation email.
 */
function VerifyEmailScreen({
  email,
  onResend,
  onSignOut,
}: {
  email: string;
  onResend: () => Promise<{ ok: boolean; error?: string }>;
  onSignOut: () => Promise<void>;
}) {
  const [busy, setBusy] = useState(false);
  const [notYet, setNotYet] = useState(false);
  const [resent, setResent] = useState(false);

  const recheck = async () => {
    if (busy) return;
    setBusy(true);
    setNotYet(false);
    setResent(false);
    const { data } = supabase ? await supabase.auth.refreshSession() : { data: { session: null } };
    if (data.session?.user?.email_confirmed_at) {
      window.location.reload();
      return;
    }
    setBusy(false);
    setNotYet(true);
  };

  const resend = async () => {
    if (busy) return;
    setBusy(true);
    setNotYet(false);
    const r = await onResend();
    setBusy(false);
    setResent(r.ok);
    if (!r.ok) setNotYet(true);
  };

  return (
    <GateShell>
      <section className="card p-6 shadow-[var(--sh-float)]">
        <div
          className="mb-3 flex h-9 w-9 items-center justify-center rounded-[var(--r-tile)]"
          style={{ background: "color-mix(in srgb, var(--color-accent) 16%, transparent)" }}
        >
          <MailCheck size={18} style={{ color: "var(--color-accent)" }} aria-hidden />
        </div>
        <h1 className="t-title text-[var(--color-text)]">Verify your email</h1>
        <p className="mt-2 text-sm text-[var(--color-text-dim)]">
          We sent a verification link to{" "}
          <span className="font-medium text-[var(--color-text)]">{email || "your email"}</span>. Open it to confirm your
          account, then continue. Check your spam folder if it hasn't arrived.
        </p>
        <div className="mt-5 flex flex-col gap-2">
          <button
            type="button"
            onClick={() => void recheck()}
            disabled={busy}
            className="inline-flex items-center justify-center rounded-full bg-[var(--color-accent-deep)] px-4 py-2 text-sm font-medium text-[var(--color-on-accent)] disabled:opacity-60"
          >
            {busy ? "Checking…" : "I've verified — continue"}
          </button>
          <button
            type="button"
            onClick={() => void resend()}
            disabled={busy}
            className="inline-flex items-center justify-center rounded-full border border-[var(--color-border-strong)] bg-[var(--color-surface-1)] px-4 py-2 text-sm font-medium text-[var(--color-text)] hover:border-[var(--color-accent)] disabled:opacity-60"
          >
            Resend verification email
          </button>
          <button
            type="button"
            onClick={() => void onSignOut()}
            className="inline-flex items-center justify-center rounded-[var(--r-tile)] px-3 py-2 text-sm font-medium text-[var(--color-text-dim)] hover:text-[var(--color-text)]"
          >
            Sign out
          </button>
        </div>
        {resent && (
          <p role="status" className="mt-3 t-tag text-[var(--color-accent)]">
            Sent — check your inbox.
          </p>
        )}
        {notYet && (
          <p role="alert" className="mt-3 t-tag text-[var(--color-sev-critical)]">
            Not verified yet — open the link in the email, then try again.
          </p>
        )}
      </section>
    </GateShell>
  );
}

export default AppGate;
