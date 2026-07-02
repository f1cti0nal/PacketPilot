import { useEffect, useState, type ReactNode } from "react";
import { Radar, ShieldCheck, Check } from "lucide-react";
import { useSession, type OAuthProvider } from "./useSession";
import { AuthPanel, type AuthMode } from "./AuthPanel";
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

const FEATURES = [
  "20+ detectors — beaconing, exfiltration, scans, lateral movement, and more.",
  "Every finding severity-ranked and mapped to MITRE ATT&CK.",
  "Runs entirely on your device — nothing is uploaded, and it works offline.",
];

/** Decorative branding column (login/signup only). aria-hidden so screen readers land on the form. */
function BrandPanel({ mode }: { mode: AuthMode }) {
  return (
    <aside
      aria-hidden
      className="relative hidden overflow-hidden border-l border-[var(--color-border)] px-12 py-16 lg:flex lg:flex-col lg:justify-center"
      style={{ background: "linear-gradient(158deg, var(--color-panel), var(--color-bg))" }}
    >
      <div
        className="pointer-events-none absolute inset-0"
        style={{
          background:
            "radial-gradient(680px 420px at 84% 6%, color-mix(in srgb, var(--color-accent) 16%, transparent), transparent 60%), radial-gradient(520px 360px at 8% 112%, color-mix(in srgb, var(--color-spine-violet) 12%, transparent), transparent 55%)",
        }}
      />
      <div className="relative flex flex-col gap-6">
        <div className="flex items-center gap-3 text-[var(--color-text)]">
          <Radar size={26} style={{ color: "var(--color-accent)" }} aria-hidden />
          <span className="font-display text-xl font-medium tracking-tight">PacketPilot</span>
        </div>

        <p className="max-w-[15ch] font-display text-[32px] font-medium leading-[1.14] tracking-tight text-[var(--color-text)]">
          Turn a <span style={{ color: "var(--color-accent)" }}>.pcap</span> into ranked threat
          intelligence.
        </p>

        <p className="max-w-[46ch] text-[15px] leading-relaxed text-[var(--color-text-dim)]">
          {mode === "signup"
            ? "Create your account to save workspaces and unlock reputation + AI enrichment. Your captures still never leave the browser."
            : "A Rust + WebAssembly engine triages your capture on-device — severity-ranked, MITRE ATT&CK–mapped findings without a packet ever leaving your browser."}
        </p>

        <ul className="flex flex-col gap-3">
          {FEATURES.map((f) => (
            <li key={f} className="flex items-start gap-3 text-sm text-[var(--color-text)]">
              <Check size={17} className="mt-0.5 shrink-0" style={{ color: "var(--color-accent)" }} aria-hidden />
              <span>{f}</span>
            </li>
          ))}
        </ul>

        <span
          className="inline-flex items-center gap-2 self-start rounded-full border border-[var(--color-border-strong)] px-3.5 py-2 text-[13px] font-medium text-[var(--color-accent-strong)]"
          style={{ background: "color-mix(in srgb, var(--color-accent) 8%, transparent)" }}
        >
          <ShieldCheck size={15} style={{ color: "var(--color-accent)" }} aria-hidden />
          Your captures never leave the browser
        </span>
      </div>
    </aside>
  );
}

/**
 * Dedicated /login, /signup, /logout endpoints. Login/signup render a real, linkable split-screen
 * page (brand panel + native auth card: email/password + Google/GitHub). /logout ends the Supabase
 * session. Already-signed-in users are bounced to /app.
 */
export function AuthApp() {
  const session = useSession();
  const mode = modeFromPath();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [confirmSentTo, setConfirmSentTo] = useState<string | null>(null);

  useEffect(() => {
    if (mode === "logout") {
      if (session.status === "authed") void session.signOut().then(() => window.location.assign("/"));
      else if (session.status === "anon") window.location.assign("/");
      return;
    }
    if (session.status === "authed") window.location.assign("/app");
  }, [mode, session]);

  const onSubmit = async (email: string, password: string) => {
    if (session.status !== "anon" || busy) return;
    setBusy(true);
    setError(null);
    if (mode === "signup") {
      const r = await session.signUp(email, password);
      if (!r.ok) {
        setError(r.error ?? "Sign-up failed");
        setBusy(false);
      } else if (r.needsConfirm) {
        setConfirmSentTo(email);
        setBusy(false);
      } else {
        window.location.assign("/app");
      }
    } else {
      const r = await session.signIn(email, password);
      if (!r.ok) {
        setError(r.error ?? "Sign-in failed");
        setBusy(false);
      } else {
        window.location.assign("/app");
      }
    }
  };

  const onSocial = async (provider: OAuthProvider) => {
    if (session.status !== "anon" || busy) return;
    setBusy(true);
    setError(null);
    const r = await session.signInWithProvider(provider);
    // On success the browser redirects to the provider; we only land here if it failed to start.
    if (!r.ok) {
      setError(r.error ?? "Sign-in failed");
      setBusy(false);
    }
  };

  const onResend = async (email: string) => {
    if (session.status !== "anon") return;
    setBusy(true);
    setError(null);
    const r = await session.resendVerification(email);
    setBusy(false);
    if (!r.ok) setError(r.error ?? "Couldn't resend the email");
  };

  // Non-form states share one centered layout.
  if (mode === "logout" || session.status !== "anon") {
    return (
      <Shell>
        <div className="flex min-h-screen items-center justify-center px-6">
          <LoadingState
            label={
              mode === "logout" ? "Signing out…" : session.status === "loading" ? "Loading…" : "Redirecting…"
            }
          />
        </div>
      </Shell>
    );
  }

  const formMode: AuthMode = mode === "signup" ? "signup" : "login";

  return (
    <Shell>
      <div className="grid min-h-screen grid-cols-1 lg:grid-cols-2">
        <section
          className="relative flex flex-col items-center justify-center px-6 py-16"
          style={{
            background:
              "radial-gradient(720px 420px at 50% -14%, color-mix(in srgb, var(--color-accent) 6%, transparent), transparent 60%), var(--color-bg)",
          }}
        >
          <AuthPanel
            mode={formMode}
            busy={busy}
            error={error}
            confirmSentTo={confirmSentTo}
            onSwitchMode={(next) => window.location.assign(next === "signup" ? "/signup" : "/login")}
            onSubmit={onSubmit}
            onSocial={onSocial}
            onResend={onResend}
            showBackToApp
          />
        </section>
        <BrandPanel mode={formMode} />
      </div>
    </Shell>
  );
}

/** Full-viewport surface with the theme toggle pinned to the top-right. */
function Shell({ children }: { children: ReactNode }) {
  return (
    <div className="relative min-h-screen bg-[var(--color-bg)] text-[var(--color-text)]">
      <div className="absolute right-4 top-4 z-10">
        <ThemeToggle />
      </div>
      {children}
    </div>
  );
}

export default AuthApp;
