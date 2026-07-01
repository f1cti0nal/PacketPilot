import { useState } from "react";
import { ShieldCheck } from "lucide-react";
import type { AdminSession } from "./useAdminSession";

type LoginSession = Extract<AdminSession, { status: "anon" | "forbidden" | "unconfigured" }>;

/** Centered card used for every pre-shell admin state. */
function Frame({ children }: { children: React.ReactNode }) {
  return (
    <div className="app-bg flex h-full min-h-0 items-center justify-center px-6 py-12 text-[var(--color-text)]">
      <section className="card w-full max-w-sm p-6 shadow-[var(--sh-hero)]">
        <div className="mb-4 flex items-center gap-2">
          <ShieldCheck size={18} className="text-[var(--color-accent)]" aria-hidden />
          <h1 className="t-title text-[var(--color-text)]">PacketPilot Admin</h1>
        </div>
        {children}
      </section>
    </div>
  );
}

export function AdminLogin({ session }: { session: LoginSession }) {
  const [busy, setBusy] = useState(false);

  if (session.status === "unconfigured") {
    return (
      <Frame>
        <p className="text-sm text-[var(--color-text-dim)]">
          The admin backend is not configured. Set <code>VITE_SUPABASE_URL</code>, <code>VITE_SUPABASE_ANON_KEY</code>,{" "}
          <code>VITE_AUTH0_DOMAIN</code>, and <code>VITE_AUTH0_CLIENT_ID</code>, then reload.
        </p>
      </Frame>
    );
  }

  if (session.status === "forbidden") {
    return (
      <Frame>
        <p className="text-sm text-[var(--color-text-dim)]">
          You are signed in as <span className="text-[var(--color-text)]">{session.email}</span>, but this account is{" "}
          <strong className="text-[var(--color-text)]">not an administrator</strong>.
        </p>
        <button
          type="button"
          onClick={() => void session.signOut()}
          className="mt-4 inline-flex items-center justify-center rounded-[var(--r-tile)] border border-[var(--color-border)] bg-[var(--color-surface-2)] px-3 py-1.5 text-sm text-[var(--color-text-dim)] hover:border-[var(--color-border-strong)] hover:text-[var(--color-text)]"
        >
          Sign out
        </button>
      </Frame>
    );
  }

  return (
    <Frame>
      <p className="mb-4 text-sm text-[var(--color-text-dim)]">
        Administrator access only. Sign in with your Auth0 account to continue.
      </p>
      <button
        type="button"
        disabled={busy}
        onClick={() => {
          setBusy(true);
          void session.login();
        }}
        className="inline-flex w-full items-center justify-center rounded-[var(--r-tile)] bg-[var(--color-accent-deep)] px-3 py-1.5 text-sm font-medium text-[var(--color-on-accent)] disabled:opacity-60"
      >
        {busy ? "Redirecting…" : "Sign in"}
      </button>
    </Frame>
  );
}

export default AdminLogin;
