import { useState, type FormEvent } from "react";
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
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  if (session.status === "unconfigured") {
    return (
      <Frame>
        <p className="text-sm text-[var(--color-text-dim)]">
          The admin backend is not configured. Set <code>VITE_SUPABASE_URL</code> and{" "}
          <code>VITE_SUPABASE_ANON_KEY</code>, then reload.
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

  const onSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (busy) return;
    setBusy(true);
    setError(null);
    const res = await session.signIn(email, password);
    if (!res.ok) setError(res.error ?? "Sign-in failed");
    setBusy(false);
  };

  return (
    <Frame>
      <form onSubmit={onSubmit} className="flex flex-col gap-3">
        <label className="flex flex-col gap-1 text-sm">
          <span className="t-label text-[var(--color-text-dim)]">Email</span>
          <input
            type="email"
            autoComplete="username"
            required
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="rounded-[var(--r-tile)] border border-[var(--color-border)] bg-[var(--color-surface-2)] px-3 py-1.5 text-[var(--color-text)] outline-none focus:border-[var(--color-accent)]"
          />
        </label>
        <label className="flex flex-col gap-1 text-sm">
          <span className="t-label text-[var(--color-text-dim)]">Password</span>
          <input
            type="password"
            autoComplete="current-password"
            required
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="rounded-[var(--r-tile)] border border-[var(--color-border)] bg-[var(--color-surface-2)] px-3 py-1.5 text-[var(--color-text)] outline-none focus:border-[var(--color-accent)]"
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
          {busy ? "Signing in…" : "Sign in"}
        </button>
      </form>
    </Frame>
  );
}

export default AdminLogin;
