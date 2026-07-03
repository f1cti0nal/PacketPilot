import { useState, type FormEvent } from "react";
import { ShieldCheck } from "lucide-react";
import type { AdminSession } from "./useAdminSession";

type LoginSession = Extract<AdminSession, { status: "anon" | "forbidden" | "unconfigured" }>;

/** Centered card used for every pre-shell admin state. */
function Frame({ children }: { children: React.ReactNode }) {
  return (
    <div className="admin-root flex h-full min-h-0 items-center justify-center bg-[var(--admin-canvas)] px-6 py-12 text-[var(--color-text)]">
      <section className="admin-card w-full max-w-sm p-7">
        <div className="mb-5 flex items-center gap-3">
          <span className="flex h-10 w-10 items-center justify-center rounded-xl bg-[var(--color-accent-deep)] text-[var(--color-on-accent)]">
            <ShieldCheck size={20} aria-hidden />
          </span>
          <span>
            <span className="block font-display text-lg font-semibold leading-tight text-[var(--color-text)]">
              PacketPilot
            </span>
            <span className="block text-xs font-medium uppercase tracking-wider text-[var(--color-text-faint)]">
              Admin Console
            </span>
          </span>
        </div>
        {children}
      </section>
    </div>
  );
}

export function AdminLogin({ session }: { session: LoginSession }) {
  const [busy, setBusy] = useState(false);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);

  if (session.status === "unconfigured") {
    return (
      <Frame>
        <p className="text-sm text-[var(--color-text-dim)]">
          The admin backend is not configured. Set <code className="font-mono-num">VITE_SUPABASE_URL</code> and{" "}
          <code className="font-mono-num">VITE_SUPABASE_ANON_KEY</code>, then reload.
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
          className="mt-5 inline-flex items-center justify-center rounded-full border border-[var(--color-border)] bg-[var(--color-surface-1)] px-4 py-1.5 text-sm font-medium text-[var(--color-text)] transition-colors hover:border-[var(--color-border-strong)] hover:bg-[var(--color-surface-2)]"
        >
          Sign out
        </button>
      </Frame>
    );
  }

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (busy) return;
    setBusy(true);
    setError(null);
    const r = await session.signIn(email, password);
    if (!r.ok) {
      setError(r.error ?? "Sign-in failed");
      setBusy(false);
    }
    // On success onAuthStateChange re-derives the session (admin/forbidden) — no redirect needed.
  };

  const inputCls =
    "w-full rounded-xl border border-[var(--color-border)] bg-[var(--color-surface-1)] px-3 py-2 text-sm text-[var(--color-text)] outline-none transition-colors focus:border-[var(--color-accent)]";

  return (
    <Frame>
      <p className="mb-5 text-sm text-[var(--color-text-dim)]">Administrator access only. Sign in to continue.</p>
      <form onSubmit={submit} className="flex flex-col gap-3.5">
        <label className="flex flex-col gap-1.5 text-sm">
          <span className="text-xs font-medium text-[var(--color-text-dim)]">Email</span>
          <input type="email" autoComplete="username" required value={email} onChange={(e) => setEmail(e.target.value)} className={inputCls} />
        </label>
        <label className="flex flex-col gap-1.5 text-sm">
          <span className="text-xs font-medium text-[var(--color-text-dim)]">Password</span>
          <input type="password" autoComplete="current-password" required value={password} onChange={(e) => setPassword(e.target.value)} className={inputCls} />
        </label>
        {error && (
          <p role="alert" className="text-sm text-[var(--color-sev-critical)]">
            {error}
          </p>
        )}
        <button
          type="submit"
          disabled={busy}
          className="mt-1 inline-flex w-full items-center justify-center rounded-full bg-[var(--color-accent-deep)] px-4 py-2 text-sm font-medium text-[var(--color-on-accent)] transition-[filter] hover:brightness-110 disabled:opacity-60"
        >
          {busy ? "Signing in…" : "Sign in"}
        </button>
      </form>
    </Frame>
  );
}

export default AdminLogin;
