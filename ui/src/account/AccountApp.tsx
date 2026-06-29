import { useEffect } from "react";
import { Radar, ArrowLeft } from "lucide-react";
import { useSession } from "../auth/useSession";
import { LoadingState } from "../components/state/LoadingState";
import { ThemeToggle } from "../cockpit/ThemeToggle";
import { AccountPage } from "./AccountPage";

/** Standalone /account route shell: brand header + back-to-app, gated to signed-in users. */
export function AccountApp() {
  const session = useSession();
  useEffect(() => {
    if (session.status === "anon") window.location.assign("/app");
  }, [session.status]);

  return (
    <div className="min-h-screen bg-[var(--color-bg)] text-[var(--color-text)]">
      <header className="flex h-14 items-center gap-3 border-b border-[var(--color-border)] bg-[var(--color-surface)] px-4">
        <a
          href="/app"
          aria-label="Back to app"
          className="flex items-center gap-2 text-[var(--color-text-dim)] hover:text-[var(--color-text)]"
        >
          <ArrowLeft size={16} aria-hidden />
          <span
            className="flex h-7 w-7 items-center justify-center rounded-[var(--r-tile)]"
            style={{ background: "color-mix(in srgb, var(--color-accent) 16%, transparent)" }}
          >
            <Radar size={16} style={{ color: "var(--color-accent)" }} aria-hidden />
          </span>
          <span className="font-display text-[15px] font-medium tracking-tight">PacketPilot</span>
        </a>
        <span className="ml-1 t-label text-[var(--color-text-dim)]">Account</span>
        <div className="ml-auto">
          <ThemeToggle />
        </div>
      </header>
      <main className="mx-auto w-full max-w-3xl px-4 py-8">
        {session.status === "loading" && <LoadingState label="Loading account…" />}
        {session.status === "anon" && <LoadingState label="Redirecting…" />}
        {session.status === "authed" && <AccountPage session={session} />}
      </main>
    </div>
  );
}

export default AccountApp;
