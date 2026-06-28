import { useEffect, useRef, useState } from "react";
import { ChevronDown, User } from "lucide-react";
import type { SessionState } from "./useSession";
import { startCheckout, openPortal } from "./billing";

export function AccountMenu({ session, onOpenAuth }: { session: SessionState; onOpenAuth: () => void }) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    document.addEventListener("mousedown", onDoc);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDoc);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  if (session.status === "loading") return null;

  if (session.status === "anon") {
    return (
      <button
        type="button"
        aria-label="Sign in"
        onClick={onOpenAuth}
        className="inline-flex items-center gap-1.5 rounded-[var(--r-tile)] border border-[var(--color-border)] bg-transparent px-2.5 py-1.5 text-xs font-medium text-[var(--color-text-dim)] transition-colors hover:border-[var(--color-border-strong)] hover:text-[var(--color-text)]"
      >
        <User size={14} aria-hidden />
        <span className="hidden sm:inline">Sign in</span>
      </button>
    );
  }

  return (
    <div ref={ref} className="relative">
      <button
        type="button"
        aria-label="Account menu"
        aria-haspopup="true"
        aria-expanded={open}
        onClick={() => setOpen((o) => !o)}
        className="inline-flex items-center gap-1.5 rounded-[var(--r-tile)] border border-[var(--color-border)] bg-[var(--color-surface-2)] px-2 py-1.5 text-xs text-[var(--color-text-dim)] hover:text-[var(--color-text)]"
      >
        <User size={14} aria-hidden />
        <span className="hidden max-w-[10rem] truncate sm:inline">{session.email}</span>
        <ChevronDown size={13} aria-hidden />
      </button>
      {open && (
        <div className="absolute right-0 z-40 mt-1 w-52 rounded-[var(--r-tile)] border border-[var(--color-border)] bg-[var(--color-surface-raised)] p-2 shadow-[var(--sh-float)]">
          <div className="truncate px-1 pb-1 text-xs text-[var(--color-text-dim)]">{session.email}</div>
          <div className="px-1 pb-2">
            <span className="inline-flex items-center rounded-[var(--r-chip)] border border-[var(--color-border)] bg-[var(--color-surface-2)] px-1.5 py-0.5 t-tag uppercase text-[var(--color-text-dim)]">
              {session.profile.plan}
            </span>
          </div>
          {session.profile.plan === "pro" ? (
            <button
              type="button"
              onClick={() => void openPortal()}
              className="w-full rounded-[var(--r-micro)] px-2 py-1.5 text-left text-sm text-[var(--color-text-dim)] hover:bg-[var(--color-surface-2)] hover:text-[var(--color-text)]"
            >
              Manage billing
            </button>
          ) : (
            <button
              type="button"
              onClick={() => void startCheckout()}
              className="w-full rounded-[var(--r-micro)] px-2 py-1.5 text-left text-sm text-[var(--color-accent-strong)] hover:bg-[var(--color-surface-2)]"
            >
              Upgrade to Pro
            </button>
          )}
          <button
            type="button"
            onClick={() => void session.signOut()}
            className="w-full rounded-[var(--r-micro)] px-2 py-1.5 text-left text-sm text-[var(--color-text-dim)] hover:bg-[var(--color-surface-2)] hover:text-[var(--color-text)]"
          >
            Sign out
          </button>
        </div>
      )}
    </div>
  );
}

export default AccountMenu;
