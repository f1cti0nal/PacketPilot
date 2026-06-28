import { useEffect, useRef, useState } from "react";
import { ChevronDown } from "lucide-react";
import { ThemeToggle } from "../cockpit/ThemeToggle";
import { DensityToggle } from "../cockpit/DensityToggle";

export function AdminTopBar({
  title,
  email,
  onSignOut,
}: {
  title: string;
  email: string;
  onSignOut: () => Promise<void>;
}) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", onDoc);
    return () => document.removeEventListener("mousedown", onDoc);
  }, [open]);

  return (
    <header className="flex h-12 shrink-0 items-center justify-between border-b border-[var(--color-border)] bg-[var(--color-surface-1)] px-4">
      <h1 className="t-title text-[var(--color-text)]">{title}</h1>
      <div className="flex items-center gap-2">
        <ThemeToggle />
        <DensityToggle />
        <div ref={ref} className="relative">
          <button
            type="button"
            aria-label="Account menu"
            aria-expanded={open}
            onClick={() => setOpen((o) => !o)}
            className="flex items-center gap-1.5 rounded-[var(--r-tile)] border border-[var(--color-border)] bg-[var(--color-surface-2)] px-2 py-1 text-sm text-[var(--color-text-dim)] hover:text-[var(--color-text)]"
          >
            <span className="max-w-[12rem] truncate">{email}</span>
            <ChevronDown size={14} aria-hidden />
          </button>
          {open && (
            <div
              role="menu"
              className="absolute right-0 z-10 mt-1 w-40 rounded-[var(--r-tile)] border border-[var(--color-border)] bg-[var(--color-surface-raised)] p-1 shadow-[var(--sh-float)]"
            >
              <button
                type="button"
                onClick={() => void onSignOut()}
                className="w-full rounded-[var(--r-micro)] px-2 py-1.5 text-left text-sm text-[var(--color-text-dim)] hover:bg-[var(--color-surface-2)] hover:text-[var(--color-text)]"
              >
                Sign out
              </button>
            </div>
          )}
        </div>
      </div>
    </header>
  );
}

export default AdminTopBar;
