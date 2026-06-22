import { useEffect, useRef, useState } from "react";
import { FileDown, Loader2 } from "lucide-react";

export interface ExportAction {
  id: string;
  label: string;
  run: () => void;
}

/** A small dropdown of export actions (download/copy per format). */
export function ExportMenu({
  actions,
  disabled,
  busy,
}: {
  actions: ExportAction[];
  disabled?: boolean;
  busy?: boolean;
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
    <div ref={ref} className="relative inline-flex">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        disabled={disabled || busy}
        aria-expanded={open}
        className="inline-flex items-center gap-1.5 rounded-md border border-[var(--color-border)] bg-[var(--color-surface-2)] px-2.5 py-1.5 text-xs font-medium text-[var(--color-text)] transition-colors hover:border-[var(--color-accent)] hover:text-[var(--color-accent)] disabled:opacity-50"
      >
        {busy ? <Loader2 size={14} className="animate-spin" /> : <FileDown size={14} />}
        Export
      </button>
      {open && (
        <div className="absolute right-0 top-full z-30 mt-1 min-w-[12rem] overflow-hidden rounded-md border border-[var(--color-border)] bg-[var(--color-surface-2)] py-1 shadow-lg">
          {actions.map((a) => (
            <button
              key={a.id}
              type="button"
              onClick={() => { setOpen(false); a.run(); }}
              className="block w-full px-3 py-1.5 text-left text-xs text-[var(--color-text-dim)] transition-colors hover:bg-[var(--color-surface)] hover:text-[var(--color-accent)]"
            >
              {a.label}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
