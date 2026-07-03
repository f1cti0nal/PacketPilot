import type { ReactNode } from "react";

/** A titled `.card` block — one per account section. */
export function Card({ title, desc, children }: { title: string; desc?: string; children: ReactNode }) {
  return (
    <section className="card p-5">
      <header className="mb-4">
        <h2 className="t-title text-[var(--color-text)]">{title}</h2>
        {desc && <p className="mt-0.5 text-sm text-[var(--color-text-dim)]">{desc}</p>}
      </header>
      <div className="flex flex-col gap-4">{children}</div>
    </section>
  );
}

/** A labelled setting row: label (+ optional hint) on the left, control on the right. */
export function Row({ label, hint, children }: { label: string; hint?: string; children: ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-4">
      <div className="min-w-0">
        <div className="text-sm font-medium text-[var(--color-text)]">{label}</div>
        {hint && <div className="t-tag text-[var(--color-text-dim)]">{hint}</div>}
      </div>
      <div className="shrink-0">{children}</div>
    </div>
  );
}

export const fieldCls =
  "rounded-[var(--r-tile)] border border-[var(--color-border)] bg-[var(--color-surface-2)] px-3 py-1.5 text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-accent)]";
export const btnCls =
  "inline-flex items-center justify-center rounded-full bg-[var(--color-accent-deep)] px-4 py-1.5 text-sm font-medium text-[var(--color-on-accent)] disabled:opacity-60";
export const btnGhost =
  "inline-flex items-center justify-center rounded-full border border-[var(--color-border-strong)] bg-transparent px-4 py-1.5 text-sm text-[var(--color-text-dim)] hover:text-[var(--color-text)] disabled:opacity-60";
