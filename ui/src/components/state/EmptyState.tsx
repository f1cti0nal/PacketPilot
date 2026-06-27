import { Radar, FolderOpen } from "lucide-react";

export interface EmptyStateProps {
  title: string;
  hint?: string;
  /** When provided, renders a primary "Load capture" call-to-action. */
  onLoad?: () => void;
}

/** First-run / no-data screen: a centered brand glyph, title, hint, and an optional load CTA. */
export function EmptyState({
  title,
  hint = "Drop a .pcap or .pcapng file anywhere, or open one to get started.",
  onLoad,
}: EmptyStateProps) {
  return (
    <div
      data-component="EmptyState"
      className="app-bg flex h-full min-h-0 flex-col items-center justify-center px-6 py-12 text-center"
    >
      <div className="mb-5 flex h-16 w-16 items-center justify-center rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface-1)] text-[var(--color-accent)]">
        <Radar size={30} aria-hidden />
      </div>
      <h2 className="font-display text-xl font-medium text-[var(--color-text)]">{title}</h2>
      <p className="mt-2 max-w-sm text-sm text-[var(--color-text-dim)]">{hint}</p>
      {onLoad && (
        <button
          type="button"
          onClick={onLoad}
          className="mt-6 inline-flex items-center gap-2 rounded-[var(--r-tile)] bg-[var(--color-accent)] px-4 py-2 text-sm font-medium text-[var(--color-bg)] transition-opacity hover:opacity-90"
        >
          <FolderOpen size={16} aria-hidden />
          Load capture
        </button>
      )}
    </div>
  );
}

export default EmptyState;
