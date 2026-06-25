import { Loader2 } from "lucide-react";

export interface LoadingStateProps {
  label?: string; // default "Loading…"
}

/** Centered spinner + label, announced politely to assistive tech. */
export function LoadingState({ label = "Loading…" }: LoadingStateProps) {
  return (
    <div
      data-component="LoadingState"
      role="status"
      aria-live="polite"
      className="app-bg flex h-full min-h-0 flex-col items-center justify-center gap-3 px-6 py-12 text-center"
    >
      <Loader2 size={28} className="animate-spin text-[var(--color-accent)]" aria-hidden />
      <p className="text-sm text-[var(--color-text-dim)]">{label}</p>
    </div>
  );
}

export default LoadingState;
