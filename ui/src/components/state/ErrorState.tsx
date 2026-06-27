import { AlertTriangle, RefreshCw } from "lucide-react";

export interface ErrorStateProps {
  message: string;
  onRetry?: () => void;
}

/** Centered error screen: a critical glyph, message, and an optional retry action. */
export function ErrorState({ message, onRetry }: ErrorStateProps) {
  return (
    <div
      data-component="ErrorState"
      role="alert"
      className="app-bg flex h-full min-h-0 flex-col items-center justify-center px-6 py-12 text-center"
    >
      <div className="mb-5 flex h-16 w-16 items-center justify-center rounded-2xl border border-[var(--color-sev-critical)] bg-[color-mix(in_srgb,var(--color-sev-critical)_12%,transparent)] text-[var(--color-sev-critical)]">
        <AlertTriangle size={30} aria-hidden />
      </div>
      <h2 className="font-display text-xl font-medium text-[var(--color-text)]">Couldn't load the capture</h2>
      <p className="mt-2 max-w-md break-words text-sm text-[var(--color-text-dim)]">{message}</p>
      {onRetry && (
        <button
          type="button"
          onClick={onRetry}
          className="mt-6 inline-flex items-center gap-2 rounded-[var(--r-tile)] border border-[var(--color-border)] bg-[var(--color-surface-2)] px-4 py-2 text-sm font-medium text-[var(--color-text)] transition-colors hover:border-[var(--color-accent)] hover:text-[var(--color-accent)]"
        >
          <RefreshCw size={16} aria-hidden />
          Try again
        </button>
      )}
    </div>
  );
}

export default ErrorState;
