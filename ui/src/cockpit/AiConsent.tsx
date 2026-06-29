import { useDialogA11y } from "../lib/useDialogA11y";

export function AiConsent({ model, onProceed, onCancel }:
  { model: string; onProceed: () => void; onCancel: () => void }) {
  const { ref, onKeyDown } = useDialogA11y(onCancel);
  return (
    <div ref={ref} onKeyDown={onKeyDown} role="dialog" aria-modal="true" aria-label="AI consent" className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
      <div className="w-full max-w-md rounded-[var(--r-card)] border border-[var(--color-border)] bg-[var(--color-surface)] text-[var(--color-text)] shadow-[var(--sh-float)]">
        <div className="border-b border-[var(--color-border)] px-5 py-4">
          <h2 className="text-sm font-medium">Send the analysis summary to the model?</h2>
        </div>
        <div className="px-5 py-4">
          <p className="text-xs text-[var(--color-text-dim)]">
            Your capture&apos;s <b>derived summary</b> — severity counts, top incidents, threat IPs (with
            evidence), and contacted domains (never raw packets, payloads, or the capture file) — will be
            sent <b>via PacketPilot&apos;s servers</b> to the AI provider (model <b>{model}</b>) to generate
            this.
          </p>
        </div>
        <div className="flex justify-end gap-2 border-t border-[var(--color-border)] px-5 py-3">
          <button type="button" className="rounded-[var(--r-micro)] border border-[var(--color-border)] bg-transparent px-3 py-1.5 text-xs font-medium text-[var(--color-text-dim)] transition-colors hover:border-[var(--color-border-strong)] hover:text-[var(--color-text)]" onClick={onCancel}>Cancel</button>
          <button type="button" className="rounded-[var(--r-micro)] bg-[var(--color-accent-deep)] px-3 py-1.5 text-xs font-medium text-[var(--color-on-accent)] transition-opacity hover:opacity-90" onClick={onProceed}>Proceed</button>
        </div>
      </div>
    </div>
  );
}
