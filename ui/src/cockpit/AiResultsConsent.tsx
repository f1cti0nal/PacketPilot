import { useDialogA11y } from "../lib/useDialogA11y";
import { BTN_OUTLINE, BTN_PRIMARY, DIALOG_PANEL, OVERLAY_BACKDROP } from "./primitives";

/**
 * The SECOND consent class (see lib/ai/settings.ts): unlike the general AI
 * consent, proceeding here authorizes sending capture-derived RESULT ROWS —
 * a capped preview of the current query result — to the AI provider.
 */
export function AiResultsConsent({ model, rows, onProceed, onCancel }:
  { model: string; rows: number; onProceed: () => void; onCancel: () => void }) {
  const { ref, onKeyDown } = useDialogA11y(onCancel);
  return (
    <div ref={ref} onKeyDown={onKeyDown} role="dialog" aria-modal="true" aria-label="AI results consent" className={`${OVERLAY_BACKDROP} z-50 flex items-center justify-center p-4`}>
      <div className={`${DIALOG_PANEL} w-full max-w-md text-[var(--color-text)]`}>
        <div className="border-b border-[var(--color-border)] px-5 py-4">
          <h2 className="text-sm font-medium">Send this result preview to the model?</h2>
        </div>
        <div className="px-5 py-4">
          <p className="text-xs text-[var(--color-text-dim)]">
            A preview of <b>up to {rows} result rows</b> — which can include IPs, domains, TLS
            fingerprints, and user-agents from your capture — plus the SQL and your question will be
            sent <b>via PacketPilot&apos;s servers</b> to the AI provider (model <b>{model}</b>) to
            write a short analyst note. This is separate from the general AI consent: it is the only
            query action that sends capture-derived rows. Never raw packets, payloads, or the capture
            file — and never more than this capped preview.
          </p>
        </div>
        <div className="flex justify-end gap-2 border-t border-[var(--color-border)] px-5 py-3">
          <button type="button" className={BTN_OUTLINE} onClick={onCancel}>Cancel</button>
          <button type="button" className={BTN_PRIMARY} onClick={onProceed}>Proceed</button>
        </div>
      </div>
    </div>
  );
}
