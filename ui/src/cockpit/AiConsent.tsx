import { useDialogA11y } from "../lib/useDialogA11y";
import { BTN_OUTLINE, BTN_PRIMARY, DIALOG_PANEL, OVERLAY_BACKDROP } from "./primitives";

export function AiConsent({ model, onProceed, onCancel }:
  { model: string; onProceed: () => void; onCancel: () => void }) {
  const { ref, onKeyDown } = useDialogA11y(onCancel);
  return (
    <div ref={ref} onKeyDown={onKeyDown} role="dialog" aria-modal="true" aria-label="AI consent" className={`${OVERLAY_BACKDROP} z-50 flex items-center justify-center p-4`}>
      <div className={`${DIALOG_PANEL} w-full max-w-md text-[var(--color-text)]`}>
        <div className="border-b border-[var(--color-border)] px-5 py-4">
          <h2 className="text-sm font-medium">Send the analysis summary to the model?</h2>
        </div>
        <div className="px-5 py-4">
          <p className="text-xs text-[var(--color-text-dim)]">
            Your capture&apos;s <b>derived summary</b> will be sent <b>via PacketPilot&apos;s servers</b> to
            the AI provider (model <b>{model}</b>) to generate this. The summary covers severity counts,
            top incidents, threat IPs (with evidence), and contacted domains: never raw packets, payloads,
            or the capture file.
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
