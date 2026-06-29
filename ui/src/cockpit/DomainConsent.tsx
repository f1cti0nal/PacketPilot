import { useDialogA11y } from "../lib/useDialogA11y";

export function DomainConsent({ domainCount, onProceed, onCancel }:
  { domainCount: number; onProceed: () => void; onCancel: () => void }) {
  const { ref, onKeyDown } = useDialogA11y(onCancel);
  return (
    <div ref={ref} onKeyDown={onKeyDown} role="dialog" aria-modal="true" aria-label="Domain reputation consent" className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
      <div className="w-full max-w-md rounded-[var(--r-card)] border border-[var(--color-border)] bg-[var(--color-surface)] text-[var(--color-text)] shadow-[var(--sh-float)]">
        <div className="border-b border-[var(--color-border)] px-5 py-4">
          <h2 className="text-sm font-medium">Send {domainCount} domain{domainCount === 1 ? "" : "s"} to VirusTotal?</h2>
        </div>
        <div className="px-5 py-4">
          <p className="text-xs text-[var(--color-text-dim)]">
            The top {domainCount} TLS SNI hostname{domainCount === 1 ? "" : "s"} this capture contacted will be sent <strong>via PacketPilot's servers</strong> to VirusTotal
            to check reputation. Internal IPs, payloads, and the capture itself never leave this device.
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
