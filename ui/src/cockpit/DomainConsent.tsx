export function DomainConsent({ domainCount, onProceed, onCancel }:
  { domainCount: number; onProceed: () => void; onCancel: () => void }) {
  return (
    <div role="dialog" aria-label="Domain reputation consent" className="fixed inset-0 z-50 flex items-center justify-center bg-black/40">
      <div className="max-w-md rounded-lg bg-[var(--color-surface)] p-5 text-[var(--color-text)]">
        <h2 className="text-sm font-semibold">Send {domainCount} domain{domainCount === 1 ? "" : "s"} to VirusTotal?</h2>
        <p className="mt-2 text-xs text-[var(--color-text-faint)]">
          The top {domainCount} TLS SNI hostname{domainCount === 1 ? "" : "s"} this capture contacted will be sent to VirusTotal
          to check reputation. Payloads and the capture itself never leave this device.
        </p>
        <div className="mt-4 flex justify-end gap-2">
          <button className="t-tag" onClick={onCancel}>Cancel</button>
          <button className="t-tag font-semibold" onClick={onProceed}>Proceed</button>
        </div>
      </div>
    </div>
  );
}
