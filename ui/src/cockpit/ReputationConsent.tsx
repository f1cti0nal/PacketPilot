export function ReputationConsent({ ipCount, providers, onProceed, onCancel }:
  { ipCount: number; providers: string[]; onProceed: () => void; onCancel: () => void }) {
  return (
    <div role="dialog" aria-label="Reputation consent" className="fixed inset-0 z-50 flex items-center justify-center bg-black/40">
      <div className="max-w-md rounded-lg bg-[var(--color-surface)] p-5 text-[var(--color-text)]">
        <h2 className="text-sm font-semibold">Send {ipCount} external IPs for reputation lookup?</h2>
        <p className="mt-2 text-xs text-[var(--color-text-faint)]">
          {ipCount} public IP{ipCount === 1 ? "" : "s"} will be sent to {providers.join(", ")} to check reputation.
          Internal IPs, payloads, and the capture itself never leave this device.
        </p>
        <div className="mt-4 flex justify-end gap-2">
          <button className="t-tag" onClick={onCancel}>Cancel</button>
          <button className="t-tag font-semibold" onClick={onProceed}>Proceed</button>
        </div>
      </div>
    </div>
  );
}
