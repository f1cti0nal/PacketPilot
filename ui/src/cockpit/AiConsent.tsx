export function AiConsent({ baseUrl, model, onProceed, onCancel }:
  { baseUrl: string; model: string; onProceed: () => void; onCancel: () => void }) {
  const local = /^https?:\/\/(localhost|127\.0\.0\.1)/i.test(baseUrl);
  return (
    <div role="dialog" aria-label="AI consent" className="fixed inset-0 z-50 flex items-center justify-center bg-black/40">
      <div className="max-w-md rounded-lg bg-[var(--color-surface)] p-5 text-[var(--color-text)]">
        <h2 className="text-sm font-semibold">Send the analysis summary to the model?</h2>
        <p className="mt-2 text-xs text-[var(--color-text-faint)]">
          Your analysis <b>summary</b> — severity counts, top incidents and threat IPs with their evidence
          (never raw packets, payloads, or the capture file) — will be sent to <b>{baseUrl}</b> using
          model <b>{model}</b>. {local ? "This endpoint is local — it stays on this device." : ""}
        </p>
        <div className="mt-4 flex justify-end gap-2">
          <button className="t-tag" onClick={onCancel}>Cancel</button>
          <button className="t-tag font-semibold" onClick={onProceed}>Proceed</button>
        </div>
      </div>
    </div>
  );
}
